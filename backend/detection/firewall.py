"""
EN: Firewall orchestration — Snitch does NOT filter packets in user-space;
    it drives the OS-native firewall instead:
      * Windows → `netsh advfirewall` (Windows Defender Firewall rules),
      * Linux   → `iptables` OUTPUT chain (a dedicated SNITCH_LOCK chain for
                  lockdown, per-destination DROP rules otherwise),
      * macOS   → `pf` anchors (a generated ruleset loaded with pfctl).
    Rules are persisted in the settings table ("firewall_rules") so they
    survive restarts. Every apply/remove is best-effort: failures are
    recorded on the rule instead of raising — the backend often runs
    elevated already (packet capture requires it), but demo mode and
    unprivileged runs degrade gracefully to `applied=False`.

    Rule kinds:  "ip"      single remote IP
                 "cidr"    network (e.g. 185.0.0.0/8)
                 "domain"  resolved to IPs at apply time (best effort)
                 "process" process name/path (netsh `program=` on Windows,
                          owner match on Linux — name resolved to PIDs)
                 "port"    remote port
    "lockdown" drops ALL outbound traffic to non-private destinations —
    loopback and LAN stay up so the UI remains reachable.

FR: Orchestration du pare-feu — Snitch ne filtre PAS les paquets en
    user-space ; il pilote le pare-feu natif de l'OS :
      * Windows → `netsh advfirewall`,
      * Linux   → `iptables` (chaîne dédiée SNITCH_LOCK pour le lockdown),
      * macOS   → ancres `pf` (jeu de règles généré chargé avec pfctl).
    Les règles sont persistées dans la table settings (« firewall_rules »)
    donc elles survivent aux redémarrages. Chaque application/retrait est
    best-effort : les échecs sont enregistrés sur la règle plutôt que levés.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

# EN: Cooldown between two BLOCKED_ATTEMPT alerts for the same rule.
# FR: Cooldown entre deux alertes BLOCKED_ATTEMPT pour une même règle.
_BLOCKED_COOLDOWN = 120

# EN: Private/LAN ranges exempted in lockdown mode so the machine keeps
#     local connectivity (UI on loopback, DNS/DHCP on the LAN).
# FR: Plages privées/LAN exemptées en lockdown pour garder la connectivité
#     locale (UI en loopback, DNS/DHCP sur le LAN).
_PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "169.254.0.0/16", "127.0.0.0/8", "::1/128", "fe80::/10"]


class FirewallManager:
    """EN: Owns firewall rules, lockdown state and blocked-attempt counters.
    FR: Gère les règles pare-feu, l'état lockdown et les compteurs de
    tentatives bloquées."""

    def __init__(self, data_dir: str):
        self._lock = threading.Lock()
        self._platform = platform.system().lower()          # 'windows'|'linux'|'darwin'
        self._demo = os.environ.get("SNITCH_DEMO") == "1"
        self._data_dir = Path(data_dir)
        # EN: The pf anchor file lives here — make sure it exists up-front.
        # FR: Le fichier d'ancre pf vit ici — s'assurer qu'il existe d'emblée.
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self._rules: list[dict] = []
        self._lockdown = False
        # EN: rule_id → last alert ts / FR: rule_id → dernier ts d'alerte
        self._block_alerts: dict[str, float] = {}
        # EN: rule_id → count of matching packets seen / FR: paquets vus par règle
        self._blocked_counts: dict[str, int] = {}

    # ── Introspection / Introspection ────────────────────────────────────────

    def supported(self) -> bool:
        """EN: Firewall orchestration needs a known OS; demo mode pretends
        everything works (rules apply in-memory only).
        FR: L'orchestration exige un OS connu ; le mode démo simule
        (règles appliquées en mémoire seulement)."""
        return self._demo or self._platform in ("windows", "linux", "darwin")

    def status(self) -> dict:
        with self._lock:
            return {
                "supported": self.supported(),
                "platform": self._platform,
                "demo": self._demo,
                "lockdown": self._lockdown,
                "rules": [dict(r) for r in self._rules],
                "blocked_counts": dict(self._blocked_counts),
            }

    # ── Persistence / Persistance ────────────────────────────────────────────

    def load(self, rules: list[dict], lockdown: bool) -> None:
        """EN: Restore persisted rules at startup and re-apply enabled ones
        silently (host firewall state may have been cleared meanwhile).
        FR: Restaurer les règles persistées au démarrage et réappliquer les
        actives en silence (l'état du pare-feu hôte a pu être vidé)."""
        with self._lock:
            self._rules = [dict(r) for r in rules if isinstance(r, dict) and r.get("kind")]
            self._lockdown = bool(lockdown)
        for r in list(self._rules):
            if r.get("enabled", True):
                self._apply(r)
        if self._lockdown:
            self._lockdown_apply(True)

    def _serialized_rules(self) -> list[dict]:
        return [dict(r) for r in self._rules]

    # ── Public rule ops / Opérations publiques ───────────────────────────────

    def add_rule(self, kind: str, value: str) -> dict:
        """EN: Create + apply a rule. `value` depends on kind (see module doc).
        Returns the persisted rule dict including its apply result.
        FR: Créer + appliquer une règle. Retourne la règle persistée avec le
        résultat d'application."""
        kind = kind.lower().strip()
        value = str(value).strip()
        if kind not in ("ip", "cidr", "domain", "process", "port"):
            raise ValueError(f"unknown rule kind: {kind}")
        rule = {
            "id": uuid.uuid4().hex[:10],
            "kind": kind,
            "value": value,
            "enabled": True,
            "applied": False,
            "error": None,
            "resolved": [],            # EN: domain→IPs / FR: domaine→IP
            "created": time.time(),
        }
        if kind in ("ip", "cidr"):
            ipaddress.ip_network(value, strict=False)   # EN: raises if invalid / FR: lève si invalide
        if kind == "domain":
            rule["resolved"] = self._resolve_domain(value)
        self._apply(rule)
        with self._lock:
            self._rules.append(rule)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            rule = next((r for r in self._rules if r["id"] == rule_id), None)
            if not rule:
                return False
            self._rules.remove(rule)
        self._remove(rule)
        return True

    def toggle_rule(self, rule_id: str, enabled: bool) -> Optional[dict]:
        with self._lock:
            rule = next((r for r in self._rules if r["id"] == rule_id), None)
            if not rule:
                return None
            rule["enabled"] = enabled
        if enabled:
            self._apply(rule)
        else:
            self._remove(rule)
        return rule

    def serialized(self) -> tuple[list[dict], bool]:
        with self._lock:
            return self._serialized_rules(), self._lockdown

    # ── Lockdown / Confinement ───────────────────────────────────────────────

    def set_lockdown(self, on: bool) -> dict:
        """EN: Global panic switch — drop all outbound traffic to public IPs,
        keep loopback + LAN so the Snitch UI/API stays reachable.
        FR: Bouton panique — coupe tout le trafic sortant vers les IP
        publiques, conserve loopback + LAN pour garder l'UI joignable."""
        ok, err = self._lockdown_apply(on)
        with self._lock:
            self._lockdown = on if ok else self._lockdown
            if ok:
                self._lockdown = on
        return {"ok": ok, "lockdown": self._lockdown, "error": err}

    # ── Packet matching / Correspondance paquets ─────────────────────────────

    def check_packet(self, pkt) -> Optional[dict]:
        """EN: First enabled rule matching this packet (remote IP/CIDR, port,
        process name). Used to emit BLOCKED_ATTEMPT alerts — the OS firewall
        already drops the traffic, this is only visibility.
        FR: Première règle active correspondant au paquet (IP/CIDR, port,
        processus). Sert à émettre les alertes BLOCKED_ATTEMPT — le pare-feu
        OS droppe déjà le trafic, ceci n'est que de la visibilité."""
        remote = pkt.dst_ip if pkt.direction == "out" else pkt.src_ip
        port = pkt.dst_port if pkt.direction == "out" else pkt.src_port
        proc = (pkt.process_name or "").lower()
        try:
            rip = ipaddress.ip_address(remote)
        except ValueError:
            return None

        # EN: Lockdown flags every outbound packet to a public destination —
        #     private/LAN traffic stays exempt so the UI remains reachable.
        # FR: Le lockdown signale chaque paquet sortant vers une destination
        #     publique — le trafic privé/LAN reste exempt pour garder l'UI.
        with self._lock:
            lockdown = self._lockdown
            rules = [r for r in self._rules if r.get("enabled", True)]
        if lockdown and pkt.direction == "out" and not rip.is_private \
                and not rip.is_loopback and not rip.is_link_local:
            return {"id": "__lockdown__", "kind": "lockdown", "value": "*"}
        for r in rules:
            k, v = r["kind"], r["value"]
            hit = False
            if k in ("ip", "cidr"):
                try:
                    hit = rip in ipaddress.ip_network(v, strict=False)
                except ValueError:
                    hit = False
            elif k == "domain":
                for resolved in r.get("resolved", []):
                    try:
                        if rip in ipaddress.ip_network(resolved, strict=False):
                            hit = True
                            break
                    except ValueError:
                        continue
            elif k == "process":
                hit = proc == v.lower() or proc.endswith("/" + v.lower()) \
                    or proc.endswith("\\" + v.lower())
            elif k == "port":
                try:
                    hit = int(v) == int(port or 0)
                except (TypeError, ValueError):
                    hit = False
            if hit:
                return r
        return None

    def note_blocked(self, rule_id: str) -> Optional[dict]:
        """EN: Increment the seen-blocked counter; returns alert context when
        the cooldown allows a new BLOCKED_ATTEMPT notification.
        FR: Incrémente le compteur de blocages ; retourne le contexte
        d'alerte quand le cooldown autorise une notification."""
        with self._lock:
            self._blocked_counts[rule_id] = self._blocked_counts.get(rule_id, 0) + 1
            now = time.time()
            last = self._block_alerts.get(rule_id, 0)
            if now - last < _BLOCKED_COOLDOWN:
                return None
            self._block_alerts[rule_id] = now
            rule = next((r for r in self._rules if r["id"] == rule_id), None)
            return {"rule": dict(rule) if rule else None,
                    "count": self._blocked_counts[rule_id]}

    # ── OS plumbing / Plomberie OS ───────────────────────────────────────────

    def _run(self, args: list[str]) -> tuple[bool, str]:
        """EN: Run one firewall command, never through a shell. Returns
        (success, stderr). / FR: Exécute une commande pare-feu sans shell."""
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=15)
            err = (p.stderr or p.stdout or "").strip()
            return p.returncode == 0, err[:300]
        except Exception as e:                       # noqa: BLE001 — report, don't crash
            return False, str(e)[:300]

    def _apply(self, rule: dict) -> None:
        if self._demo:
            rule["applied"], rule["error"] = True, None
            return
        kind, value, rid = rule["kind"], rule["value"], rule["id"]
        targets = rule.get("resolved") if kind == "domain" else [value]
        if kind == "domain" and not targets:
            rule["applied"], rule["error"] = False, "domain did not resolve"
            return
        ok_all, err_all = True, ""
        for t in targets:
            ok, err = self._apply_one(kind, t, rid)
            ok_all = ok_all and ok
            err_all = err or err_all
        rule["applied"], rule["error"] = ok_all, err_all or None

    def _apply_one(self, kind: str, target: str, rid: str) -> tuple[bool, str]:
        if self._platform == "windows":
            name = f"SnitchRule-{rid}"
            if kind == "process":
                return self._run(["netsh", "advfirewall", "firewall", "add", "rule",
                                  f"name={name}", "dir=out", "action=block",
                                  f"program={target}", "enable=yes"])
            key = "remoteip" if kind in ("ip", "cidr", "domain") else "remoteport"
            return self._run(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name={name}-{abs(hash(target)) % 10**6}",
                              "dir=out", "action=block", f"{key}={target}", "enable=yes"])
        if self._platform == "linux":
            if kind == "process":
                # EN: owner match works for locally generated packets by PID.
                #     Names are resolved to PIDs lazily — best effort.
                # FR: Le match owner fonctionne par PID sur paquets locaux.
                return self._block_linux_process(target, rid)
            args = ["iptables", "-w", "-I", "OUTPUT"]
            if kind in ("ip", "cidr", "domain"):
                args += ["-d", target]
            elif kind == "port":
                args += ["-p", "tcp", "--dport", target]
            args += ["-j", "DROP", "-m", "comment", "--comment", f"snitch-{rid}"]
            return self._run(args)
        if self._platform == "darwin":
            return self._pf_apply()
        return False, f"unsupported platform {self._platform}"

    def _remove(self, rule: dict) -> None:
        if self._demo:
            return
        rid, kind = rule["id"], rule["kind"]
        if self._platform == "windows":
            self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                       f"name=SnitchRule-{rid}"])
            # EN: per-target suffixed copies / FR: copies suffixées par cible
            self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                       "name=all", "program=" + rule["value"]]) if kind == "process" else None
        elif self._platform == "linux":
            targets = rule.get("resolved") if kind == "domain" else [rule["value"]]
            for t in targets:
                args = ["iptables", "-w", "-D", "OUTPUT"]
                if kind in ("ip", "cidr", "domain"):
                    args += ["-d", t]
                elif kind == "port":
                    args += ["-p", "tcp", "--dport", t]
                elif kind == "process":
                    continue
                args += ["-j", "DROP", "-m", "comment", "--comment", f"snitch-{rid}"]
                self._run(args)
        elif self._platform == "darwin":
            self._pf_apply()   # EN: regenerates the anchor without this rule / FR: régénère l'ancre sans la règle

    # ── Linux process block / Blocage processus Linux ────────────────────────

    def _block_linux_process(self, proc_name: str, rid: str) -> tuple[bool, str]:
        """EN: iptables `owner` matches by PID — resolve the name to current
        PIDs via psutil. Only locally generated packets match; still useful
        for an instant kill-switch on a known process.
        FR: `owner` matche par PID — on résout le nom en PID via psutil."""
        try:
            import psutil
            pids = [p.pid for p in psutil.process_iter(["name"])
                    if (p.info.get("name") or "").lower() == proc_name.lower()]
        except Exception as e:                        # noqa: BLE001
            return False, str(e)[:200]
        if not pids:
            return False, f"no running process named {proc_name}"
        ok_all = True
        for pid in pids[:8]:                          # EN: cap / FR: borne
            ok, _ = self._run(["iptables", "-w", "-I", "OUTPUT", "-m", "owner",
                               "--pid-owner", str(pid), "-j", "DROP"])
            ok_all = ok_all and ok
        return ok_all, "" if ok_all else "owner match failed"

    # ── macOS pf / pf macOS ──────────────────────────────────────────────────

    def _pf_apply(self) -> tuple[bool, str]:
        """EN: Regenerate the com.snitch anchor from enabled rules + lockdown
        and load it with pfctl. The anchor file lives in the data dir.
        FR: Régénère l'ancre com.snitch depuis les règles actives + lockdown
        et la charge avec pfctl."""
        dests, procs_note = [], []
        with self._lock:
            rules = [r for r in self._rules if r.get("enabled", True)]
            lockdown = self._lockdown
        for r in rules:
            if r["kind"] in ("ip", "cidr"):
                dests.append(r["value"])
            elif r["kind"] == "domain":
                dests += r.get("resolved", [])
            elif r["kind"] == "port":
                dests.append(f"port {r['value']}")
            elif r["kind"] == "process":
                procs_note.append(r["value"])   # EN: pf can't match processes / FR: pf ne filtre pas par processus
        lines = [f'table <snitch_block> const {{ {", ".join(d for d in dests if "/" in d or ":" not in d)} }}']
        lines.append("block drop out quick inet from any to <snitch_block>")
        port_rules = [r["value"] for r in rules if r["kind"] == "port"]
        for p in port_rules:
            lines.append(f"block drop out quick inet proto tcp from any to any port {p}")
        if lockdown:
            nets = ", ".join(_PRIVATE_NETS)
            lines.append(f"block drop out quick inet from any to ! {{ {nets} }}")
        anchor = self._data_dir / "pf-snitch.anchor"
        anchor.write_text("\n".join(lines) + "\n")
        return self._run(["pfctl", "-a", "com.snitch", "-f", str(anchor)])

    # ── Lockdown internals / Internes lockdown ───────────────────────────────

    def _lockdown_apply(self, on: bool) -> tuple[bool, str]:
        if self._demo:
            return True, ""
        if self._platform == "windows":
            if on:
                return self._run(["netsh", "advfirewall", "set", "allprofiles",
                                  "firewallpolicy", "blockinbound,blockoutbound"])
            return self._run(["netsh", "advfirewall", "set", "allprofiles",
                              "firewallpolicy", "blockinbound,allowoutbound"])
        if self._platform == "linux":
            if on:
                self._run(["iptables", "-w", "-N", "SNITCH_LOCK"])
                self._run(["iptables", "-w", "-F", "SNITCH_LOCK"])
                for net in _PRIVATE_NETS[:5]:
                    self._run(["iptables", "-w", "-A", "SNITCH_LOCK", "-d", net, "-j", "ACCEPT"])
                self._run(["iptables", "-w", "-A", "SNITCH_LOCK", "-o", "lo", "-j", "ACCEPT"])
                ok, err = self._run(["iptables", "-w", "-A", "SNITCH_LOCK", "-j", "DROP"])
                self._run(["iptables", "-w", "-I", "OUTPUT", "1", "-j", "SNITCH_LOCK"])
                return ok, err
            self._run(["iptables", "-w", "-D", "OUTPUT", "-j", "SNITCH_LOCK"])
            ok, err = self._run(["iptables", "-w", "-F", "SNITCH_LOCK"])
            return ok, err
        if self._platform == "darwin":
            with self._lock:
                self._lockdown = on
            return self._pf_apply()
        return False, f"unsupported platform {self._platform}"

    # ── DNS resolution for domain rules / Résolution DNS ────────────────────

    @staticmethod
    def _resolve_domain(domain: str) -> list[str]:
        """EN: Resolve a domain rule to concrete IPs now (firewalls match IPs,
        not names). Re-resolved on each apply — best effort.
        FR: Résout une règle domaine en IP concrètes (les pare-feux matchent
        des IP, pas des noms)."""
        ips: set[str] = set()
        try:
            for info in socket.getaddrinfo(domain, None):
                ip = info[4][0]
                try:
                    ipaddress.ip_address(ip)
                    ips.add(ip + ("/128" if ":" in ip else "/32"))
                except ValueError:
                    continue
        except socket.gaierror:
            pass
        return sorted(ips)
