"""
EN: Firewall orchestration — Snitch does NOT filter packets in user-space;
    it drives the OS-native firewall instead:
      * Windows → WFP USER-MODE filters via `fwpuclnt.dll` ctypes (ALE
                  connect layers, per-app ALE_APP_ID, per-key deletes —
                  see detection/wfp.py), `netsh advfirewall` as fallback,
      * Linux   → `iptables` OUTPUT chain (a dedicated SNITCH_LOCK chain for
                  lockdown, per-destination DROP rules otherwise) +
                  `tc` clsact/flower policing for throttle rules,
      * macOS   → `pf` anchors (a generated ruleset loaded with pfctl).
    Rules are persisted in the settings table ("firewall_rules") so they
    survive restarts. Every apply/remove is best-effort: failures are
    recorded on the rule instead of raising — the backend often runs
    elevated already (packet capture requires it), but demo mode and
    unprivileged runs degrade gracefully to `applied=False`.

    Rule kinds:  "ip"      single remote IP
                 "cidr"    network (e.g. 185.0.0.0/8)
                 "domain"  resolved to IPs at apply time AND re-resolved
                          periodically (refresh_domains) so CDN rotation
                          and DNS changes don't silently unblock a name
                 "process" process name/path (WFP ALE_APP_ID on Windows —
                          names resolved to exe paths — iptables owner
                          match on Linux; unsupported on macOS pf)
                 "port"    remote port
    Rule actions: "block"    drop the traffic (default)
                  "sinkhole" redirect instead of dropping — domains go to
                          127.0.0.1 via a marked block in the hosts file
                          (all OSes), IPs/CIDRs via iptables DNAT in the
                          nat OUTPUT chain (Linux only). The loopback
                          responder (detection/sinkresponder.py) then logs
                          the request's Host/path/SNI → SINKHOLE_HIT.
                  "throttle" rate-limit instead of blocking — Linux `tc`
                          clsact egress police per destination (rule["rate"]
                          kbit/s); other platforms report applied=False.
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
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

# EN: RFC-1034/1123 hostname — labels of ≤63 alnum/dash chars joined by
#     dots, total ≤253. Anchored so no whitespace/newline can slip through.
# FR: Nom d'hôte RFC-1034/1123 — labels de ≤63 caractères alnum/tiret joints
#     par des points, total ≤253. Ancré : aucun espace/newline ne passe.
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")

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
        # EN: WFP user-mode backend (Windows) — opened lazily on first apply;
        #     None = not tried, False = unavailable, WfpBackend = active.
        # FR: Backend WFP user-mode (Windows) — ouvert au premier apply ;
        #     None = pas tenté, False = indisponible, WfpBackend = actif.
        self._wfp: object | None = None
        # EN: tc state for throttle rules — iface cached after first setup.
        # FR: État tc pour les règles throttle — iface mise en cache.
        self._tc_iface: str | None = None
        # EN: Linux firewall tool — 'iptables' | 'nft' | False (none).
        #     nftables is the modern path; iptables-nft maps to it anyway.
        # FR: Outil pare-feu Linux — 'iptables' | 'nft' | False (aucun).
        #     nftables est le chemin moderne ; iptables-nft y mappe déjà.
        self._linux_fw: object | None = None

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

    def add_rule(self, kind: str, value: str, action: str = "block",
                 rate: int = 64) -> dict:
        """EN: Create + apply a rule. `value` depends on kind (see module doc),
        `action` is "block" (default), "sinkhole" or "throttle" (rate kbit/s).
        Returns the persisted rule dict including its apply result.
        FR: Créer + appliquer une règle. `action` = « block » (défaut),
        « sinkhole » ou « throttle » (rate en kbit/s)."""
        kind = kind.lower().strip()
        value = str(value).strip()
        action = (action or "block").lower().strip()
        if kind not in ("ip", "cidr", "domain", "process", "port"):
            raise ValueError(f"unknown rule kind: {kind}")
        if action not in ("block", "sinkhole", "throttle"):
            raise ValueError(f"unknown rule action: {action}")
        if action != "block" and kind in ("process", "port"):
            raise ValueError(f"{action} is not meaningful for kind {kind}")
        if kind == "domain":
            # EN: Strict hostname validation — the sinkhole path writes this
            #     value verbatim into the hosts file, so newlines/whitespace
            #     or shell chars must be impossible.
            # FR: Validation stricte du nom d'hôte — le chemin sinkhole
            #     écrit cette valeur verbatim dans le fichier hosts, donc
            #     retours à la ligne/espaces/caractères shell impossibles.
            value = value.lower().rstrip(".")
            if not _DOMAIN_RE.match(value):
                raise ValueError(f"invalid domain name: {value[:80]}")
        if kind == "port":
            # EN: Ports reach iptables/netsh argv — coerce to a real port
            #     number so the rule fails here, not silently downstream.
            # FR: Les ports arrivent en argv iptables/netsh — forcer un
            #     vrai numéro pour échouer ici, pas silencieusement plus bas.
            try:
                port_no = int(value)
            except ValueError:
                raise ValueError(f"invalid port: {value[:80]}") from None
            if not 1 <= port_no <= 65535:
                raise ValueError(f"port out of range: {port_no}")
            value = str(port_no)
        if len(value) > 253:
            raise ValueError("rule value too long")
        rule = {
            "id": uuid.uuid4().hex[:10],
            "kind": kind,
            "value": value,
            "action": action,
            "rate": max(1, min(int(rate or 64), 1_000_000)),  # EN: kbit/s / FR: kbit/s
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

    # ── Named profiles / Profils nommés ──────────────────────────────────────
    #
    # EN: A profile is a named bundle of ordinary rules + a lockdown state,
    #     expanded through the same add/remove machinery the UI uses — no
    #     hidden code path. `permissive` empties the policy, `balanced`
    #     adds a conservative egress baseline (spam-bot SMTP, common
    #     stratum mining-pool ports), `strict` is balanced + lockdown.
    #     Applying a profile never removes rules it did not create (except
    #     `permissive`, whose whole point is a clean slate).
    # FR: Un profil est un lot nommé de règles ordinaires + un état de
    #     lockdown, appliqué par la même machinerie add/remove que l'UI —
    #     aucun chemin de code caché. `permissive` vide la politique,
    #     `balanced` ajoute une base sortante prudente (SMTP des botnets
    #     de spam, ports stratum de pools de minage courants), `strict`
    #     = balanced + lockdown. Appliquer un profil ne retire jamais les
    #     règles qu'il n'a pas créées (sauf `permissive`, dont c'est le
    #     but).

    PROFILES: dict[str, dict] = {
        "permissive": {
            "lockdown": False,
            "replace": True,
            "rules": [],
        },
        "balanced": {
            "lockdown": False,
            "replace": False,
            "rules": [
                # EN: Outbound SMTP — classic spam-botnet egress.
                # FR: SMTP sortant — égress classique des botnets de spam.
                {"kind": "port", "value": "25", "action": "block"},
                # EN: Common stratum mining-pool ports.
                # FR: Ports stratum de pools de minage courants.
                {"kind": "port", "value": "3333", "action": "block"},
                {"kind": "port", "value": "5555", "action": "block"},
                {"kind": "port", "value": "7777", "action": "block"},
                {"kind": "port", "value": "14444", "action": "block"},
            ],
        },
        "strict": {
            "lockdown": True,
            "replace": False,
            "rules": [
                {"kind": "port", "value": "25", "action": "block"},
                {"kind": "port", "value": "3333", "action": "block"},
                {"kind": "port", "value": "5555", "action": "block"},
                {"kind": "port", "value": "7777", "action": "block"},
                {"kind": "port", "value": "14444", "action": "block"},
            ],
        },
    }

    def apply_profile(self, name: str) -> dict:
        """EN: Expand a named profile into real rules + lockdown state.
        Existing identical rules are reused (dedup on kind/value/action);
        `permissive` removes every rule first. Returns a summary.
        FR: Déplier un profil nommé en vraies règles + état lockdown. Les
        règles identiques existantes sont réutilisées ; `permissive`
        supprime d'abord toutes les règles. Renvoie un résumé."""
        spec = self.PROFILES.get((name or "").lower().strip())
        if spec is None:
            raise ValueError(f"unknown profile: {name}")
        removed = 0
        if spec["replace"]:
            with self._lock:
                ids = [r["id"] for r in self._rules]
            for rid in ids:
                if self.remove_rule(rid):
                    removed += 1
        added = 0
        for tpl in spec["rules"]:
            if self._find_rule(tpl["kind"], tpl["value"], tpl["action"]):
                continue                            # EN: already there / FR: déjà présente
            self.add_rule(tpl["kind"], tpl["value"], tpl["action"])
            added += 1
        lockdown_res = None
        if spec["lockdown"] is not None:
            lockdown_res = self.set_lockdown(bool(spec["lockdown"]))
        return {"profile": name, "added": added, "removed": removed,
                "lockdown": lockdown_res}

    def _find_rule(self, kind: str, value: str, action: str) -> Optional[dict]:
        """EN: First rule with the same kind/normalized value/action —
        profile dedup helper. / FR: Première règle de même
        kind/valeur/action — dédup des profils."""
        with self._lock:
            for r in self._rules:
                if (r["kind"] == kind and r["action"] == action
                        and str(r["value"]).lower() == str(value).lower()):
                    return r
        return None

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
        action = rule.get("action", "block")
        if action == "sinkhole":
            rule["applied"], rule["error"] = self._sinkhole_apply(rule)
            return
        if action == "throttle":
            rule["applied"], rule["error"] = self._throttle_apply(rule)
            return
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
            # EN: WFP user-mode first — per-app ALE_APP_ID + atomic per-key
            #     deletes; netsh stays as the honest fallback.
            # FR: WFP user-mode d'abord — ALE_APP_ID par app + suppressions
            #     atomiques par clé ; netsh reste le repli honnête.
            ok, err = self._wfp_apply(kind, target, rid)
            if ok is not None:
                return ok, err
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
            tool = self._linux_tool()
            if tool == "nft":
                return self._nft_apply(kind, target, rid)
            if tool is None:
                return False, "no iptables or nft binary"
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

    # ── Windows WFP backend / Backend WFP Windows ────────────────────────────

    def _wfp_engine(self):
        """EN: Lazy engine open — returns the backend, False when unavailable
        (non-Windows, missing admin, absent dll), and remembers the verdict.
        FR: Ouverture paresseuse du moteur — renvoie le backend, False si
        indisponible, et mémorise le verdict."""
        if self._wfp is not None:
            return self._wfp or None
        try:
            from detection.wfp import WfpBackend
        except ImportError:
            try:
                from .wfp import WfpBackend            # type: ignore
            except ImportError:
                self._wfp = False
                return None
        if not WfpBackend.available():
            self._wfp = False
            return None
        backend = WfpBackend()
        ok, _err = backend.open()
        self._wfp = backend if ok else False
        return self._wfp or None

    def _resolve_exe(self, name_or_path: str) -> Optional[str]:
        """EN: WFP ALE_APP_ID needs a real exe path — resolve bare process
        names through the running process table (netsh needed the same).
        FR: ALE_APP_ID exige un chemin d'exe — les noms nus sont résolus
        via la table des processus (netsh l'exigeait déjà)."""
        if os.sep in name_or_path or "/" in name_or_path:
            return name_or_path
        try:
            import psutil
            for p in psutil.process_iter(["name", "exe"]):
                if (p.info.get("name") or "").lower() == name_or_path.lower():
                    return p.info.get("exe")
        except Exception:                            # noqa: BLE001
            pass
        return None

    def _wfp_apply(self, kind: str, target: str, rid: str):
        """EN: Apply through WFP. Returns (ok, err) or (None, reason) when
        WFP can't serve this rule — the caller then falls back to netsh.
        FR: Applique via WFP. Renvoie (ok, err) ou (None, raison) quand
        WFP ne peut pas servir — l'appelant replie alors sur netsh."""
        wfp = self._wfp_engine()
        if wfp is None:
            return None, "wfp unavailable"
        if kind == "process":
            exe = self._resolve_exe(target)
            if not exe:
                return False, f"no running process/exe for {target}"
            conds = [{"app": exe}]
        elif kind == "port":
            conds = [{"port": int(target)}]
        else:                                        # EN: ip/cidr/domain / FR: idem
            conds = [{"remote": target}]
        ok, err = wfp.add_block(rid, conds)
        return ok, err

    def _wfp_delete(self, rule: dict) -> None:
        """EN: Delete all WFP filters a rule may have created — keys are
        deterministic, unknown ones are simply absent.
        FR: Supprime tous les filtres WFP créés par la règle — les clés
        sont déterministes, les absentes ignorées."""
        wfp = self._wfp_engine()
        if wfp is None:
            return
        from detection.wfp import WfpBackend
        tags = WfpBackend.tags_for(rule["kind"], rule["value"],
                                   rule.get("resolved"))
        wfp.delete(rule["id"], tags)

    # ── Throttle (tc) / Limitation (tc) ─────────────────────────────────────

    def _tc_setup(self) -> tuple[bool, str]:
        """EN: One-time clsact qdisc on the default-route interface — the
        modern, filterable egress hook (no root-qdisc takeover like htb).
        FR: qdisc clsact unique sur l'interface de la route par défaut —
        le point d'accroche sortant filtrable moderne (pas de reprise de
        la qdisc root comme htb)."""
        if self._tc_iface:
            return True, ""
        ok, out = self._run(["ip", "-o", "route", "show", "default"])
        if not ok or not out:
            return False, "no default route / ip tool missing"
        try:
            self._tc_iface = out.split()[4]
        except IndexError:
            return False, "cannot parse default route"
        self._run(["tc", "qdisc", "add", "dev", self._tc_iface, "clsact"])
        # EN: "File exists" is fine — filters attach either way.
        # FR: « File exists » est acceptable — les filtres s'attachent pareil.
        return True, ""

    def _throttle_apply(self, rule: dict) -> tuple[bool, str]:
        """EN: Police egress to this destination at rule["rate"] kbit/s —
        clsact + flower dst_ip + police action. Linux only, honest False
        elsewhere. FR: Police la sortie vers cette destination à
        rule["rate"] kbit/s — clsact + flower dst_ip + action police.
        Linux seulement, False honnête ailleurs."""
        if self._platform != "linux":
            return False, "throttle needs tc/clsact (linux only)"
        ok, err = self._tc_setup()
        if not ok:
            return False, err
        idx = (int(rule["id"], 16) % 9900) + 100     # EN: stable prio / FR: prio stable
        rule["tc_pref"] = idx
        targets = rule.get("resolved") if rule["kind"] == "domain" else [rule["value"]]
        ok_all, err_all = True, ""
        for t in targets:
            proto = "ipv6" if ":" in t else "ip"
            ok, err = self._run([
                "tc", "filter", "add", "dev", self._tc_iface, "egress",
                "protocol", proto, "pref", str(idx), "flower",
                "dst_ip", t.split("/")[0],
                "action", "police", "rate", f"{rule['rate']}kbit",
                "burst", "32k", "conform-exceed", "drop"])
            ok_all = ok_all and ok
            err_all = err or err_all
        return ok_all, err_all or None

    def _throttle_remove(self, rule: dict) -> None:
        """EN: Remove this rule's tc filter by its stored pref.
        FR: Supprime le filtre tc de la règle par son pref mémorisé."""
        idx = rule.get("tc_pref")
        if self._platform != "linux" or not idx or not self._tc_iface:
            return
        for proto in ("ip", "ipv6"):
            self._run(["tc", "filter", "del", "dev", self._tc_iface,
                       "egress", "protocol", proto, "pref", str(idx),
                       "flower"])

    # ── Sinkhole / Trou noir ─────────────────────────────────────────────────

    def _hosts_path(self) -> Optional[Path]:
        """EN: Platform hosts file — where domain sinkholes are written.
        FR: Fichier hosts de la plateforme — là où vont les sinkholes domaine."""
        if self._platform in ("linux", "darwin"):
            return Path("/etc/hosts")
        if self._platform == "windows":
            root = os.environ.get("SystemRoot", r"C:\Windows")
            return Path(root) / "System32" / "drivers" / "etc" / "hosts"
        return None

    def _sinkhole_apply(self, rule: dict) -> tuple[bool, str]:
        """EN: Redirect instead of drop. Domains land in the hosts file
        between `# snitch-sinkhole <id>` markers (removal = strip the block);
        IP/CIDR targets get an iptables DNAT rule to 127.0.0.1 on Linux.
        FR: Rediriger plutôt que dropper. Les domaines vont dans le fichier
        hosts entre marqueurs `# snitch-sinkhole <id>` ; les IP/CIDR reçoivent
        une règle DNAT iptables vers 127.0.0.1 sous Linux."""
        kind, value, rid = rule["kind"], rule["value"], rule["id"]
        if kind == "domain":
            hosts = self._hosts_path()
            if hosts is None:
                return False, f"no hosts file path on {self._platform}"
            # EN: Cover the bare name + www + wildcard-ish parents.
            # FR: Couvrir le nom nu + www + parents type wildcard.
            names = {value, f"www.{value}"}
            lines = [f"# snitch-sinkhole {rid} begin"]
            lines += [f"127.0.0.1 {n}" for n in sorted(names)]
            lines += [f"::1 {n}" for n in sorted(names)]
            lines.append(f"# snitch-sinkhole {rid} end")
            try:
                with open(hosts, "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                return True, ""
            except OSError as e:
                return False, f"hosts file not writable: {e}"
        # EN: ip/cidr sinkhole — DNAT to loopback, Linux nat table only.
        # FR: sinkhole ip/cidr — DNAT vers loopback, table nat Linux seulement.
        if self._platform != "linux":
            return False, "ip sinkhole needs iptables/nft (linux only)"
        if self._linux_tool() == "nft":
            return self._nft_dnat(value, rid)
        if self._linux_tool() is None:
            return False, "no iptables or nft binary"
        return self._run(["iptables", "-w", "-t", "nat", "-I", "OUTPUT",
                          "-d", value, "-j", "DNAT",
                          "--to-destination", "127.0.0.1",
                          "-m", "comment", "--comment", f"snitch-sinkhole-{rid}"])

    def _sinkhole_remove(self, rule: dict) -> None:
        """EN: Undo a sinkhole — strip the marked hosts block or delete the
        DNAT rule. Best-effort, never raises.
        FR: Défaire un sinkhole — retirer le bloc hosts marqué ou supprimer
        la règle DNAT. Au mieux, ne lève jamais."""
        kind, rid, value = rule["kind"], rule["id"], rule["value"]
        if kind == "domain":
            hosts = self._hosts_path()
            if hosts is None:
                return
            try:
                lines = hosts.read_text(encoding="utf-8",
                                        errors="replace").splitlines()
                out, skip = [], False
                for line in lines:
                    if line.strip() == f"# snitch-sinkhole {rid} begin":
                        skip = True
                        continue
                    if line.strip() == f"# snitch-sinkhole {rid} end":
                        skip = False
                        continue
                    if not skip:
                        out.append(line)
                hosts.write_text("\n".join(out) + "\n", encoding="utf-8")
            except OSError:
                pass
        elif self._platform == "linux":
            if self._linux_tool() == "nft":
                self._nft_del_comment(f"snitch-sinkhole-{rid}")
                return
            self._run(["iptables", "-w", "-t", "nat", "-D", "OUTPUT",
                       "-d", value, "-j", "DNAT",
                       "--to-destination", "127.0.0.1",
                       "-m", "comment", "--comment", f"snitch-sinkhole-{rid}"])

    # ── Domain re-resolution / Re-résolution des domaines ───────────────────

    def refresh_domains(self) -> int:
        """EN: Re-resolve every enabled domain rule and apply the delta —
        stale IPs removed, new IPs added. Called periodically from the flush
        loop so CDN rotation can't silently unblock a name. Returns the
        number of rules whose resolution changed.
        FR: Re-résoudre chaque règle domaine active et appliquer le delta —
        IP périmées retirées, nouvelles ajoutées. Appelé périodiquement
        depuis la boucle de flush pour que la rotation CDN ne débloque pas
        silencieusement un nom. Retourne le nombre de règles modifiées."""
        with self._lock:
            rules = [r for r in self._rules
                     if r.get("enabled", True) and r["kind"] == "domain"]
        changed = 0
        for r in rules:
            new = self._resolve_domain(r["value"])
            old = list(r.get("resolved") or [])
            if set(new) == set(old):
                continue
            changed += 1
            # EN: Sinkhole domains redirect through the hosts file (by name) —
            #     re-resolution only refreshes packet-matching visibility,
            #     no OS-level delta needed.
            # FR: Les domaines sinkhole redirigent via le fichier hosts (par
            #     nom) — la re-résolution ne sert qu'à la visibilité du
            #     matching, pas de delta OS nécessaire.
            if r.get("action", "block") == "sinkhole":
                r["resolved"] = new
                continue
            if not self._demo:
                if r.get("action") == "throttle":
                    # EN: tc filters are per-IP — re-apply the whole flower
                    #     set (same pref → add replaces; stale IPs removed
                    #     by delete+re-add cycle).
                    # FR: Les filtres tc sont par IP — réapplication du jeu
                    #     flower complet (même pref → l'ajout remplace).
                    self._throttle_remove(r)
                    r["resolved"] = new
                    self._throttle_apply(r)
                    continue
                if self._platform == "linux":
                    rid = r["id"]
                    if self._linux_tool() == "nft":
                        # EN: Comment-tagged delete is the whole delta —
                        #     one scan covers every stale IP at once.
                        # FR: La suppression par commentaire fait tout le
                        #     delta en un scan.
                        self._nft_del_comment(f"snitch-{rid}")
                        for t in new:
                            self._nft_apply("domain", t, rid)
                    else:
                        for t in sorted(set(old) - set(new)):
                            self._run(["iptables", "-w", "-D", "OUTPUT", "-d", t,
                                       "-j", "DROP", "-m", "comment",
                                       "--comment", f"snitch-{rid}"])
                        for t in sorted(set(new) - set(old)):
                            self._run(["iptables", "-w", "-I", "OUTPUT", "-d", t,
                                       "-j", "DROP", "-m", "comment",
                                       "--comment", f"snitch-{rid}"])
                elif self._platform == "windows":
                    if self._wfp_engine() is not None:
                        # EN: True delta — per-IP keys mean stale addresses
                        #     are deleted and new ones added atomically.
                        # FR: Vrai delta — les clés par IP suppriment les
                        #     adresses périmées et ajoutent les nouvelles.
                        self._wfp_delete({
                            "id": r["id"], "kind": "domain",
                            "value": r["value"], "resolved": old})
                        for t in sorted(set(new) - set(old)):
                            self._wfp_engine().add_block(
                                r["id"], [{"remote": t}])
                    else:
                        # EN: netsh rules are name-keyed, not value-keyed —
                        #     cheapest correct delta = delete + recreate.
                        # FR: Les règles netsh sont indexées par nom —
                        #     delta correct minimal = supprimer + recréer.
                        self._remove(r)
                        r["resolved"] = new
                        self._apply(r)
                        continue
                elif self._platform == "darwin":
                    r["resolved"] = new
                    self._pf_apply()      # EN: anchor is regenerated whole
                                          # FR: l'ancre est régénérée entière
                    continue
            r["resolved"] = new
        return changed

    def _remove(self, rule: dict) -> None:
        if self._demo:
            return
        if rule.get("action", "block") == "sinkhole":
            self._sinkhole_remove(rule)
            return
        if rule.get("action") == "throttle":
            self._throttle_remove(rule)
            return
        rid, kind = rule["id"], rule["kind"]
        if self._platform == "windows":
            # EN: WFP filters are deleted by deterministic key — then the
            #     netsh copies (fallback path) get cleaned too.
            # FR: Les filtres WFP se suppriment par clé déterministe —
            #     puis les copies netsh (chemin de repli) sont nettoyées.
            self._wfp_delete(rule)
            self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                       f"name=SnitchRule-{rid}"])
            # EN: per-target suffixed copies / FR: copies suffixées par cible
            self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                       "name=all", "program=" + rule["value"]]) if kind == "process" else None
        elif self._platform == "linux":
            if self._linux_tool() == "nft":
                self._nft_del_comment(f"snitch-{rid}")
                return
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
        if self._linux_tool() == "nft":
            # EN: nftables has no PID-owner match — meta skuid is per-USER.
            #     Honest refusal rather than a wrong-semantic rule.
            # FR: nftables n'a pas de match par PID — meta skuid est par
            #     UTILISATEUR. Refus honnête plutôt qu'une règle biaisée.
            return False, ("nftables cannot match per-process (owner "
                           "match is iptables-only); use a port/ip rule "
                           "instead")
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

    # ── Linux nftables backend / Backend nftables Linux ────────────────────
    #
    # EN: iptables-nft already maps onto nftables, but some minimal systems
    #     ship ONLY `nft`. When iptables is absent we drive nftables
    #     directly: a dedicated `inet snitch` table whose `output` chain
    #     hooks the output path, plus a `dnat` chain for IP sinkholes.
    #     Rules are removed by their `comment "snitch-<rid>"` tag — we
    #     scan `nft -a` handles and delete each match.
    # FR: iptables-nft mappe déjà sur nftables, mais certains systèmes
    #     minimaux n'ont QUE `nft`. Sans iptables on pilote nftables
    #     directement : table `inet snitch` dédiée avec chaîne `output`
    #     accrochée au chemin sortant + chaîne `dnat` pour les sinkholes
    #     IP. Les règles se suppriment par leur tag `comment "snitch-<rid>"`
    #     via les handles de `nft -a`.

    def _linux_tool(self) -> Optional[str]:
        """EN: Cached Linux backend — 'iptables' preferred (widest compat),
        'nft' when only nftables exists, False when neither.
        FR: Backend Linux en cache — 'iptables' de préférence, 'nft' quand
        seul nftables existe, False sinon."""
        if self._linux_fw is not None:
            return self._linux_fw or None
        if shutil.which("iptables"):
            self._linux_fw = "iptables"
        elif shutil.which("nft"):
            self._linux_fw = "nft"
        else:
            self._linux_fw = False
        return self._linux_fw or None

    def _nft_setup(self) -> None:
        """EN: Create the table + hooked chains once — idempotent, errors
        ignored (existing objects make nft exit non-zero harmlessly).
        FR: Crée la table + chaînes accrochées une fois — idempotent."""
        self._run(["nft", "add", "table", "inet", "snitch"])
        self._run(["nft", "add", "chain", "inet", "snitch", "output",
                   "{", "type", "filter", "hook", "output", "priority",
                   "0", ";", "policy", "accept", ";", "}"])
        self._run(["nft", "add", "chain", "inet", "snitch", "dnat",
                   "{", "type", "nat", "hook", "output", "priority",
                   "-100", ";", "}"])

    def _nft_apply(self, kind: str, target: str, rid: str) -> tuple[bool, str]:
        """EN: Append one drop rule with our comment tag.
        FR: Ajoute une règle drop avec notre tag de commentaire."""
        self._nft_setup()
        rule = ["nft", "add", "rule", "inet", "snitch", "output"]
        if kind in ("ip", "cidr", "domain"):
            fam = "ip6" if ":" in target else "ip"
            rule += [fam, "daddr", target]
        elif kind == "port":
            rule += ["tcp", "dport", str(target)]
        else:
            return False, f"nft backend cannot match kind {kind}"
        rule += ["counter", "drop", "comment", f'"snitch-{rid}"']
        return self._run(rule)

    def _nft_dnat(self, target: str, rid: str) -> tuple[bool, str]:
        """EN: IP sinkhole under nftables — dnat to loopback in the nat
        chain. / FR: Sinkhole IP sous nftables — dnat vers loopback."""
        self._nft_setup()
        fam = "ip6" if ":" in target else "ip"
        loopback = "::1" if ":" in target else "127.0.0.1"
        return self._run([
            "nft", "add", "rule", "inet", "snitch", "dnat",
            fam, "daddr", target, "counter", "dnat", "to", loopback,
            "comment", f'"snitch-sinkhole-{rid}"'])

    def _nft_del_comment(self, tag: str) -> None:
        """EN: Delete every rule in our chains carrying `comment "tag"` —
        handle-scan via `nft -a list chain`. Best-effort.
        FR: Supprime chaque règle de nos chaînes portant `comment "tag"`
        — scan des handles via `nft -a`. Au mieux."""
        for chain in ("output", "dnat"):
            ok, out = self._run(["nft", "-a", "list", "chain", "inet",
                                 "snitch", chain])
            if not ok:
                continue
            for line in out.splitlines():
                if tag not in line or "handle" not in line:
                    continue
                try:
                    handle = line.rsplit("handle", 1)[1].strip().split()[0]
                    self._run(["nft", "delete", "rule", "inet", "snitch",
                               chain, "handle", handle])
                except (IndexError, ValueError):
                    continue

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
            if self._linux_tool() == "nft":
                # EN: Lockdown under nftables — private/LAN returns, then a
                #     tagged blanket drop at the END of our output chain.
                # FR: Lockdown sous nftables — return privé/LAN puis drop
                #     général taggé en FIN de notre chaîne output.
                if on:
                    self._nft_setup()
                    nets = ", ".join(_PRIVATE_NETS[:5])
                    self._run(["nft", "add", "rule", "inet", "snitch",
                               "output", "ip", "daddr", "{", nets, "}",
                               "return", "comment", '"snitch-lock"'])
                    self._run(["nft", "add", "rule", "inet", "snitch",
                               "output", "oif", '"lo"', "return",
                               "comment", '"snitch-lock"'])
                    return self._run(["nft", "add", "rule", "inet",
                                      "snitch", "output", "counter",
                                      "drop", "comment", '"snitch-lock"'])
                self._nft_del_comment("snitch-lock")
                return True, ""
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
