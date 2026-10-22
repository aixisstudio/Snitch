"""
Snitch — peer IOC sharing (decentralized-lite) / partage d'IOC entre
pairs (décentralisé allégé).

EN: The honest, shippable version of "fleet gossip": instead of a real
    epidemic protocol (libp2p, membership, NAT traversal — heavy and
    attack-prone), Snitch instances EXPLICITLY paired by the operator
    exchange their privacy-preserving IOC packs directly over HTTP:

      * peers are opt-in and explicit — a list of `http(s)://host:port`
        Snitch backends plus the shared bearer token; ZERO auto-discovery,
        nothing ever leaves for an unlisted address
      * transport = the peer's own authenticated API: our `format=proof`
        pack is POSTed to its /security/iocpack/import — no new wire
        protocol, the receiving side applies the same salted-Merkle
        verification as a file import
      * content = salted hash leaves + Merkle root ONLY (never raw IOCs,
        never hostnames/paths/users — the pack format already guarantees
        that)
      * cadence = manual `POST /remote/ioc_sync` plus an optional periodic
        push (~5 min) when `gossip_enabled` is set
      * failures are recorded per-peer and surfaced honestly in status()

    This IS decentralized sharing — no central server — scoped to the
    operator's own fleet, which is the honest 90% of the feature. A real
    anonymous gossip mesh stays a research item.

FR: Version honnête et livrable du « gossip de flotte » : au lieu d'un
    vrai protocole épidémique (lourd et exposé), les instances Snitch
    explicitement appairées par l'opérateur échangent leurs packs IOC
    préservant la vie privée en HTTP direct — pairs opt-in uniquement,
    transport = l'API authentifiée du pair (notre pack `format=proof`
    posté vers son /security/iocpack/import), contenu = feuilles salées +
    racine Merkle seulement. Partage réellement décentralisé, borné à la
    flotte de l'opérateur. Un mesh anonyme reste en recherche.
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

_MAX_PEERS = 32
_TIMEOUT = 8


class PeerSync:
    """EN: Owns the explicit peer list + per-peer sync state.
    FR: Gère la liste de pairs explicite + l'état de sync par pair."""

    def __init__(self, token_getter):
        """EN: token_getter() → the bearer token peers expect (their own
        API token — configured per deployment, never stored here).
        FR: token_getter() → le jeton bearer attendu par les pairs."""
        self._token_getter = token_getter
        self._peers: list[str] = []
        self._state: dict[str, dict] = {}

    def configure(self, peers: list[str]) -> None:
        """EN: Replace the peer list — host:port or http(s)://host:port,
        deduped, bounded. http is allowed on purpose: peers are LAN/trust-
        domain scoped and the payload is a hash pack, but https is
        recommended across untrusted links (documented).
        FR: Remplace la liste — host:port ou http(s)://, dédupliquée,
        bornée. http autorisé volontairement (LAN) ; https recommandé sur
        liens non fiables."""
        clean = []
        for p in peers[:_MAX_PEERS]:
            p = str(p).strip().rstrip("/")
            if not p:
                continue
            if not p.startswith(("http://", "https://")):
                p = "http://" + p
            if p not in clean:
                clean.append(p)
        self._peers = clean

    @property
    def peers(self) -> list[str]:
        return list(self._peers)

    def push_pack(self, pack: dict) -> dict:
        """EN: POST one IOC pack (snitch-ioc-proof/1 dict) to every peer's
        import endpoint. Returns per-peer results; never raises.
        FR: POST un pack IOC vers l'endpoint import de chaque pair.
        Renvoie les résultats par pair ; ne lève jamais."""
        if not self._peers:
            return {"ok": False, "error": "no peers configured"}
        body = json.dumps(pack).encode()
        results = {}
        for peer in self._peers:
            url = f"{peer}/security/iocpack/import"
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {self._token_getter()}"})
            try:
                with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                    st = {"ok": 200 <= r.status < 300, "code": r.status,
                          "ts": time.time()}
            except urllib.error.HTTPError as e:
                st = {"ok": False, "code": e.code, "ts": time.time()}
            except (urllib.error.URLError, OSError) as e:
                st = {"ok": False, "error": str(e)[:160],
                      "ts": time.time()}
            results[peer] = st
            self._state[peer] = st
        return {"ok": all(s.get("ok") for s in results.values()),
                "results": results}

    def status(self) -> dict:
        return {"peers": self._peers,
                "last": dict(self._state)}

    def fleet_audit(self) -> dict:
        """EN: Lightweight fleet console — GET /security/audit from every
        configured peer (authenticated, bounded timeout, failures are
        per-peer errors not crashes) and merge into one view: agent
        count, worst score, per-peer findings. This is the honest
        minimal version of "regroup N agents in one dashboard" — peers
        are still the operator-listed gossip_peers, so trust domain is
        unchanged. / FR: Console de flotte légère — GET /security/audit
        de chaque pair configuré et fusion en une vue. Version honnête
        minimale du « regrouper N agents » — les pairs sont les
        gossip_peers de l'opérateur, domaine de confiance inchangé."""
        agents: list[dict] = []
        for peer in self._peers:
            req = urllib.request.Request(
                f"{peer}/security/audit",
                headers={"Authorization":
                         f"Bearer {self._token_getter()}"})
            try:
                with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                    # EN: bounded read — a misbehaving/malicious peer
                    #     must not hand us an unbounded body.
                    # FR: lecture bornée — un pair défaillant/hostile ne
                    #     doit pas nous servir un corps illimité.
                    data = json.loads(
                        r.read(1 << 20).decode("utf-8", "replace"))
                data["peer"] = peer
                data["reachable"] = True
                agents.append(data)
            except urllib.error.HTTPError as e:
                agents.append({"peer": peer, "reachable": False,
                               "error": f"http {e.code}"})
            except (urllib.error.URLError, OSError, ValueError) as e:
                agents.append({"peer": peer, "reachable": False,
                               "error": str(e)[:160]})
        scores = [a["score"] for a in agents
                  if a.get("reachable") and isinstance(a.get("score"), int)]
        return {"agent_count": len(agents),
                "reachable": sum(1 for a in agents if a.get("reachable")),
                "worst_score": min(scores) if scores else None,
                "mean_score": round(sum(scores) / len(scores), 1)
                if scores else None,
                "agents": agents}
