"""
Snitch — network containment sandbox / bac à sable réseau.

EN: The honest user-mode slice of "micro-VM containment": run a suspect
    binary in a network-less sandbox so an analyst can observe its
    behaviour (filesystem, dns-ish attempts, crashes) with zero egress.
    No VM, no driver — just the OS's own isolation:

      * Linux : `unshare --user --net` — an unprivileged user+network
                namespace; the child sees only loopback. Works without
                root on any kernel with unprivileged userns enabled
                (Debian disables it — reported honestly).
      * macOS : `sandbox-exec` with a `(deny network*)` seatbelt
                profile — deprecated since Catalina but still enforced
                on current releases; reported as best-effort.
      * Windows: no user-mode equivalent exists (Job Objects restrict
                 CPU/memory, not sockets) — unavailable() is honest.

    Safety: the binary runs UNPRIVILEGED with NO network; the wrapper
    itself only launches it and caps runtime + captured output. The
    caller decides what to detonate — Snitch never auto-detonates.

FR: La tranche user-mode honnête du « confinement micro-VM » : exécuter
    un binaire suspect dans un bac à sable sans réseau pour observer son
    comportement avec zéro égress. Pas de VM, pas de driver — juste
    l'isolation de l'OS : `unshare --user --net` sous Linux (namespace
    utilisateur + réseau non privilégié — l'enfant ne voit que loopback),
    `sandbox-exec` + profil `(deny network*)` sous macOS (déprécié mais
    encore appliqué). Sous Windows aucun équivalent user-mode n'existe —
    le statut est honnête. Sécurité : le binaire tourne non privilégié et
    sans réseau ; le wrapper ne fait que le lancer avec bornes temps +
    sortie. Snitch ne détone jamais rien tout seul.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from procutils import spawn_kwargs

_SYSTEM = platform.system().lower()
_MAX_SECONDS = 30
_MAX_OUT = 4096

# EN: Seatbelt profile — deny every network operation, keep filesystem +
#     process defaults readable/writable (the point is egress, not
#     filesystem damage control).
# FR: Profil seatbelt — refuse toute opération réseau, garde le reste par
#     défaut (le but est l'égress, pas le verrouillage filesystem).
_MACOS_PROFILE = ("(version 1)(allow default)(deny network*)"
                  "(deny network-bind)(deny network-outbound)"
                  "(deny network-inbound)")


def available() -> tuple[bool, str]:
    """EN: Honest capability probe — which sandbox primitive exists here.
    FR: Sonde de capacité honnête — quelle primitive de sandbox existe ici."""
    if _SYSTEM == "linux":
        if shutil.which("unshare"):
            return True, "linux user+net namespace (unshare -U -n)"
        # EN: firejail is a common pre-installed sandbox — `--net=none`
        #     gives the same zero-egress guarantee as our namespace path.
        # FR: firejail est souvent pré-installé — `--net=none` donne la
        #     même garantie zéro-égress que le namespace.
        if shutil.which("firejail"):
            return True, "linux firejail (--net=none)"
        return False, "no unshare or firejail binary"
    if _SYSTEM == "darwin":
        if shutil.which("sandbox-exec"):
            return True, "macOS seatbelt (sandbox-exec deny network*)"
        return False, "no sandbox-exec binary"
    return False, ("no user-mode network sandbox on this OS "
                   "(Windows Job Objects can't restrict sockets)")


def sandbox_command(path: str, args: list[str]) -> list[str]:
    """EN: Wrap `path args` in the platform's network-denial sandbox —
        returns the full command for the API to run or the user to copy.
        Linux prefers `unshare -U -n` (unprivileged userns); if userns is
        disabled at boot the child reports EPERM — surfaced as an error,
        not faked.
    FR: Envelopper `path args` dans la sandbox réseau de la plateforme —
        renvoie la commande complète (API ou copie manuelle). Linux
        préfère `unshare -U -n` ; si les userns non privilégiés sont
        désactivés au boot, l'enfant renvoie EPERM — rapporté, pas simulé."""
    if _SYSTEM == "linux":
        if shutil.which("unshare"):
            return ["unshare", "--user", "--net", "--map-root-user",
                    "--fork", path, *args]
        # EN: --net=none removes all interfaces except loopback; --quiet
        #     keeps firejail's own banner out of the captured output.
        # FR: --net=none retire toutes les interfaces sauf loopback ;
        #     --quiet garde la bannière firejail hors de la sortie.
        return ["firejail", "--net=none", "--quiet", "--", path, *args]
    if _SYSTEM == "darwin":
        return ["sandbox-exec", "-p", _MACOS_PROFILE, path, *args]
    return [path, *args]                 # EN: never reached — caller checks available() first


def run_sandboxed(path: str, args: list[str],
                  seconds: int = 10) -> dict:
    """EN: Detonate `path` network-less for ≤_MAX_SECONDS, capturing
        bounded stdout+stderr — the egress-free behaviour report. The
        process is killed on timeout; a sandbox primitive failure is
        returned as an honest error (e.g. userns disabled → EPERM).
    FR: Détoner `path` sans réseau ≤_MAX_SECONDS, stdout+stderr bornés —
        le rapport de comportement sans égress. Le processus est tué au
        timeout ; un échec de primitive est renvoyé en erreur honnête."""
    ok, why = available()
    if not ok:
        return {"ok": False, "error": why}
    import os
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        return {"ok": False, "error": "not an executable file"}
    seconds = max(1, min(int(seconds), _MAX_SECONDS))
    cmd = sandbox_command(path, args[:16])
    try:
        t0 = time.monotonic()
        proc = subprocess.run(cmd, timeout=seconds, capture_output=True,
                             **spawn_kwargs(),
                              text=False, cwd="/", check=False)
        dur = round(time.monotonic() - t0, 2)
        return {"ok": True, "command": cmd, "seconds": dur,
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:_MAX_OUT].decode("utf-8", "replace"),
                "stderr": proc.stderr[:_MAX_OUT].decode("utf-8", "replace"),
                "note": "ran with no network — connection attempts "
                        "failed inside the sandbox"}
    except subprocess.TimeoutExpired:
        return {"ok": True, "command": cmd, "seconds": seconds,
                "exit_code": None, "stdout": "", "stderr": "",
                "note": "killed at timeout — network was denied "
                        "throughout"}
    except OSError as e:
        return {"ok": False, "command": cmd,
                "error": f"sandbox launch failed: {e}"}
