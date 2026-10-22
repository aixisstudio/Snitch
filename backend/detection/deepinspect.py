"""
EN: Deep process inspection — the honest user-mode stand-in for dynamic
    taint analysis. Instead of simulating DTA, Snitch uses Frida (optional,
    user-installed) to attach to ONE suspicious process for a bounded
    window and instrument its socket entry points (connect / WSAConnect /
    sendto / sendmsg). For every outbound connection attempt it reports
    WHICH MODULE called the API — the return address resolves to the exe
    or a loaded DLL. That is exactly what catches injected code: a clean
    "chrome.exe" whose connections originate from a DLL living in %TEMP%
    is a red flag no packet inspection can produce.

    Bounded: max 60 s attach, max 500 events, one inspect at a time.
    Frida's own permission model applies (same user, debugger rights;
    hardened/SIP-protected macOS processes refuse attachment — reported
    honestly). Nothing is simulated when Frida is absent.

FR: Inspection profonde de processus — le remplaçant user-mode honnête de
    l'analyse de teinte dynamique. Au lieu de simuler la DTA, Snitch
    utilise Frida (optionnel, installé par l'utilisateur) pour s'attacher
    à UN processus suspect pendant une fenêtre bornée et instrumenter ses
    points d'entrée socket (connect / WSAConnect / sendto / sendmsg). Pour
    chaque tentative de connexion sortante, il rapporte QUEL MODULE a
    appelé l'API — l'adresse de retour résout vers l'exe ou une DLL
    chargée. C'est précisément ce qui attrape le code injecté : un
    « chrome.exe » sain dont les connexions viennent d'une DLL dans %TEMP%
    est un signal qu'aucune inspection de paquets ne peut produire.
"""

from __future__ import annotations

import threading
import time

_MAX_SECONDS = 60
_MAX_EVENTS = 500

# EN: Frida JS payload — hooks every plausible socket entry point on the
#     platform, parses the sockaddr, and sends back the calling module.
#     Defensive: missing exports are skipped, malformed sockaddr ignored.
# FR: Payload JS Frida — hooke chaque point d'entrée socket plausible,
#     analyse le sockaddr et renvoie le module appelant. Défensif : les
#     exports absents sont ignorés, les sockaddr malformés sautés.
_JS = r"""
var AF_INET = 2, AF_INET6_WIN = 23, AF_INET6_UNIX = 10;
function parseSockaddr(p) {
    try {
        var fam = p.readU16();
        if (fam === AF_INET) {
            return {ip: [p.add(4).readU8(), p.add(5).readU8(),
                         p.add(6).readU8(), p.add(7).readU8()].join('.'),
                    port: (p.add(2).readU8() << 8) | p.add(3).readU8()};
        }
        if (fam === AF_INET6_WIN || fam === AF_INET6_UNIX) {
            var b = [];
            for (var i = 8; i < 24; i += 2)
                b.push(p.add(i).readU16().toString(16));
            return {ip: b.join(':'),
                    port: (p.add(2).readU8() << 8) | p.add(3).readU8()};
        }
    } catch (e) {}
    return null;
}
function hook(api, lib) {
    var addr = null;
    try { addr = lib ? Module.getExportByName(lib, api)
                     : Module.findExportByName(null, api); }
    catch (e) { addr = null; }
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var sa = parseSockaddr(ptr(args[1]));
            if (!sa || !sa.ip || sa.ip === '0.0.0.0') return;
            var mod = null;
            try { mod = Process.findModuleByAddress(this.returnAddress); }
            catch (e) {}
            send({api: api, ip: sa.ip, port: sa.port,
                  module: mod ? mod.name : '?',
                  path: mod ? mod.path : ''});
        }
    });
}
// EN: POSIX sockets (Linux libc / macOS libsystem) + WinSock2.
// FR: sockets POSIX (libc Linux / libsystem macOS) + WinSock2.
['connect', 'sendto', 'sendmsg'].forEach(function (a) {
    hook(a, null); hook(a, 'libc.so'); hook(a, 'libSystem.B.dylib');
});
['WSAConnect', 'connect', 'WSASend', 'send'].forEach(function (a) {
    hook(a, 'ws2_32.dll');
});
"""


class DeepInspector:
    """EN: One-shot bounded Frida inspection of a PID. inspect() blocks for
    `seconds` (called from an executor) then detaches and returns the
    collected {api, ip, port, module, path} events plus a per-module tally.
    FR: Inspection Frida bornée d'un PID. inspect() bloque `seconds`
    (appelé depuis un executor) puis se détache et renvoie les événements
    {api, ip, port, module, path} + le décompte par module."""

    def __init__(self):
        self._busy = threading.Lock()

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            import frida  # noqa: F401
            return True, ""
        except ImportError:
            return False, "frida not installed (pip install frida)"

    def inspect(self, pid: int, seconds: int = 20) -> dict:
        """EN: Attach → hook → collect → detach. Never raises; error string
        explains attach failures (permissions, hardened process, gone pid).
        FR: Attach → hook → collecte → détache. Ne lève jamais ; l'erreur
        explique les échecs d'attache."""
        ok, why = self.available()
        if not ok:
            return {"ok": False, "error": why, "events": [], "modules": {}}
        if not self._busy.acquire(blocking=False):
            return {"ok": False, "error": "another inspection is running",
                    "events": [], "modules": {}}
        seconds = max(3, min(int(seconds), _MAX_SECONDS))
        events: list[dict] = []
        try:
            import frida
            try:
                session = frida.attach(pid)
            except Exception as e:                   # noqa: BLE001
                return {"ok": False,
                        "error": f"attach failed: {str(e)[:160]}",
                        "events": [], "modules": {}}
            try:
                script = session.create_script(_JS)
                script.on("message", lambda m, d: self._on_msg(m, events))
                script.load()
                time.sleep(seconds)
            finally:
                try:
                    session.detach()
                except Exception:                    # noqa: BLE001
                    pass
        finally:
            self._busy.release()
        modules: dict[str, int] = {}
        for e in events:
            modules[e["module"]] = modules.get(e["module"], 0) + 1
        return {"ok": True, "pid": pid, "seconds": seconds,
                "events": events[:_MAX_EVENTS], "modules": modules}

    @staticmethod
    def _on_msg(message: dict, out: list) -> None:
        if message.get("type") == "send" and len(out) < _MAX_EVENTS:
            p = message.get("payload") or {}
            if isinstance(p, dict) and p.get("ip"):
                out.append(p)


def suspicious_module_paths(events: list[dict]) -> list[str]:
    """EN: Flag module paths that executable code should never load from —
    temp dirs, user-writable caches, /dev/shm, downloads. These are the
    classic injection/extraction staging spots.
    FR: Signale les chemins de modules d'où du code exécutable ne devrait
    jamais se charger — temp, caches accessibles, /dev/shm, téléchargements."""
    bad_markers = ("\\temp\\", "\\tmp\\", "/tmp/", "/dev/shm/",
                   "\\appdata\\local\\temp", "\\downloads\\",
                   "/downloads/", "\\roaming\\", "/.cache/")
    seen, bad = set(), []
    for e in events:
        path = (e.get("path") or "").lower()
        if path and path not in seen and any(m in path for m in bad_markers):
            seen.add(path)
            bad.append(e["path"])
    return bad
