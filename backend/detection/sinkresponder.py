"""
EN: Sinkhole responder — turns "redirect to 127.0.0.1" from a blind drop
    into a sensor. When Snitch sinkholes a domain/IP, the victim process
    still connects — it just reaches this tiny listener instead of the
    real server. We log what it tried to send:

      * :80  → parse the HTTP request line + Host + path (and the first
               bytes of a POST body — that is the C2 protocol revealing
               itself), answer a minimal 200 so the client keeps talking
               on later requests;
      * :443 → TLS is opaque, but the ClientHello SNI is not: reuse our
               own TLS parser to recover the intended hostname, then
               close. We do NOT MITM TLS — no cert forgery, ever.

    Source-port → PID attribution uses a psutil snapshot at accept time.
    Binding <1024 needs privileges: each listener reports honest
    listening=True/False, and rules keep working even if we can't listen
    (the hosts/DNAT redirect still lands the connection on a refused port).

FR: Répondeur de sinkhole — transforme la redirection vers 127.0.0.1 en
    capteur au lieu d'un trou noir. Quand Snitch sinkhole un domaine/IP,
    le processus victime se connecte quand même — il atteint ce petit
    écouteur à la place du vrai serveur. On journalise ce qu'il tente :

      * :80  → ligne de requête HTTP + Host + chemin (et les premiers
               octets d'un POST — le protocole C2 qui se révèle), réponse
               200 minimale pour que le client continue ;
      * :443 → TLS est opaque, mais le SNI du ClientHello ne l'est pas :
               notre parseur TLS récupère le nom visé, puis on ferme. Pas
               de MITM TLS — jamais de certificat forgé.

    L'attribution port-source → PID utilise un instantané psutil à
    l'accept. Binder <1024 exige des privilèges : chaque écouteur rapporte
    listening honnêtement, et les règles restent actives même sans écoute.
"""

from __future__ import annotations

import socket
import threading
import time

try:                                                 # EN: reuse our own TLS parser
    from capture.parser import parse_tls_sni         # FR: réutilise notre parseur TLS
except ImportError:                                  # pragma: no cover
    from ..capture.parser import parse_tls_sni       # type: ignore

_MAX_HITS = 200
_READ_TIMEOUT = 4.0


def _pid_for_port(port: int) -> tuple[int | None, str | None]:
    """EN: Map a loopback source port to the owning process — one psutil
    snapshot per accepted connection is affordable (sinkholes are rare).
    FR: Mappe un port source loopback vers son processus — un instantané
    psutil par connexion acceptée est abordable."""
    try:
        import psutil
        for c in psutil.net_connections("tcp"):
            if c.laddr and c.laddr.port == port and c.pid:
                try:
                    return c.pid, psutil.Process(c.pid).name()
                except psutil.Error:
                    return c.pid, None
    except Exception:                                # noqa: BLE001
        pass
    return None, None


class SinkholeResponder:
    """EN: Two threaded listeners (80 HTTP / 443 SNI) + a bounded hit ring.
    start()/stop() are idempotent; hits carry {ts, port, host, path,
    process, pid, kind}. / FR: Deux écouteurs threadés (80 HTTP / 443 SNI)
    + anneau de hits borné. start()/stop() idempotents ; les hits portent
    {ts, port, host, path, process, pid, kind}."""

    def __init__(self):
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._hits: list[dict] = []
        self._lock = threading.Lock()
        self._listening: dict[int, bool] = {80: False, 443: False}

    # ── lifecycle / cycle de vie ─────────────────────────────────────────────

    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        for port, handler in ((80, self._handle_http),
                              (443, self._handle_tls)):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                s.listen(16)
                s.settimeout(1.0)
            except OSError:                          # EN: no privilege / FR: pas de privilège
                self._listening[port] = False
                continue
            self._socks.append(s)
            self._listening[port] = True
            t = threading.Thread(target=self._accept_loop,
                                 args=(s, handler), daemon=True,
                                 name=f"snitch-sink-{port}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks.clear()
        self._threads.clear()
        self._listening = {80: False, 443: False}

    def status(self) -> dict:
        with self._lock:
            return {"listening": dict(self._listening),
                    "hits": list(self._hits[-_MAX_HITS:])}

    def pop_hits(self) -> list[dict]:
        """EN: Drain accumulated hits — each reported once as an alert.
        FR: Vider les hits accumulés — chacun rapporté une fois en alerte."""
        with self._lock:
            hits, self._hits = self._hits, []
            return hits

    # ── listeners / écouteurs ────────────────────────────────────────────────

    def _accept_loop(self, sock: socket.socket, handler) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handler, args=(conn, peer),
                             daemon=True).start()

    def _record(self, kind: str, src_port: int, host: str, extra: dict) -> None:
        pid, name = _pid_for_port(src_port)
        with self._lock:
            self._hits.append({"ts": time.time(), "kind": kind,
                               "src_port": src_port, "host": host,
                               "pid": pid, "process": name, **extra})
            if len(self._hits) > _MAX_HITS:
                del self._hits[: len(self._hits) - _MAX_HITS]

    def _handle_http(self, conn: socket.socket, peer) -> None:
        """EN: Read the request, capture Host+path(+body head), answer 200
        so the client proceeds — each request becomes a SINKHOLE_HIT.
        FR: Lit la requête, capture Host+chemin(+tête du corps), répond 200
        pour que le client poursuive — chaque requête devient un hit."""
        try:
            conn.settimeout(_READ_TIMEOUT)
            data = conn.recv(8192)
            head = data.decode("latin-1", "replace")
            first = head.split("\r\n", 1)[0]
            host = next((ln.split(":", 1)[1].strip()
                         for ln in head.split("\r\n")[1:]
                         if ln.lower().startswith("host:")), "")
            parts = first.split()
            method, path = (parts + ["", ""])[:2]
            body = head.split("\r\n\r\n", 1)[1][:160] if "\r\n\r\n" in head else ""
            self._record("http", peer[1], host,
                         {"method": method, "path": path,
                          "body_head": body})
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Connection: close\r\n\r\nOK")
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_tls(self, conn: socket.socket, peer) -> None:
        """EN: Read the ClientHello, recover the SNI with our own parser,
        record it, close. No TLS MITM — we never present a certificate.
        FR: Lit le ClientHello, récupère le SNI via notre parseur,
        l'enregistre, ferme. Pas de MITM TLS — jamais de certificat."""
        try:
            conn.settimeout(_READ_TIMEOUT)
            data = conn.recv(4096)
            sni = parse_tls_sni(data) if data[:2] == b"\x16\x03" else None
            self._record("tls", peer[1], sni or "",
                         {"cipher_attempt": bool(data)})
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
