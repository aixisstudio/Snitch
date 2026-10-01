"""
Snitch — command-line entry point (`snitch`).

EN: Starts the local API + bundled web UI on a free loopback port, prints the
    token URL once, and opens the browser. Runs headless in --no-browser mode
    (e.g. remote/Docker use).

    Capture privileges are still required:
      - Windows : run the terminal as Administrator (Npcap installed)
      - Linux   : root, or `sudo setcap cap_net_raw,cap_net_admin` on the binary
      - macOS   : read access to /dev/bpf*

    Usage:  snitch [--port N] [--bind 127.0.0.1] [--no-browser]

FR: Point d'entrée en ligne de commande (`snitch`).

    Lance l'API locale + l'UI web embarquée sur un port loopback libre, affiche
    l'URL avec jeton une fois, et ouvre le navigateur. Mode --no-browser pour
    usage sans interface graphique (ex. distant/Docker).

    Les privilèges de capture restent requis :
      - Windows : terminal Administrateur (Npcap installé)
      - Linux   : root, ou `sudo setcap cap_net_raw,cap_net_admin` sur le binaire
      - macOS   : accès en lecture aux /dev/bpf*

    Usage :  snitch [--port N] [--bind 127.0.0.1] [--no-browser]
"""

import argparse
import logging
import os
import socket
import sys
import threading
import webbrowser


def _free_port() -> int:
    """EN: Grab a free loopback port. / FR: Prendre un port loopback libre."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    """EN: CLI entry — parse args, boot uvicorn, open the browser.
    FR: Entrée CLI — parser les args, démarrer uvicorn, ouvrir le navigateur."""
    ap = argparse.ArgumentParser(
        prog="snitch",
        description="Snitch — real-time network traffic visualizer / "
                    "visualiseur de trafic réseau en temps réel")
    ap.add_argument("--port", type=int, default=0,
                    help="port to bind (0 = pick a free one) / "
                         "port d'écoute (0 = choisir un port libre)")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="bind address — keep 127.0.0.1 unless you know why / "
                         "adresse d'écoute — garder 127.0.0.1 sauf raison explicite")
    ap.add_argument("--no-browser", action="store_true",
                    help="don't open the browser / ne pas ouvrir le navigateur")
    args = ap.parse_args()

    # EN: Ensure backend/ is importable when running from a wheel install.
    # FR: Garantir que backend/ est importable en installation wheel.
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    if pkg_dir not in sys.path:
        sys.path.insert(0, pkg_dir)

    os.environ["SNITCH_USER_DATA"] = "1"   # EN: per-OS data dir, not repo/data
                                         # FR: dossier de données par OS

    from logging_config import setup_logging
    setup_logging(logging.INFO)

    port = args.port or _free_port()
    os.environ["SNITCH_PORT"] = str(port)
    os.environ["SNITCH_BIND"] = args.bind

    from api.main import app           # noqa: E402
    from api.security import get_token  # noqa: E402
    import uvicorn                      # noqa: E402

    token = get_token()
    url = f"http://127.0.0.1:{port}/?token={token}"
    print(f"\n  Snitch is running / Snitch tourne :\n\n    {url}\n")
    print("  Keep this terminal open. Ctrl+C to stop. / "
          "Gardez ce terminal ouvert. Ctrl+C pour arrêter.\n")

    if not args.no_browser:
        # EN: Open after a short delay so uvicorn is listening first.
        # FR: Ouvrir après un court délai pour qu'uvicorn écoute d'abord.
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=args.bind, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
