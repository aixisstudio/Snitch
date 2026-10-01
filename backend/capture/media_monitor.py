"""
Snitch — microphone / camera usage monitor.

EN: Polls the OS to find which processes currently hold the microphone or
    the camera. This powers the MEDIA_EXFIL anomaly rule: an unknown process
    using the mic AND sending traffic out is a red flag.

    - Windows: reads the ConsentStore registry keys. `LastUsedTimeStop == 0`
      means the device is currently in use by that app.
    - Linux: scans each process's open files for /dev/snd* and /dev/video*.

FR: Interroge l'OS pour savoir quels processus utilisent actuellement le
    microphone ou la caméra. Cela alimente la règle d'anomalie MEDIA_EXFIL :
    un processus inconnu qui utilise le micro ET envoie du trafic est un
    signal d'alerte.

    - Windows : lit les clés de registre ConsentStore. `LastUsedTimeStop == 0`
      signifie que l'appareil est actuellement utilisé par cette app.
    - Linux : scanne les fichiers ouverts de chaque processus à la recherche
      de /dev/snd* et /dev/video*.
"""

import sys
import time
import threading
from dataclasses import dataclass, field
from typing import Callable

import psutil


@dataclass
class MediaState:
    """EN: Snapshot of which process names are using mic/camera.
    FR: Instantané des noms de processus utilisant micro/caméra."""
    mic: list[str] = field(default_factory=list)
    camera: list[str] = field(default_factory=list)


def _detect_windows() -> MediaState:
    """
    EN: Read Windows' per-app consent store. Each sub-key under
        `microphone`/`webcam` is an app; `LastUsedTimeStop == 0` means the
        device is open right now.
    FR: Lire le magasin de consentement Windows par app. Chaque sous-clé sous
        `microphone`/`webcam` est une app ; `LastUsedTimeStop == 0` signifie
        que l'appareil est ouvert en ce moment.
    """
    import winreg
    state = MediaState()

    def _read_consent(device: str) -> list[str]:
        procs = []
        key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{device}"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    i += 1
                    if sub == "NonPackaged":
                        # EN: Desktop (non-UWP) apps live under "NonPackaged".
                        # FR: Les apps bureau (non-UWP) sont sous « NonPackaged ».
                        np_key = winreg.OpenKey(key, sub)
                        j = 0
                        while True:
                            try:
                                app = winreg.EnumKey(np_key, j)
                                j += 1
                                app_key = winreg.OpenKey(np_key, app)
                                try:
                                    val, _ = winreg.QueryValueEx(app_key, "LastUsedTimeStop")
                                    if val == 0:
                                        # EN: 0 = device currently in use.
                                        # FR: 0 = appareil en cours d'utilisation.
                                        procs.append(app.split("#")[-1])
                                except FileNotFoundError:
                                    pass
                            except OSError:
                                break
                except OSError:
                    break
        except OSError:
            pass
        return procs

    state.mic = _read_consent("microphone")
    state.camera = _read_consent("webcam")
    return state


def _detect_linux() -> MediaState:
    """
    EN: Heuristic — a process holding /dev/snd* uses audio; /dev/video* means
        camera. Requires read access to other processes' fd lists.
    FR: Heuristique — un processus qui tient /dev/snd* utilise l'audio ;
        /dev/video* signifie caméra. Nécessite l'accès en lecture aux
        descripteurs de fichiers des autres processus.
    """
    state = MediaState()
    try:
        for proc in psutil.process_iter(['name', 'open_files']):
            try:
                files = proc.open_files()
                for f in files:
                    if '/dev/snd' in f.path or '/dev/audio' in f.path:
                        if proc.name() not in state.mic:
                            state.mic.append(proc.name())
                    if '/dev/video' in f.path:
                        if proc.name() not in state.camera:
                            state.camera.append(proc.name())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return state


def detect_media_usage() -> MediaState:
    """EN: Platform dispatch. / FR: Répartition selon la plateforme."""
    if sys.platform == "win32":
        return _detect_windows()
    return _detect_linux()


class MediaMonitor:
    """
    EN: Poll-based watcher. The callback fires only on CHANGE — same state
        twice in a row produces no event.
    FR: Observateur par sondage. Le callback ne se déclenche qu'en cas de
        CHANGEMENT — deux états identiques d'affilée ne produisent rien.
    """

    def __init__(self, callback: Callable[[MediaState], None], interval: int = 3):
        self.callback = callback
        self.interval = interval
        self._running = False
        self._last: MediaState | None = None

    def start(self) -> None:
        """EN: Blocking loop — run inside a daemon thread.
        FR: Boucle bloquante — à lancer dans un thread daemon."""
        self._running = True
        while self._running:
            try:
                state = detect_media_usage()
                if self._last is None or state.mic != self._last.mic or state.camera != self._last.camera:
                    self._last = state
                    self.callback(state)
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self) -> None:
        """EN: Stop the polling loop. / FR: Arrêter la boucle de sondage."""
        self._running = False
