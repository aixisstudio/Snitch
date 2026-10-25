"""EN: Windows-safe subprocess helpers.

    Console tools spawned from the windowed (non-console) backend each
    flash a transient console window on Windows unless told otherwise —
    e.g. the 60 s Wi-Fi-SSID poll via ``netsh`` produced a visible popup
    storm (issue #62). Every backend subprocess call must funnel through
    ``spawn_kwargs()`` so console children stay invisible.

FR: Helpers subprocess sûrs sous Windows.

    Les outils console lancés depuis le backend fenêtré font clignoter une
    fenêtre console à chaque appel sauf indication contraire — ex. le
    sondage SSID Wi-Fi via ``netsh`` toutes les 60 s produisait une rafale
    de popups (issue #62). Tout appel subprocess du backend doit passer
    par ``spawn_kwargs()`` pour que les enfants restent invisibles.
"""
import subprocess
import sys

__all__ = ["spawn_kwargs"]


def spawn_kwargs() -> dict:
    """EN: Extra kwargs for subprocess.run/Popen hiding the child console
        on Windows; empty dict elsewhere so call sites stay portable.
    FR: kwargs supplémentaires pour subprocess.run/Popen cachant la console
        enfant sous Windows ; dict vide ailleurs pour rester portable."""
    if sys.platform != "win32":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": si,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
    }
