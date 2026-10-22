"""
Snitch — declarative config file (Security-as-Code) / fichier de
configuration déclaratif (Security-as-Code).

EN: Lets admins provision Snitch entirely by file — Ansible, Puppet,
    SaltStack, GPO or a docker-compose bind-mount drop ONE file and the
    backend applies it at startup, no clicks:

      * path resolution — `$SNITCH_CONFIG` first, then
        `data_dir()/snitch.toml`, then `data_dir()/snitch.json`
      * format — TOML (stdlib tomllib, Python ≥3.11) or JSON; the file
        is a FLAT map of the same keys `/settings` accepts
        (`syslog_addr`, `kill_switch_enabled`, `firewall_rules`, …)
      * precedence — the FILE wins for every key it declares (that is
        the point of Security-as-Code: the repo is the source of truth);
        undeclared keys keep whatever the DB/UI last persisted
      * failure honesty — an unreadable or invalid file logs a warning
        and yields {}; Snitch never refuses to start on a typo

    Example::

        # snitch.toml — dropped by Ansible onto every host
        syslog_addr = "siem.corp:514"
        syslog_format = "cef"
        kill_switch_enabled = true
        ask_enabled = false
        ports = [443]
        gossip_peers = ["sec-01.corp:8080"]

FR: Permet de provisionner Snitch entièrement par fichier — Ansible,
    Puppet, GPO ou un bind-mount Docker déposent UN fichier et le backend
    l'applique au démarrage, sans clic. Résolution : `$SNITCH_CONFIG`,
    puis `data_dir()/snitch.toml`, puis `snitch.json`. TOML (stdlib) ou
    JSON, map plate des mêmes clés que `/settings`. Le FICHIER gagne pour
    les clés déclarées — le dépôt est la source de vérité. Un fichier
    invalide log un warning et n'empêche jamais le démarrage.
"""

from __future__ import annotations

import json
import logging
import os
import tomllib
from pathlib import Path

logger = logging.getLogger("snitch.configfile")


def _candidate_paths(data_dir: Path) -> list[Path]:
    """EN: $SNITCH_CONFIG wins, then the conventional names inside the
    data dir. / FR: $SNITCH_CONFIG d'abord, puis les noms usuels."""
    env = os.environ.get("SNITCH_CONFIG", "").strip()
    out = []
    if env:
        out.append(Path(env))
    out += [data_dir / "snitch.toml", data_dir / "snitch.json"]
    return out


def load(data_dir: Path) -> dict:
    """EN: Flat settings dict from the first config file found — {} when
    none exists or the file cannot be parsed. Values pass through
    unchanged (the settings layer already handles arbitrary JSON types).
    FR: Réglages plats du premier fichier trouvé — {} s'il n'y en a pas
    ou si le parsing échoue."""
    for path in _candidate_paths(data_dir):
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
            cfg = (tomllib.loads(raw.decode("utf-8"))
                   if path.suffix.lower() == ".toml"
                   else json.loads(raw.decode("utf-8")))
        except (OSError, tomllib.TOMLDecodeError, json.JSONDecodeError,
                UnicodeDecodeError) as e:
            logger.warning("config file %s unreadable: %s", path, e)
            return {}
        if not isinstance(cfg, dict):
            logger.warning("config file %s is not a mapping — ignored",
                           path)
            return {}
        logger.info("config file loaded: %s (%d keys)", path, len(cfg))
        return cfg
    return {}


def apply(data_dir: Path, set_setting) -> int:
    """EN: Persist each declared key via the normal settings path — the
    file is authoritative for what it names. Returns the applied count.
    FR: Persiste chaque clé déclarée par le chemin normal — le fichier
    fait foi pour ce qu'il nomme. Renvoie le nombre appliqué."""
    cfg = load(data_dir)
    applied = 0
    for key, value in cfg.items():
        try:
            set_setting(str(key), value)
            applied += 1
        except Exception as e:                          # noqa: BLE001
            logger.warning("config key %s rejected: %s", key, e)
    return applied
