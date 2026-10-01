"""
Snitch — SQLite persistence layer.

EN: Two tables:
      - traffic    : per-minute aggregates (packets + bytes by category)
      - alerts_log : every emitted alert, serialized as JSON details
    Writes are cheap: packets only feed an in-memory accumulator that a
    background thread flushes every 10 s. Hourly cleanup keeps the DB to a
    24-hour sliding window.

    DB location resolution order:
      1. SNITCH_DATA_DIR env var (tests, custom deployments)
      2. LOCALAPPDATA\\Snitch      (frozen/Electron builds on Windows)
      3. <repo>/data               (dev / Docker)

FR: Deux tables :
      - traffic    : agrégats par minute (paquets + octets par catégorie)
      - alerts_log : chaque alerte émise, détails sérialisés en JSON
    Les écritures sont légères : les paquets ne font qu'alimenter un
    accumulateur en mémoire qu'un thread d'arrière-plan vide toutes les 10 s.
    Un nettoyage horaire limite la base à une fenêtre glissante de 24 h.

    Ordre de résolution de l'emplacement de la base :
      1. variable SNITCH_DATA_DIR (tests, déploiements personnalisés)
      2. LOCALAPPDATA\\Snitch       (builds figés/Electron sous Windows)
      3. <dépôt>/data               (dev / Docker)
"""

import json
import logging
import os
import sqlite3
import sys
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger("snitch.storage")


def _get_db_path() -> Path:
    """
    EN: Resolve the DB path — see module docstring for the precedence order.
    FR: Résoudre le chemin de la base — voir le docstring du module pour
        l'ordre de priorité.
    """
    env_dir = os.environ.get("SNITCH_DATA_DIR")
    if env_dir:
        db_dir = Path(env_dir)
    elif getattr(sys, 'frozen', False):
        db_dir = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'Snitch'
    else:
        db_dir = Path(__file__).parent.parent.parent / 'data'
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / 'snitch.db'


DB_PATH = _get_db_path()

# EN: Single shared connection guarded by a lock — sqlite3 is not thread-safe
#     by default and we write from several threads.
# FR: Connexion unique partagée protégée par un verrou — sqlite3 n'est pas
#     thread-safe par défaut et nous écrivons depuis plusieurs threads.
_conn: sqlite3.Connection | None = None
_conn_lock = threading.Lock()

# EN: In-memory write accumulator — (minute, category) -> [packets, bytes].
# FR: Accumulateur d'écriture en mémoire — (minute, catégorie) -> [paquets, octets].
_pending: dict[tuple, list] = defaultdict(lambda: [0, 0])
_pending_lock = threading.Lock()


def _utcnow_minute() -> str:
    """EN: Current UTC minute as 'YYYY-MM-DDTHH:MM' (timezone-aware; utcnow()
    is deprecated since Python 3.12). / FR: Minute UTC courante au format
    'YYYY-MM-DDTHH:MM' (conscient du fuseau ; utcnow() est déprécié depuis 3.12)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")


def _utcnow_iso() -> str:
    """EN: Current UTC instant as ISO string. / FR: Instant UTC courant en ISO."""
    return datetime.now(timezone.utc).isoformat()


# ── Connection & schema / Connexion & schéma ─────────────────────────────────

def get_conn() -> sqlite3.Connection:
    """
    EN: Lazily create the shared connection with WAL journaling — better
        concurrent read/write behavior for our single-writer pattern.
    FR: Créer paresseusement la connexion partagée avec journal WAL — meilleur
        comportement lecture/écriture concurrente pour notre schéma à un
        seul rédacteur.
    """
    global _conn
    if _conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _init_schema(_conn)
    return _conn


def _init_schema(conn: sqlite3.Connection) -> None:
    """EN: Create tables + indexes if absent. / FR: Créer tables + index si absentes."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS traffic (
            minute   TEXT NOT NULL,
            category TEXT NOT NULL,
            packets  INTEGER DEFAULT 0,
            bytes    INTEGER DEFAULT 0,
            PRIMARY KEY (minute, category)
        );
        CREATE INDEX IF NOT EXISTS idx_traffic_minute ON traffic(minute);

        CREATE TABLE IF NOT EXISTS alerts_log (
            id       TEXT PRIMARY KEY,
            ts       TEXT NOT NULL,
            type     TEXT,
            severity TEXT,
            message  TEXT,
            node_id  TEXT,
            details  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts_log(ts);
    """)
    conn.commit()


# ── Write helpers / Aides d'écriture ─────────────────────────────────────────

def accumulate(minute: str, category: str, size: int) -> None:
    """
    EN: Fast, lock-minimal accumulator called once per captured packet —
        must never block the packet pipeline on disk I/O.
    FR: Accumulateur rapide à verrou minimal appelé pour chaque paquet capturé —
        ne doit jamais bloquer le pipeline de paquets sur de l'E/S disque.
    """
    with _pending_lock:
        _pending[(minute, category)][0] += 1
        _pending[(minute, category)][1] += size


def flush() -> None:
    """
    EN: Batch-write the accumulator to SQLite using UPSERT semantics.
        Called by the background flush thread every ~10 s.
    FR: Écrire l'accumulateur dans SQLite par lots avec sémantique UPSERT.
        Appelé par le thread de flush toutes les ~10 s.
    """
    with _pending_lock:
        if not _pending:
            return
        batch = dict(_pending)
        _pending.clear()

    rows = [(m, c, v[0], v[1]) for (m, c), v in batch.items()]
    try:
        with _conn_lock:
            conn = get_conn()
            conn.executemany("""
                INSERT INTO traffic (minute, category, packets, bytes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(minute, category) DO UPDATE SET
                    packets = packets + excluded.packets,
                    bytes   = bytes   + excluded.bytes
            """, rows)
            conn.commit()
    except sqlite3.Error as exc:
        logger.error("flush failed: %s", exc)


def log_alert(alert: dict) -> None:
    """
    EN: Persist one alert. INSERT OR IGNORE makes retries idempotent on the
        UUID primary key.
    FR: Persister une alerte. INSERT OR IGNORE rend les réessais idempotents
        grâce à la clé primaire UUID.
    """
    try:
        with _conn_lock:
            conn = get_conn()
            conn.execute("""
                INSERT OR IGNORE INTO alerts_log (id, ts, type, severity, message, node_id, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["id"], alert["timestamp"], alert["type"],
                alert["severity"], alert["message"],
                alert.get("node_id"), json.dumps(alert.get("details", {})),
            ))
            conn.commit()
    except sqlite3.Error as exc:
        logger.error("log_alert failed: %s", exc)


# ── Read helpers / Aides de lecture ──────────────────────────────────────────

def get_timeline(minutes: int = 60) -> list[dict]:
    """
    EN: Per-minute packet/byte totals plus the number of alerts per minute —
        exactly what the frontend timeline chart draws.
    FR: Totaux de paquets/octets par minute plus le nombre d'alertes par
        minute — exactement ce que dessine le graphique timeline du frontend.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M")

    with _conn_lock:
        conn = get_conn()
        traffic_rows = conn.execute("""
            SELECT minute, SUM(packets), SUM(bytes)
            FROM traffic
            WHERE minute >= ?
            GROUP BY minute
            ORDER BY minute ASC
        """, (cutoff,)).fetchall()

        alert_rows = conn.execute("""
            SELECT substr(ts, 1, 16) AS minute, COUNT(*) AS cnt
            FROM alerts_log
            WHERE ts >= ?
            GROUP BY minute
        """, (cutoff,)).fetchall()

    alert_map = {r[0]: r[1] for r in alert_rows}

    return [
        {
            "minute":  r[0],
            "packets": r[1],
            "bytes":   r[2],
            "alerts":  alert_map.get(r[0], 0),
        }
        for r in traffic_rows
    ]


def cleanup_old_data(hours: int = 24) -> None:
    """
    EN: Delete rows older than `hours` — keeps the DB bounded since the UI
        only ever displays a sliding window.
    FR: Supprimer les lignes de plus de `hours` heures — borne la taille de la
        base puisque l'UI n'affiche qu'une fenêtre glissante.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M")
    try:
        with _conn_lock:
            conn = get_conn()
            conn.execute("DELETE FROM traffic WHERE minute < ?", (cutoff,))
            conn.execute("DELETE FROM alerts_log WHERE ts < ?", (cutoff,))
            conn.commit()
    except sqlite3.Error as exc:
        logger.error("cleanup failed: %s", exc)
