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
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from paths import data_dir

logger = logging.getLogger("snitch.storage")

DB_PATH = data_dir() / 'snitch.db'

# EN: Single shared connection guarded by a lock — sqlite3 is not thread-safe
#     by default and we write from several threads.
# FR: Connexion unique partagée protégée par un verrou — sqlite3 n'est pas
#     thread-safe par défaut et nous écrivons depuis plusieurs threads.
_conn: sqlite3.Connection | None = None
_conn_lock = threading.Lock()

# EN: In-memory write accumulator — (minute, category) -> [packets, bytes].
# FR: Accumulateur d'écriture en mémoire — (minute, catégorie) -> [paquets, octets].
_pending: dict[tuple, list] = defaultdict(lambda: [0, 0])
_pending_hist: dict[tuple, list] = defaultdict(lambda: [0, 0])
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

        -- EN: Persisted settings (filters, whitelist, language, thresholds…).
        --     Values are JSON; the API loads them at startup.
        -- FR: Réglages persistés (filtres, whitelist, langue, seuils…).
        --     Valeurs en JSON ; l'API les charge au démarrage.
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- EN: Per-host and per-process byte/packet history, per minute.
        --     dim is 'host' or 'process'; key is the IP or process name.
        -- FR: Historique par hôte et par processus, en octets/paquets par
        --     minute. dim vaut 'host' ou 'process' ; key est l'IP ou le nom
        --     de processus.
        CREATE TABLE IF NOT EXISTS history (
            minute  TEXT NOT NULL,
            dim     TEXT NOT NULL,
            key     TEXT NOT NULL,
            packets INTEGER DEFAULT 0,
            bytes   INTEGER DEFAULT 0,
            PRIMARY KEY (minute, dim, key)
        );
        CREATE INDEX IF NOT EXISTS idx_history_lookup ON history(dim, key, minute);

        -- EN: Remembered LAN devices. Identities learned passively (mDNS,
        --     DHCP, NBNS, LLMNR, OUI) persist across restarts — a device once
        --     named never falls back to a bare IP again. NULL-safe upserts
        --     keep the best-known value for every field.
        -- FR: Appareils LAN mémorisés. Les identités apprises passivement
        --     (mDNS, DHCP, NBNS, LLMNR, OUI) survivent aux redémarrages —
        --     un appareil nommé une fois ne retombe jamais sur une IP nue.
        --     Les upserts NULL-safe gardent la meilleure valeur de chaque
        --     champ.
        CREATE TABLE IF NOT EXISTS devices (
            ip          TEXT PRIMARY KEY,
            mac         TEXT,
            vendor      TEXT,
            device_type TEXT,
            hostname    TEXT,
            private_mac INTEGER DEFAULT 0,
            first_seen  TEXT,
            last_seen   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
    """)
    conn.commit()


# ── Settings / Réglages ──────────────────────────────────────────────────────

def get_setting(key: str, default=None):
    """EN: Read one persisted setting (JSON-decoded). / FR: Lire un réglage persisté (décodé JSON)."""
    with _conn_lock:
        row = get_conn().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return default


def set_setting(key: str, value) -> None:
    """EN: Persist one setting as JSON. / FR: Persister un réglage en JSON."""
    with _conn_lock:
        conn = get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, json.dumps(value)))
        conn.commit()


def all_settings() -> dict:
    """EN: All persisted settings as a dict. / FR: Tous les réglages persistés en dict."""
    with _conn_lock:
        rows = get_conn().execute("SELECT key, value FROM settings").fetchall()
    out = {}
    for k, v in rows:
        try:
            out[k] = json.loads(v)
        except (json.JSONDecodeError, TypeError):
            pass
    return out


# ── Remembered devices / Appareils mémorisés ─────────────────────────────────

def upsert_device(ip: str, mac: Optional[str] = None,
                  vendor: Optional[str] = None,
                  device_type: Optional[str] = None,
                  hostname: Optional[str] = None,
                  private_mac: Optional[bool] = None) -> None:
    """
    EN: Persist the best-known identity of a LAN device. NULL/empty fields
        never overwrite stored knowledge — a scan can only ENRICH a row.
        Called on ARP discovery and each passive name learning.
    FR: Persister la meilleure identité connue d'un appareil LAN. Les champs
        NULL/vides n'écrasent jamais un savoir stocké — un scan ne peut
        qu'ENRICHIR une ligne. Appelé à la découverte ARP et à chaque
        apprentissage passif de nom.
    """
    now = _utcnow_iso()
    try:
        with _conn_lock:
            conn = get_conn()
            conn.execute("""
                INSERT INTO devices (ip, mac, vendor, device_type, hostname,
                                     private_mac, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac         = COALESCE(excluded.mac, devices.mac),
                    vendor      = COALESCE(NULLIF(excluded.vendor, ''),
                                           devices.vendor),
                    device_type = COALESCE(NULLIF(excluded.device_type, ''),
                                           devices.device_type),
                    hostname    = COALESCE(NULLIF(excluded.hostname, ''),
                                           devices.hostname),
                    private_mac = COALESCE(excluded.private_mac,
                                           devices.private_mac),
                    last_seen   = excluded.last_seen
            """, (ip, mac, vendor, device_type, hostname,
                  None if private_mac is None else int(private_mac),
                  now, now))
            conn.commit()
    except sqlite3.Error as exc:
        logger.error("upsert_device(%s) failed: %s", ip, exc)


def device_identity(ip: str, mac: Optional[str] = None) -> dict:
    """
    EN: Recall a stored identity for a device. MAC match wins (DHCP can
        reassign IPs to OTHER devices — an IP-only name could misname a
        newcomer); the IP row is only trusted when its MAC agrees or is
        unknown.
    FR: Rappeler l'identité stockée d'un appareil. La correspondance MAC
        gagne (le DHCP peut réassigner une IP à un AUTRE appareil — un nom
        par IP seule pourrait mal nommer un nouvel arrivant) ; la ligne IP
        n'est crédible que si sa MAC concorde ou est inconnue.
    """
    def _merge(best: dict, row: tuple) -> dict:
        r_mac, vendor, dtype, hostname, priv = row
        if r_mac and not best.get("mac"):
            best["mac"] = r_mac
        for key, val in (("vendor", vendor), ("device_type", dtype),
                         ("hostname", hostname)):
            if val and key not in best:
                best[key] = val
        if priv is not None and "private_mac" not in best:
            best["private_mac"] = bool(priv)
        return best

    with _conn_lock:
        conn = get_conn()
        best: dict = {}
        if mac:
            row = conn.execute(
                "SELECT mac, vendor, device_type, hostname, private_mac "
                "FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row:
                _merge(best, row)
        row = conn.execute(
            "SELECT mac, vendor, device_type, hostname, private_mac "
            "FROM devices WHERE ip = ?", (ip,)).fetchone()
        # EN: The IP-keyed row is trusted only when its stored MAC agrees
        #     with the device in front of us (or is unknown) — DHCP reassigns
        #     IPs, a stale IP→name binding would misname the newcomer.
        # FR: La ligne indexée par IP n'est fiable que si sa MAC stockée
        #     concorde avec l'appareil en face de nous (ou est inconnue) —
        #     le DHCP réassigne les IP, une liaison IP→nom périmée
        #     nommerait mal le nouvel arrivant.
        if row and (not mac or not row[0] or row[0] == mac):
            _merge(best, row)
    return best


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


def accumulate_history(minute: str, dim: str, key: str, size: int) -> None:
    """
    EN: Same zero-block pattern as accumulate(), but into the per-entity
        `history` table — one call per (remote host, owning process) pair.
    FR: Même schéma non-bloquant qu'accumulate(), vers la table `history` —
        un appel par couple (hôte distant, processus).
    """
    with _pending_lock:
        _pending_hist[(minute, dim, key)][0] += 1
        _pending_hist[(minute, dim, key)][1] += size


def flush() -> None:
    """
    EN: Batch-write the accumulator to SQLite using UPSERT semantics.
        Called by the background flush thread every ~10 s.
    FR: Écrire l'accumulateur dans SQLite par lots avec sémantique UPSERT.
        Appelé par le thread de flush toutes les ~10 s.
    """
    with _pending_lock:
        if not _pending and not _pending_hist:
            return
        batch = dict(_pending)
        _pending.clear()
        hist_batch = dict(_pending_hist)
        _pending_hist.clear()

    rows = [(m, c, v[0], v[1]) for (m, c), v in batch.items()]
    hist_rows = [(m, d, k, v[0], v[1]) for (m, d, k), v in hist_batch.items()]
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
            conn.executemany("""
                INSERT INTO history (minute, dim, key, packets, bytes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(minute, dim, key) DO UPDATE SET
                    packets = packets + excluded.packets,
                    bytes   = bytes   + excluded.bytes
            """, hist_rows)
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


def get_history(dim: str, key: str, minutes: int = 60) -> list[dict]:
    """
    EN: Per-entity history — bytes/packets per minute for one host or process.
        Used by the per-application view and node detail panel.
    FR: Historique par entité — octets/paquets par minute pour un hôte ou un
        processus. Utilisé par la vue par application et le panneau de détail.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M")
    with _conn_lock:
        rows = get_conn().execute("""
            SELECT minute, packets, bytes FROM history
            WHERE dim = ? AND key = ? AND minute >= ?
            ORDER BY minute ASC
        """, (dim, key, cutoff)).fetchall()
    return [{"minute": r[0], "packets": r[1], "bytes": r[2]} for r in rows]


def get_top_processes(minutes: int = 60, limit: int = 50) -> list[dict]:
    """
    EN: Top talkers by process over the window — feeds the Apps view.
    FR: Plus gros émetteurs par processus sur la fenêtre — alimente la vue Apps.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M")
    with _conn_lock:
        rows = get_conn().execute("""
            SELECT key, SUM(packets), SUM(bytes) FROM history
            WHERE dim = 'process' AND minute >= ?
            GROUP BY key ORDER BY SUM(bytes) DESC LIMIT ?
        """, (cutoff, limit)).fetchall()
    return [{"process": r[0], "packets": r[1], "bytes": r[2]} for r in rows]


def get_alerts(limit: int = 100) -> list[dict]:
    """
    EN: Most recent persisted alerts, newest first — the /alerts endpoint now
        survives restarts instead of serving only the in-memory tail.
    FR: Alertes persistées les plus récentes, plus récentes d'abord — le
        endpoint /alerts survit désormais aux redémarrages au lieu de servir
        seulement la queue en mémoire.
    """
    with _conn_lock:
        rows = get_conn().execute("""
            SELECT id, ts, type, severity, message, node_id, details
            FROM alerts_log ORDER BY ts DESC LIMIT ?
        """, (limit,)).fetchall()
    out = []
    for r in rows:
        try:
            details = json.loads(r[6] or "{}")
        except json.JSONDecodeError:
            details = {}
        out.append({
            "id": r[0], "timestamp": r[1], "type": r[2], "severity": r[3],
            "message": r[4], "node_id": r[5], "details": details,
        })
    return out


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
            conn.execute("DELETE FROM history WHERE minute < ?", (cutoff,))
            conn.commit()
    except sqlite3.Error as exc:
        logger.error("cleanup failed: %s", exc)
