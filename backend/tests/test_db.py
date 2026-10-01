"""
Snitch — SQLite persistence tests.

EN: Uses an isolated SNITCH_DATA_DIR (set in conftest.py) so the real
    snitch.db is never touched. Covers accumulate→flush→timeline and alert
    logging.
FR: Utilise un SNITCH_DATA_DIR isolé (posé dans conftest.py) pour ne jamais
    toucher la vraie snitch.db. Couvre accumulate→flush→timeline et le
    journal d'alertes.
"""

import uuid
from datetime import datetime, timezone

import storage.db as db


def test_accumulate_flush_timeline_roundtrip():
    # EN: get_timeline filters on a sliding window — use the CURRENT minute.
    # FR: get_timeline filtre sur une fenêtre glissante — utiliser la minute COURANTE.
    minute = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    db.accumulate(minute, "safe", 500)
    db.accumulate(minute, "safe", 700)
    db.accumulate(minute, "tracking", 100)
    db.flush()

    rows = [r for r in db.get_timeline(minutes=99999) if r["minute"] == minute]
    assert len(rows) == 1
    assert rows[0]["packets"] == 2 + 1
    assert rows[0]["bytes"] == 1300


def test_log_alert_persists():
    alert = {
        "id": str(uuid.uuid4()),
        "timestamp": "2024-06-01T12:00:00+00:00",
        "type": "NEW_HOST",
        "severity": "info",
        "message": "test",
        "node_id": "1.2.3.4",
        "details": {"ip": "1.2.3.4"},
    }
    db.log_alert(alert)
    # EN: Second insert of the same id must be a no-op (INSERT OR IGNORE).
    # FR: Une seconde insertion du même id doit être un no-op (INSERT OR IGNORE).
    db.log_alert(alert)

    with db._conn_lock:
        rows = db.get_conn().execute(
            "SELECT COUNT(*) FROM alerts_log WHERE id = ?", (alert["id"],)
        ).fetchone()
    assert rows[0] == 1


def test_cleanup_deletes_old_rows():
    db.accumulate("2000-01-01T00:00", "safe", 1)
    db.flush()
    db.cleanup_old_data(hours=24)
    rows = [r for r in db.get_timeline(minutes=99999999) if r["minute"] == "2000-01-01T00:00"]
    assert rows == []
