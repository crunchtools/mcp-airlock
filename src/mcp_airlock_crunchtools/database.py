"""SQLite blocklist database for mcp-airlock-crunchtools.

Write access is deterministic code ONLY. The Q-Agent cannot write to this database.
The Q-Agent's detection output is returned as structured JSON, parsed by the server's
deterministic code, which decides whether to record a detection.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .config import get_config

_db: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source TEXT NOT NULL,
    domain TEXT,
    detected_at TEXT NOT NULL,
    layer1_stats TEXT NOT NULL,
    qagent_assessment TEXT,
    risk_level TEXT NOT NULL,
    blocked BOOLEAN DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_detections_domain ON detections(domain);
CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source);
"""


def get_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the singleton database connection."""
    global _db
    if _db is None:
        path = db_path or get_config().db_path
        get_config().ensure_db_dir()
        _db = sqlite3.connect(path)
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA foreign_keys=ON")
        _db.executescript(SCHEMA)
    return _db


def is_blocked(source: str) -> dict[str, Any] | None:
    """Check if a source is in the blocklist. Returns detection details or None."""
    db = get_db()
    cursor = db.execute(
        "SELECT * FROM detections WHERE source = ? AND blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 1",
        (source,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def is_domain_blocked(domain: str) -> dict[str, Any] | None:
    """Check if any URL from a domain is in the blocklist."""
    db = get_db()
    cursor = db.execute(
        "SELECT * FROM detections WHERE domain = ? AND blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 1",
        (domain,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def record_detection(
    source_type: str,
    source: str,
    domain: str | None,
    layer1_stats: dict[str, Any],
    risk_level: str,
    qagent_assessment: dict[str, Any] | None = None,
) -> int:
    """Record a detection in the blocklist. Returns the detection ID."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO detections (source_type, source, domain, detected_at, "
        "layer1_stats, qagent_assessment, risk_level, blocked) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        (
            source_type,
            source,
            domain,
            now,
            json.dumps(layer1_stats),
            json.dumps(qagent_assessment) if qagent_assessment else None,
            risk_level,
        ),
    )
    db.commit()
    return cursor.lastrowid or 0


def get_blocklist_stats() -> dict[str, Any]:
    """Get summary statistics for the blocklist."""
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) as cnt FROM detections WHERE blocked = 1"
    ).fetchone()
    recent = db.execute(
        "SELECT source_type, source, domain, detected_at, risk_level "
        "FROM detections WHERE blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 10"
    ).fetchall()

    by_risk = db.execute(
        "SELECT risk_level, COUNT(*) as cnt FROM detections "
        "WHERE blocked = 1 GROUP BY risk_level"
    ).fetchall()

    return {
        "total_blocked": total["cnt"] if total else 0,
        "by_risk_level": {row["risk_level"]: row["cnt"] for row in by_risk},
        "recent_detections": [dict(row) for row in recent],
    }
