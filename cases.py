"""
FORENSTIX 2.0 — Case Management (SQLite)

Provides a lightweight persistent store for investigations:
  Case       — top-level investigation container (name, description, status)
  CaseFile   — file analysed within a case
  CaseIOC    — IOC extracted from a file (linked to case and file)
  PivotResult — result of running a tool against a CaseIOC
  Note       — analyst annotations on a case

All writes are thread-safe; reads use Row factory for dict-like access.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import datetime
from typing import Any, Dict, List, Optional

_DB_PATH = os.environ.get("FORENSTIX_DB", "forenstix.db")
_lock = threading.Lock()


# ─── Schema ───────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    status      TEXT    DEFAULT 'open',    -- open | closed | archived
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS case_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename    TEXT    NOT NULL,
    analysis    TEXT    NOT NULL,          -- JSON blob of analyze_file() result
    risk_label  TEXT    NOT NULL,
    risk_score  INTEGER NOT NULL,
    added_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS case_iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    file_id     INTEGER REFERENCES case_files(id) ON DELETE SET NULL,
    ioc_type    TEXT    NOT NULL,          -- domain | url | email | ip | hash | username
    value       TEXT    NOT NULL,
    context     TEXT    DEFAULT '',        -- extra context (rule name, field, etc.)
    added_at    TEXT    NOT NULL,
    UNIQUE (case_id, ioc_type, value)
);

CREATE TABLE IF NOT EXISTS pivot_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id      INTEGER NOT NULL REFERENCES case_iocs(id) ON DELETE CASCADE,
    tool_id     TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL,
    result      TEXT    NOT NULL,          -- JSON blob of run_tool() result
    ran_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    content     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_files_case ON case_files(case_id);
CREATE INDEX IF NOT EXISTS idx_iocs_case       ON case_iocs(case_id);
CREATE INDEX IF NOT EXISTS idx_iocs_value      ON case_iocs(value);
CREATE INDEX IF NOT EXISTS idx_pivot_ioc       ON pivot_results(ioc_id);
"""


# ─── Connection management ────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _init_db() -> None:
    with _lock:
        conn = _connect()
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()


_init_db()


def _now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict]:
    return dict(row) if row else None


# ─── Cases ────────────────────────────────────────────────────────────────

def create_case(name: str, description: str = "") -> Dict:
    now = _now()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "INSERT INTO cases (name, description, status, created_at, updated_at) "
                "VALUES (?, ?, 'open', ?, ?)",
                (name, description, now, now),
            )
            conn.commit()
            case_id = cur.lastrowid
        finally:
            conn.close()
    return get_case(case_id)


def get_case(case_id: int) -> Optional[Dict]:
    conn = _connect()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    return _row_to_dict(row)


def list_cases(status: Optional[str] = None) -> List[Dict]:
    conn = _connect()
    if status:
        rows = conn.execute(
            "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_case(case_id: int, **kwargs) -> Optional[Dict]:
    # Hardcoded column map — never interpolate user-supplied key names into SQL
    _UPDATABLE = {"name": "name", "description": "description", "status": "status"}
    updates: Dict[str, Any] = {}
    for field, col in _UPDATABLE.items():
        if field in kwargs:
            updates[col] = kwargs[field]
    if not updates:
        return get_case(case_id)
    updates["updated_at"] = _now()
    # Build SET clause from the fixed column names above (never from user input)
    set_clause = ", ".join(f"{col} = ?" for col in updates)
    vals = list(updates.values()) + [case_id]
    with _lock:
        conn = _connect()
        conn.execute(f"UPDATE cases SET {set_clause} WHERE id = ?", vals)
        conn.commit()
        conn.close()
    return get_case(case_id)


def delete_case(case_id: int) -> bool:
    with _lock:
        conn = _connect()
        cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        conn.commit()
        conn.close()
    return cur.rowcount > 0


# ─── Case Files ───────────────────────────────────────────────────────────

def add_file_to_case(case_id: int, analysis: Dict) -> Dict:
    """Persist an analyze_file() result and auto-extract IOCs."""
    meta = analysis.get("metadata", {})
    risk = analysis.get("risk_score", {})
    now = _now()
    with _lock:
        conn = _connect()
        cur = conn.execute(
            "INSERT INTO case_files (case_id, filename, analysis, risk_label, risk_score, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                case_id,
                meta.get("filename", "unknown"),
                json.dumps(analysis, default=str),
                risk.get("label", "UNKNOWN"),
                risk.get("score", 0),
                now,
            ),
        )
        file_id = cur.lastrowid
        # Auto-extract IOCs
        ns = meta.get("notable_strings") or {}
        _bulk_add_iocs(conn, case_id, file_id, ns)
        # Also add hashes as IOCs
        hashes = analysis.get("hashes", {})
        for hash_val in hashes.values():
            if hash_val:
                _safe_insert_ioc(conn, case_id, file_id, "hash", hash_val, "file_hash")
        conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
        conn.commit()
        row = conn.execute("SELECT * FROM case_files WHERE id = ?", (file_id,)).fetchone()
        conn.close()
    result = dict(row)
    result["analysis"] = json.loads(result["analysis"])
    return result


def _bulk_add_iocs(conn, case_id, file_id, ns):
    type_map = {
        "urls": "url",
        "emails": "email",
        "ip_addresses": "ip",
        "domains": "domain",
        "hashes_sha256": "hash",
        "hashes_sha1": "hash",
        "hashes_md5": "hash",
    }
    for field, ioc_type in type_map.items():
        for val in (ns.get(field) or []):
            _safe_insert_ioc(conn, case_id, file_id, ioc_type, val)


def _safe_insert_ioc(conn, case_id, file_id, ioc_type, value, context=""):
    try:
        conn.execute(
            "INSERT OR IGNORE INTO case_iocs (case_id, file_id, ioc_type, value, context, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, file_id, ioc_type, value, context, _now()),
        )
    except sqlite3.IntegrityError:
        pass


def list_case_files(case_id: int) -> List[Dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT id, case_id, filename, risk_label, risk_score, added_at "
        "FROM case_files WHERE case_id = ? ORDER BY added_at DESC",
        (case_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_case_file(file_id: int) -> Optional[Dict]:
    conn = _connect()
    row = conn.execute("SELECT * FROM case_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    result["analysis"] = json.loads(result["analysis"])
    return result


# ─── IOCs ─────────────────────────────────────────────────────────────────

def add_ioc(case_id: int, ioc_type: str, value: str,
            file_id: Optional[int] = None, context: str = "") -> Optional[Dict]:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO case_iocs "
                "(case_id, file_id, ioc_type, value, context, added_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, file_id, ioc_type, value, context, _now()),
            )
            conn.commit()
            ioc_id = cur.lastrowid
        finally:
            conn.close()
    if not ioc_id:
        return None
    return get_ioc(ioc_id)


def get_ioc(ioc_id: int) -> Optional[Dict]:
    conn = _connect()
    row = conn.execute("SELECT * FROM case_iocs WHERE id = ?", (ioc_id,)).fetchone()
    conn.close()
    return _row_to_dict(row)


def list_case_iocs(case_id: int, ioc_type: Optional[str] = None) -> List[Dict]:
    conn = _connect()
    if ioc_type:
        rows = conn.execute(
            "SELECT * FROM case_iocs WHERE case_id = ? AND ioc_type = ? ORDER BY added_at",
            (case_id, ioc_type),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM case_iocs WHERE case_id = ? ORDER BY ioc_type, added_at",
            (case_id,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Pivot Results ────────────────────────────────────────────────────────

def save_pivot_result(ioc_id: int, tool_id: str, tool_name: str,
                      result: Dict) -> Dict:
    now = _now()
    with _lock:
        conn = _connect()
        cur = conn.execute(
            "INSERT INTO pivot_results (ioc_id, tool_id, tool_name, result, ran_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (ioc_id, tool_id, tool_name, json.dumps(result, default=str), now),
        )
        row_id = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM pivot_results WHERE id = ?", (row_id,)).fetchone()
        conn.close()
    result_row = dict(row)
    result_row["result"] = json.loads(result_row["result"])
    return result_row


def list_ioc_pivot_results(ioc_id: int) -> List[Dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM pivot_results WHERE ioc_id = ? ORDER BY ran_at DESC",
        (ioc_id,),
    ).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["result"] = json.loads(d["result"])
        results.append(d)
    return results


# ─── Notes ────────────────────────────────────────────────────────────────

def add_note(case_id: int, content: str) -> Dict:
    now = _now()
    with _lock:
        conn = _connect()
        cur = conn.execute(
            "INSERT INTO notes (case_id, content, created_at) VALUES (?, ?, ?)",
            (case_id, content, now),
        )
        row_id = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (row_id,)).fetchone()
        conn.close()
    return dict(row)


def list_case_notes(case_id: int) -> List[Dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM notes WHERE case_id = ? ORDER BY created_at", (case_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Timeline ─────────────────────────────────────────────────────────────

def get_case_timeline(case_id: int) -> List[Dict]:
    """Merged chronological timeline of all events in a case."""
    conn = _connect()
    events = []

    for row in conn.execute(
        "SELECT added_at as ts, 'file_added' as kind, filename as label FROM case_files "
        "WHERE case_id = ?", (case_id,)
    ).fetchall():
        events.append(dict(row))

    for row in conn.execute(
        "SELECT added_at as ts, 'ioc_extracted' as kind, "
        "ioc_type || ': ' || value as label FROM case_iocs WHERE case_id = ?",
        (case_id,),
    ).fetchall():
        events.append(dict(row))

    for row in conn.execute(
        "SELECT pr.ran_at as ts, 'pivot_run' as kind, "
        "pr.tool_name || ' on ' || ci.value as label "
        "FROM pivot_results pr JOIN case_iocs ci ON pr.ioc_id = ci.id "
        "WHERE ci.case_id = ?",
        (case_id,),
    ).fetchall():
        events.append(dict(row))

    for row in conn.execute(
        "SELECT created_at as ts, 'note_added' as kind, "
        "substr(content, 1, 80) as label FROM notes WHERE case_id = ?",
        (case_id,),
    ).fetchall():
        events.append(dict(row))

    conn.close()
    events.sort(key=lambda e: e.get("ts", ""))
    return events


# ─── Stats ────────────────────────────────────────────────────────────────

def get_case_stats(case_id: int) -> Dict:
    conn = _connect()
    files = conn.execute(
        "SELECT COUNT(*) FROM case_files WHERE case_id = ?", (case_id,)
    ).fetchone()[0]
    iocs = conn.execute(
        "SELECT ioc_type, COUNT(*) as cnt FROM case_iocs WHERE case_id = ? GROUP BY ioc_type",
        (case_id,),
    ).fetchall()
    pivots = conn.execute(
        "SELECT COUNT(*) FROM pivot_results pr JOIN case_iocs ci ON pr.ioc_id = ci.id "
        "WHERE ci.case_id = ?",
        (case_id,),
    ).fetchone()[0]
    notes = conn.execute(
        "SELECT COUNT(*) FROM notes WHERE case_id = ?", (case_id,)
    ).fetchone()[0]
    conn.close()
    return {
        "files": files,
        "iocs": {r["ioc_type"]: r["cnt"] for r in iocs},
        "pivots_run": pivots,
        "notes": notes,
    }
