import sqlite3
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = Path(__file__).parent / "hackeragent.db"

_local = threading.local()

def get_db():
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA foreign_keys = ON;")
    return _local.conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT,
            target TEXT,
            project_type TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            project_id TEXT,
            model TEXT,
            saved_at TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            role TEXT,
            content TEXT,
            timestamp TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            type TEXT,
            content_json TEXT,
            timestamp TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_cache (
            cmd_key TEXT PRIMARY KEY,
            project_id TEXT,
            stdout TEXT,
            stderr TEXT,
            code INTEGER,
            ts REAL,
            cached_at TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            severity TEXT,
            type TEXT,
            value TEXT,
            description TEXT,
            source TEXT,
            raw_json TEXT,
            timestamp TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            domain TEXT,
            UNIQUE(project_id, domain),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
    """)
    conn.commit()

init_db()

# --- Projects ---
def upsert_project(project_id: str, name: str, target: str, project_type: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO projects (id, name, target, project_type, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            target=excluded.target,
            project_type=excluded.project_type,
            updated_at=excluded.updated_at
    """, (project_id, name, target, project_type, datetime.now().isoformat()))
    conn.commit()

def delete_project(project_id: str):
    conn = get_db()
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()

def get_project(project_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    return dict(row) if row else None

def get_all_projects() -> List[Dict[str, Any]]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()
    return [dict(r) for r in rows]

def update_project_timestamp(project_id: str):
    conn = get_db()
    conn.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (datetime.now().isoformat(), project_id))
    conn.commit()

# --- Sessions ---
def create_session(session_id: str, project_id: str, model: str):
    conn = get_db()
    conn.execute("""
        INSERT OR IGNORE INTO sessions (id, project_id, model, saved_at)
        VALUES (?, ?, ?, ?)
    """, (session_id, project_id, model, datetime.now().isoformat()))
    conn.commit()

def update_session(session_id: str, model: str):
    conn = get_db()
    conn.execute("UPDATE sessions SET model = ?, saved_at = ? WHERE id = ?", (model, datetime.now().isoformat(), session_id))
    conn.commit()

def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    return dict(row) if row else None

def get_sessions_for_project(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM sessions WHERE project_id = ? ORDER BY saved_at DESC", (project_id,)).fetchall()
    return [dict(r) for r in rows]

def delete_session(session_id: str):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    conn.commit()

# --- Messages ---
def save_messages(session_id: str, messages: List[Dict[str, Any]]):
    conn = get_db()
    conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
    for msg in messages:
        conn.execute("INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                     (session_id, msg.get("role", ""), msg.get("content", ""), datetime.now().isoformat()))
    conn.commit()

def get_messages(session_id: str) -> List[Dict[str, Any]]:
    conn = get_db()
    rows = conn.execute("SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC", (session_id,)).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in rows]

def get_turn_count(session_id: str) -> int:
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM messages WHERE session_id = ? AND role = 'user'", (session_id,)).fetchone()
    return row["cnt"] if row else 0

# --- Events ---
def append_event(session_id: str, event: dict):
    conn = get_db()
    conn.execute("INSERT INTO events (session_id, type, content_json, timestamp) VALUES (?, ?, ?, ?)",
                 (session_id, event.get("type", ""), json.dumps(event, ensure_ascii=False), datetime.now().isoformat()))
    conn.commit()

def get_events(session_id: str) -> List[Dict[str, Any]]:
    conn = get_db()
    rows = conn.execute("SELECT content_json FROM events WHERE session_id = ? ORDER BY id ASC", (session_id,)).fetchall()
    events = []
    for r in rows:
        try:
            events.append(json.loads(r["content_json"]))
        except:
            pass
    return events

# --- Findings ---
def add_finding(project_id: str, finding: dict):
    conn = get_db()
    # deduplication logic
    ftype = finding.get("type", "")
    val = str(finding.get("value", ""))[:80]
    
    # check if exists
    exists = conn.execute("""
        SELECT 1 FROM findings 
        WHERE project_id = ? AND type = ? AND substr(value, 1, 80) = ?
    """, (project_id, ftype, val)).fetchone()
    
    if not exists:
        conn.execute("""
            INSERT INTO findings (project_id, severity, type, value, description, source, raw_json, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            project_id,
            finding.get("severity", "info"),
            ftype,
            finding.get("value", ""),
            finding.get("description", ""),
            finding.get("source", ""),
            json.dumps(finding, ensure_ascii=False),
            datetime.now().isoformat()
        ))
        conn.commit()

def get_findings(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db()
    rows = conn.execute("SELECT raw_json FROM findings WHERE project_id = ? ORDER BY id ASC", (project_id,)).fetchall()
    return [json.loads(r["raw_json"]) for r in rows]

def get_severity_summary(project_id: str) -> Dict[str, int]:
    conn = get_db()
    rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM findings WHERE project_id = ? GROUP BY severity", (project_id,)).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}

# --- Domains ---
def add_domain(project_id: str, domain: str) -> bool:
    conn = get_db()
    try:
        conn.execute("INSERT INTO domains (project_id, domain) VALUES (?, ?)", (project_id, domain))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_domains(project_id: str) -> List[str]:
    conn = get_db()
    rows = conn.execute("SELECT domain FROM domains WHERE project_id = ? ORDER BY domain ASC", (project_id,)).fetchall()
    return [r["domain"] for r in rows]

# --- Scan Cache ---
def put_cache(project_id: str, cmd_key: str, stdout: str, stderr: str, code: int, ts: float):
    conn = get_db()
    conn.execute("""
        INSERT INTO scan_cache (cmd_key, project_id, stdout, stderr, code, ts, cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cmd_key) DO UPDATE SET
            stdout=excluded.stdout,
            stderr=excluded.stderr,
            code=excluded.code,
            ts=excluded.ts,
            cached_at=excluded.cached_at
    """, (cmd_key, project_id, stdout, stderr, code, ts, datetime.now().isoformat()))
    conn.commit()

def get_cache(cmd_key: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    row = conn.execute("SELECT * FROM scan_cache WHERE cmd_key = ?", (cmd_key,)).fetchone()
    return dict(row) if row else None
