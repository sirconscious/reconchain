"""
VSec API — SQLite Database Storage

Provides persistent storage for sessions and code reviews.
Database file is stored at: <project_root>/vsec.db
"""
import sqlite3
import json
import os
import threading
from datetime import datetime
from typing import Generator, Any
from contextlib import contextmanager

# Database file path - stored in project root
DB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(DB_DIR, "vsec.db")

# Thread-local storage for connections
_local = threading.local()


def get_db_path() -> str:
    """Get the database file path."""
    return DB_PATH


def _get_connection() -> sqlite3.Connection:
    """Get a thread-local database connection."""
    if not hasattr(_local, 'connection') or _local.connection is None:
        _local.connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.connection.row_factory = sqlite3.Row
        # Enable foreign keys
        _local.connection.execute("PRAGMA foreign_keys = ON")
    return _local.connection


def close_connection():
    """Close the thread-local connection."""
    if hasattr(_local, 'connection') and _local.connection:
        _local.connection.close()
        _local.connection = None


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database operations with automatic commit."""
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Initialize the database schema."""
    with get_db() as conn:
        conn.executescript("""
            -- Sessions table for pentest sessions
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                model TEXT NOT NULL DEFAULT 'claude-haiku-4-5',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                messages TEXT DEFAULT '[]',
                report_path TEXT,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Reviews table for code review sessions
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY,
                repo_url TEXT NOT NULL,
                repo_name TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                files_found INTEGER DEFAULT 0,
                quick_findings TEXT DEFAULT '[]',
                report_content TEXT,
                report_path TEXT,
                max_chars INTEGER DEFAULT 80000,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                error TEXT
            );
            
            -- Indexes for faster queries
            CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
            CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);
            CREATE INDEX IF NOT EXISTS idx_reviews_repo ON reviews(repo_url);
        """)
    
    print(f"  Database initialized: {DB_PATH}")


def json_dumps(obj: Any) -> str:
    """Serialize object to JSON string."""
    return json.dumps(obj, default=str, ensure_ascii=False)


def json_loads(text: str | None) -> Any:
    """Deserialize JSON string to object."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


# Database schema reference:
#
# sessions:
#   id          TEXT PRIMARY KEY
#   model       TEXT NOT NULL
#   status      TEXT NOT NULL (active, processing, complete, error)
#   created_at  TIMESTAMP
#   messages    TEXT (JSON array of {role, content})
#   report_path TEXT
#   updated_at  TIMESTAMP
#
# reviews:
#   id              TEXT PRIMARY KEY
#   repo_url        TEXT NOT NULL
#   repo_name       TEXT
#   status          TEXT NOT NULL (pending, cloning, scanning, analyzing, complete, error)
#   files_found     INTEGER
#   quick_findings TEXT (JSON array of {type, file, line, description})
#   report_content  TEXT
#   report_path     TEXT
#   max_chars       INTEGER
#   created_at      TIMESTAMP
#   updated_at      TIMESTAMP
#   error           TEXT
