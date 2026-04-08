"""
VSec API — Data Repositories

Provides data access layer for sessions and reviews using SQLite.
"""
import os
import uuid
from datetime import datetime
from typing import Any

from vsec.api.storage import get_db, json_dumps, json_loads


class SessionRepository:
    """Repository for pentest session data."""

    def create(self, session_id: str | None = None, model: str = "claude-haiku-4-5") -> dict:
        """Create a new session."""
        sid = session_id or str(uuid.uuid4())[:8]
        now = datetime.utcnow()
        
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO sessions (id, model, status, created_at, updated_at, messages)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sid, model, "active", now, now, json_dumps([]))
            )
        
        return self._row_to_session({
            "id": sid,
            "model": model,
            "status": "active",
            "created_at": now,
            "updated_at": now,
            "messages": "[]",
            "report_path": None
        })

    def get(self, session_id: str) -> dict | None:
        """Get a session by ID."""
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,)
            ).fetchone()
        
        if not row:
            return None
        
        return self._row_to_session(row)

    def update(self, session_id: str, **kwargs: Any) -> dict | None:
        """Update a session's fields."""
        if not kwargs:
            return self.get(session_id)
        
        # Map camelCase to snake_case
        field_mapping = {
            "reportPath": "report_path",
        }
        
        # Build update query
        updates = []
        values = []
        for key, value in kwargs.items():
            key = field_mapping.get(key, key)
            if key == "messages":
                value = json_dumps(value)
            elif key in ("status", "model", "report_path"):
                pass  # Already correct format
            updates.append(f"{key} = ?")
            values.append(value)
        
        if not updates:
            return self.get(session_id)
        
        updates.append("updated_at = ?")
        values.append(datetime.utcnow())
        values.append(session_id)
        
        with get_db() as conn:
            conn.execute(
                f"UPDATE sessions SET {', '.join(updates)} WHERE id = ?",
                values
            )
        
        return self.get(session_id)

    def add_message(self, session_id: str, role: str, content: str) -> dict | None:
        """Add a message to a session."""
        session = self.get(session_id)
        if not session:
            return None
        
        messages = session.get("messages", [])
        messages.append({"role": role, "content": content})
        
        return self.update(session_id, messages=messages)

    def delete(self, session_id: str) -> bool:
        """Delete a session."""
        with get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE id = ?",
                (session_id,)
            )
        return cursor.rowcount > 0

    def list_all(self, limit: int = 100) -> list[dict]:
        """List all sessions, most recent first."""
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        
        return [self._row_to_session(row) for row in rows]

    def _row_to_session(self, row: Any) -> dict:
        """Convert a database row to a session dict."""
        if row is None:
            return None
        
        if isinstance(row, dict):
            data = row
        else:
            data = dict(row)
        
        return {
            "id": data["id"],
            "model": data["model"],
            "status": data["status"],
            "created_at": data["created_at"],
            "updated_at": data.get("updated_at", data["created_at"]),
            "messages": json_loads(data.get("messages", "[]")) or [],
            "report_path": data.get("report_path"),
        }


class ReviewRepository:
    """Repository for code review data."""

    def create(
        self,
        review_id: str | None = None,
        repo_url: str = "",
        repo_name: str | None = None,
        max_chars: int = 80000
    ) -> dict:
        """Create a new review."""
        rid = review_id or str(uuid.uuid4().hex[:8])
        now = datetime.utcnow()
        
        # Extract repo name from URL if not provided
        if not repo_name and repo_url:
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO reviews (id, repo_url, repo_name, status, max_chars, created_at, updated_at, quick_findings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (rid, repo_url, repo_name, "pending", max_chars, now, now, json_dumps([]))
            )
        
        return self._row_to_review({
            "id": rid,
            "repo_url": repo_url,
            "repo_name": repo_name,
            "status": "pending",
            "files_found": 0,
            "quick_findings": "[]",
            "report_content": None,
            "report_path": None,
            "max_chars": max_chars,
            "created_at": now,
            "updated_at": now,
            "error": None
        })

    def get(self, review_id: str) -> dict | None:
        """Get a review by ID."""
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM reviews WHERE id = ?",
                (review_id,)
            ).fetchone()
        
        if not row:
            return None
        
        return self._row_to_review(row)

    def update(self, review_id: str, **kwargs: Any) -> dict | None:
        """Update a review's fields."""
        if not kwargs:
            return self.get(review_id)
        
        # Map camelCase to snake_case
        field_mapping = {
            "reportPath": "report_path",
            "reportContent": "report_content",
            "filesFound": "files_found",
            "quickFindings": "quick_findings",
        }
        
        # Build update query
        updates = []
        values = []
        for key, value in kwargs.items():
            key = field_mapping.get(key, key)
            if key == "quick_findings":
                value = json_dumps(value)
            elif key in ("report_content",):
                pass  # Already correct format
            updates.append(f"{key} = ?")
            values.append(value)
        
        if not updates:
            return self.get(review_id)
        
        updates.append("updated_at = ?")
        values.append(datetime.utcnow())
        values.append(review_id)
        
        with get_db() as conn:
            conn.execute(
                f"UPDATE reviews SET {', '.join(updates)} WHERE id = ?",
                values
            )
        
        return self.get(review_id)

    def add_finding(self, review_id: str, finding: dict) -> dict | None:
        """Add a quick finding to a review."""
        review = self.get(review_id)
        if not review:
            return None
        
        findings = review.get("quick_findings", [])
        findings.append(finding)
        
        return self.update(review_id, quick_findings=findings)

    def delete(self, review_id: str) -> bool:
        """Delete a review."""
        with get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM reviews WHERE id = ?",
                (review_id,)
            )
        return cursor.rowcount > 0

    def list_all(self, limit: int = 100) -> list[dict]:
        """List all reviews, most recent first."""
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM reviews ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        
        return [self._row_to_review(row) for row in rows]

    def _row_to_review(self, row: Any) -> dict:
        """Convert a database row to a review dict."""
        if row is None:
            return None
        
        if isinstance(row, dict):
            data = row
        else:
            data = dict(row)
        
        return {
            "id": data["id"],
            "repo_url": data["repo_url"],
            "repo_name": data.get("repo_name"),
            "status": data["status"],
            "files_found": data.get("files_found", 0),
            "quick_findings": json_loads(data.get("quick_findings", "[]")) or [],
            "report_content": data.get("report_content"),
            "report_path": data.get("report_path"),
            "max_chars": data.get("max_chars", 80000),
            "created_at": data["created_at"],
            "updated_at": data.get("updated_at", data["created_at"]),
            "error": data.get("error"),
        }


# Singleton instances
_session_repo: SessionRepository | None = None
_review_repo: ReviewRepository | None = None


def get_session_repo() -> SessionRepository:
    """Get the session repository singleton."""
    global _session_repo
    if _session_repo is None:
        _session_repo = SessionRepository()
    return _session_repo


def get_review_repo() -> ReviewRepository:
    """Get the review repository singleton."""
    global _review_repo
    if _review_repo is None:
        _review_repo = ReviewRepository()
    return _review_repo
