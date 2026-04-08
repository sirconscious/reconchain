"""
VSec API — Session management with SQLite persistence
"""
import uuid
from datetime import datetime
from typing import Any

from vsec.api.schemas import SessionStatus
from vsec.api.repositories import get_session_repo


class Session:
    """Represents a pentest session."""

    def __init__(
        self,
        session_id: str | None = None,
        model: str = "claude-haiku-4-5",
        data: dict | None = None
    ):
        if data:
            # Load from database
            self.id = data["id"]
            self.model = data["model"]
            self.status = SessionStatus(data["status"])
            self.created_at = data["created_at"]
            self.messages = data.get("messages", [])
            self.report_path = data.get("report_path")
        else:
            # Create new
            self.id = session_id or str(uuid.uuid4())[:8]
            self.model = model
            self.status = SessionStatus.ACTIVE
            self.created_at = datetime.utcnow()
            self.messages: list[dict[str, str]] = []
            self.report_path: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status.value,
            "created_at": self.created_at,
            "messages": self.messages,
            "report_path": self.report_path,
            "model": self.model,
        }

    def add_message(self, role: str, content: str):
        self.messages.append({"role": role, "content": content})

    def add_user_message(self, content: str):
        self.add_message("user", content)

    def add_assistant_message(self, content: str):
        self.add_message("assistant", content)


class SessionManager:
    """Manages pentest sessions using SQLite persistence."""

    def __init__(self):
        self._repo = get_session_repo()

    def create(self, model: str = "claude-haiku-4-5") -> Session:
        data = self._repo.create(model=model)
        return Session(data=data)

    def get(self, session_id: str) -> Session | None:
        data = self._repo.get(session_id)
        if not data:
            return None
        return Session(data=data)

    def delete(self, session_id: str) -> bool:
        return self._repo.delete(session_id)

    def list_all(self) -> list[Session]:
        data_list = self._repo.list_all()
        return [Session(data=data) for data in data_list]

    def update(self, session_id: str, **kwargs: Any) -> Session | None:
        """Update session fields in database."""
        data = self._repo.update(session_id, **kwargs)
        if not data:
            return None
        return Session(data=data)

    def add_message(self, session_id: str, role: str, content: str) -> Session | None:
        """Add a message to a session."""
        self._repo.add_message(session_id, role, content)
        return self.get(session_id)


# Module-level singleton
_sessions: SessionManager | None = None


def get_session_manager() -> SessionManager:
    global _sessions
    if _sessions is None:
        _sessions = SessionManager()
    return _sessions
