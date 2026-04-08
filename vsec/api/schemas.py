"""
VSec API — Pydantic schemas for request/response models
"""
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SessionStatus(str, Enum):
    ACTIVE = "active"
    PROCESSING = "processing"
    COMPLETE = "complete"
    ERROR = "error"


class ToolInfo(BaseModel):
    name: str
    description: str


class SessionCreate(BaseModel):
    """Request to create a new pentest session."""
    model_name: str | None = Field(
        default="claude-haiku-4-5",
        description="AI model to use (default: claude-haiku-4-5)"
    )


class SessionResponse(BaseModel):
    """Full session state."""
    id: str
    status: SessionStatus
    created_at: datetime
    messages: list[dict[str, str]] = Field(default_factory=list)
    report_path: str | None = None
    model: str


class MessageInput(BaseModel):
    """User message to send to the agent."""
    content: str = Field(..., description="Target URL or command")
    stream: bool = Field(
        default=True,
        description="Enable SSE streaming (recommended)"
    )


class MessageResponse(BaseModel):
    """Response after sending a message."""
    session_id: str
    status: SessionStatus
    response: str | None = None
    report_path: str | None = None


class SSEEvent(BaseModel):
    """Server-Sent Event data."""
    type: str
    data: dict[str, Any]


class ToolEvent(BaseModel):
    """Tool execution event."""
    type: str = Field(..., description="Event type: tool_start, tool_end, message, error, done")
    tool: str | None = None
    input: str | None = None
    output: str | None = None
    elapsed: float | None = None
    content: str | None = None
    error: str | None = None
    report_path: str | None = None


class ReportResponse(BaseModel):
    """Generated pentest report."""
    session_id: str
    content: str | None = None
    path: str | None = None


class HealthResponse(BaseModel):
    """API health status."""
    status: str
    tools_count: int
    cve_entries: int | None
    version: str


class ToolsResponse(BaseModel):
    """List of available tools."""
    tools: list[dict[str, str]]
