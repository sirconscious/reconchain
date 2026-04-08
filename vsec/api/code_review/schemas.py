"""
VSec Code Review API - Pydantic schemas
"""
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ReviewStatus(str, Enum):
    PENDING = "pending"
    CLONING = "cloning"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    ERROR = "error"


class QuickFinding(BaseModel):
    """Quick pattern scan finding."""
    type: str
    file: str
    line: str
    description: str


class ReviewCreate(BaseModel):
    """Request to start a code review."""
    repo_url: str = Field(..., description="Git repository URL (https://github.com/user/repo)")
    max_chars: int = Field(
        default=80000,
        description="Maximum characters to send to LLM (default: 80000)"
    )


class ReviewResponse(BaseModel):
    """Code review session state."""
    id: str
    status: ReviewStatus
    repo_url: str
    repo_name: str | None = None
    files_found: int = 0
    quick_findings: list[QuickFinding] = Field(default_factory=list)
    created_at: datetime
    report_path: str | None = None
    error: str | None = None


class ReviewResult(BaseModel):
    """Full review result with content."""
    id: str
    status: ReviewStatus
    repo_url: str
    repo_name: str | None = None
    files_found: int
    quick_findings: list[QuickFinding]
    report_content: str | None = None
    report_path: str | None = None


class SSEEvent(BaseModel):
    """Server-Sent Event for code review."""
    type: str  # status, quick_findings, progress, message, done, error
    status: str | None = None
    message: str | None = None
    finding: QuickFinding | None = None
    progress: int | None = None
    error: str | None = None
