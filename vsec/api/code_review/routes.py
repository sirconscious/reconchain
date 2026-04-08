"""
VSec Code Review API Routes

FastAPI routes for code security review with SQLite persistence.
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from sse_starlette.sse import EventSourceResponse

from vsec.api.code_review.schemas import (
    ReviewCreate,
    ReviewResponse,
    ReviewResult,
    ReviewStatus,
    QuickFinding,
)
from vsec.api.code_review.agent import (
    CodeReviewAgent,
    get_review_agent,
    get_repo_name,
)
from vsec.api.repositories import get_review_repo


router = APIRouter(prefix="/api/code-review", tags=["code-review"])


def create_review_response(data: dict) -> ReviewResponse:
    """Create a ReviewResponse from stored data."""
    return ReviewResponse(
        id=data["id"],
        status=ReviewStatus(data.get("status", "pending")),
        repo_url=data.get("repo_url", ""),
        repo_name=data.get("repo_name"),
        files_found=data.get("files_found", 0),
        quick_findings=[QuickFinding(**f) for f in data.get("quick_findings", [])],
        created_at=data.get("created_at", datetime.utcnow()),
        report_path=data.get("report_path"),
        error=data.get("error"),
    )


@router.post("/reviews", response_model=ReviewResponse)
async def create_review(body: ReviewCreate):
    """Start a new code review session."""
    # Validate URL
    if not body.repo_url.startswith(("http://", "https://", "git@")):
        raise HTTPException(
            status_code=400,
            detail="Invalid URL. Use https://github.com/user/repo format."
        )

    # Create review session in database
    review = get_review_repo().create(
        repo_url=body.repo_url,
        repo_name=get_repo_name(body.repo_url),
        max_chars=body.max_chars,
    )

    return create_review_response(review)


@router.get("/reviews", response_model=list[ReviewResponse])
async def list_reviews():
    """List all review sessions."""
    reviews = get_review_repo().list_all()
    return [create_review_response(r) for r in reviews]


@router.get("/reviews/{review_id}", response_model=ReviewResponse)
async def get_review(review_id: str):
    """Get a specific review session."""
    review = get_review_repo().get(review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    return create_review_response(review)


@router.delete("/reviews/{review_id}")
async def delete_review(review_id: str):
    """Delete a review session."""
    if not get_review_repo().delete(review_id):
        raise HTTPException(status_code=404, detail="Review not found")
    return {"deleted": True, "id": review_id}


async def review_event_generator(review_id: str, repo_url: str, max_chars: int):
    """Generate SSE events for a review."""
    review = get_review_repo().get(review_id)
    if not review:
        yield {"event": "error", "data": json.dumps({"error": "Review not found"})}
        return

    get_review_repo().update(review_id, status="cloning")
    agent = get_review_agent()

    try:
        for event in agent.review(repo_url, max_chars=max_chars):
            event_type = event.get("type", "message")

            if event_type == "status":
                status = event.get("status", "")
                message = event.get("message", "")
                get_review_repo().update(review_id, status=status)
                yield {"event": "status", "data": json.dumps({"status": status, "message": message})}

            elif event_type == "progress":
                progress = event.get("progress", 0)
                message = event.get("message", "")
                yield {"event": "progress", "data": json.dumps({"progress": progress, "message": message})}

            elif event_type == "quick_finding":
                finding = event.get("finding", {})
                get_review_repo().add_finding(review_id, finding)
                yield {"event": "quick_finding", "data": json.dumps({"finding": finding})}

            elif event_type == "done":
                get_review_repo().update(
                    review_id,
                    status="complete",
                    files_found=event.get("files_found", 0),
                    report_path=event.get("report_path"),
                    report_content=event.get("report_content"),
                    quick_findings=event.get("quick_findings", [])
                )

                yield {
                    "event": "done",
                    "data": json.dumps({
                        "report_path": event.get("report_path"),
                        "files_found": event.get("files_found", 0),
                        "quick_findings_count": len(event.get("quick_findings", [])),
                    })
                }

            elif event_type == "error":
                error_msg = event.get("error", "Unknown error")
                get_review_repo().update(review_id, status="error", error=error_msg)
                yield {"event": "error", "data": json.dumps({"error": error_msg})}

            else:
                yield {"event": "message", "data": json.dumps(event)}

    except Exception as e:
        error_msg = str(e)
        get_review_repo().update(review_id, status="error", error=error_msg)
        yield {"event": "error", "data": json.dumps({"error": error_msg})}


@router.post("/reviews/{review_id}/run")
async def run_review(review_id: str):
    """Start running a code review (streaming response)."""
    review = get_review_repo().get(review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    if review["status"] not in ("pending", "error"):
        raise HTTPException(
            status_code=409,
            detail=f"Review already {review['status']}"
        )

    return EventSourceResponse(
        review_event_generator(review_id, review["repo_url"], review.get("max_chars", 80000)),
        media_type="text/event-stream",
    )


@router.post("/reviews/{review_id}/start", response_model=ReviewResult)
async def start_review(review_id: str):
    """Start a review and wait for completion (non-streaming)."""
    review = get_review_repo().get(review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    agent = get_review_agent()

    result = None
    for event in agent.review(review["repo_url"], max_chars=review.get("max_chars", 80000)):
        if event.get("type") == "done":
            result = event
            break

    if result:
        get_review_repo().update(
            review_id,
            status="complete",
            files_found=result.get("files_found", 0),
            report_path=result.get("report_path"),
            report_content=result.get("report_content"),
            quick_findings=result.get("quick_findings", [])
        )

    updated = get_review_repo().get(review_id)

    return ReviewResult(
        id=review_id,
        status=ReviewStatus(updated["status"]),
        repo_url=updated["repo_url"],
        repo_name=updated["repo_name"],
        files_found=updated["files_found"],
        quick_findings=[QuickFinding(**f) for f in updated["quick_findings"]],
        report_content=updated.get("report_content"),
        report_path=updated.get("report_path"),
    )


@router.get("/reports/{review_id}")
async def get_review_report(review_id: str):
    """Get the report content for a review."""
    review = get_review_repo().get(review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    if review["status"] != "complete":
        raise HTTPException(
            status_code=409,
            detail=f"Review not complete. Status: {review['status']}"
        )

    if not review.get("report_content"):
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": review_id,
        "repo_url": review["repo_url"],
        "repo_name": review["repo_name"],
        "content": review["report_content"],
        "report_path": review["report_path"],
        "quick_findings": review["quick_findings"],
        "files_found": review["files_found"],
    }


@router.get("/reports/{review_id}/download")
async def download_review_report(review_id: str):
    """Download the report as a markdown file."""
    from fastapi.responses import FileResponse

    review = get_review_repo().get(review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")

    if not review.get("report_path"):
        raise HTTPException(status_code=404, detail="Report not found")

    if not os.path.exists(review["report_path"]):
        raise HTTPException(status_code=404, detail="Report file not found")

    filename = os.path.basename(review["report_path"])
    return FileResponse(
        path=review["report_path"],
        filename=filename,
        media_type="text/markdown",
    )
