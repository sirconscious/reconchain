"""
VSec API — FastAPI routes and SSE endpoints
"""
import os
import asyncio
import json
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from vsec.api.schemas import (
    SessionCreate,
    SessionResponse,
    MessageInput,
    MessageResponse,
    ReportResponse,
    HealthResponse,
    ToolsResponse,
    SessionStatus,
)
from vsec.api.session import get_session_manager, Session
from vsec.api.agent import get_agent, PentestAgent, SSECallbackHandler
from vsec.api.code_review.routes import router as code_review_router
from vsec.api.storage import init_db, get_db_path

VERSION = "0.1.0"

app = FastAPI(
    title="VSec API",
    description="AI-Powered Penetration Testing Agent API",
    version=VERSION,
)

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()
    print(f"  Database: {get_db_path()}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include code review routes
app.include_router(code_review_router)

_reports_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports"
)


def session_to_response(session: Session) -> SessionResponse:
    return SessionResponse(
        id=session.id,
        status=SessionStatus(session.status.value),
        created_at=session.created_at,
        messages=session.messages,
        report_path=session.report_path,
        model=session.model,
    )


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Check API health status."""
    agent = get_agent()
    return HealthResponse(
        status="healthy",
        tools_count=agent.get_tools_count(),
        cve_entries=agent._cve_count,
        version=VERSION,
    )


@app.get("/api/tools", response_model=ToolsResponse)
async def list_tools():
    """List all available pentest tools."""
    agent = get_agent()
    return ToolsResponse(tools=agent.get_tools_info())


@app.post("/api/sessions", response_model=SessionResponse)
async def create_session(body: SessionCreate | None = None):
    """Create a new pentest session."""
    model = body.model_name if body else "claude-haiku-4-5"
    manager = get_session_manager()
    session = manager.create(model=model)
    return session_to_response(session)


@app.get("/api/sessions", response_model=list[SessionResponse])
async def list_sessions():
    """List all active sessions."""
    manager = get_session_manager()
    return [session_to_response(s) for s in manager.list_all()]


@app.get("/api/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str):
    """Get session details."""
    manager = get_session_manager()
    session = manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session_to_response(session)


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a session."""
    manager = get_session_manager()
    if not manager.delete(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": True, "session_id": session_id}


async def event_generator(session_id: str, message_content: str):
    """Generate SSE events for streaming agent response."""
    manager = get_session_manager()
    session = manager.get(session_id)

    if not session:
        yield {"event": "error", "data": json.dumps({"type": "error", "error": "Session not found"})}
        return

    # Update status in database
    manager.update(session_id, status="processing")
    
    # Add user message to database
    manager.add_message(session_id, "user", message_content)
    
    # Re-fetch session with updated messages
    session = manager.get(session_id)
    messages = session.messages.copy() if session else []

    callback = SSECallbackHandler()
    agent = get_agent(model_name=session.model if session else "claude-haiku-4-5")

    try:
        result = agent.invoke_with_retry(messages, stream_callback=callback)

        for event in callback.events:
            event_type = event.get("type", "message")
            yield {"event": event_type, "data": json.dumps(event, default=str)}

        if result.get("response"):
            yield {"event": "message", "data": json.dumps({"type": "message", "content": result["response"]})}
            # Add assistant message to database
            manager.add_message(session_id, "assistant", result["response"])

        if result.get("report_path"):
            manager.update(session_id, report_path=result["report_path"])
            yield {"event": "done", "data": json.dumps({"type": "done", "report_path": result["report_path"]})}
        else:
            yield {"event": "done", "data": json.dumps({"type": "done", "complete": True})}

        # Update status in database
        manager.update(session_id, status="complete")

        # Send [DONE] to properly close SSE stream
        yield "data: [DONE]\n\n"

    except Exception as e:
        manager.update(session_id, status="error")
        error_msg = str(e)
        yield {"event": "error", "data": json.dumps({"type": "error", "error": error_msg})}
        # Send [DONE] even on error to close stream
        yield "data: [DONE]\n\n"


@app.post("/api/sessions/{session_id}/message")
async def send_message(
    session_id: str,
    body: MessageInput,
    background_tasks: BackgroundTasks,
):
    """Send a message to the agent and optionally stream the response."""
    manager = get_session_manager()
    session = manager.get(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status == SessionStatus.PROCESSING:
        raise HTTPException(status_code=409, detail="Session is already processing")

    if not body.stream:
        callback = SSECallbackHandler()
        
        # Add user message to database
        manager.add_message(session_id, "user", body.content)
        
        # Re-fetch with updated messages
        session = manager.get(session_id)
        
        agent = get_agent(model_name=session.model if session else "claude-haiku-4-5")

        try:
            result = agent.invoke_with_retry(session.messages.copy(), stream_callback=callback)

            if result.get("response"):
                # Add assistant message to database
                manager.add_message(session_id, "assistant", result["response"])

            # Update report path if provided
            if result.get("report_path"):
                manager.update(session_id, report_path=result["report_path"])
                session.report_path = result["report_path"]
            
            # Update status in database
            manager.update(session_id, status="complete")

            return MessageResponse(
                session_id=session_id,
                status=SessionStatus.COMPLETE,
                response=result.get("response"),
                report_path=session.report_path,
            )
        except Exception as e:
            manager.update(session_id, status="error")
            raise HTTPException(status_code=500, detail=str(e))

    return EventSourceResponse(
        event_generator(session_id, body.content),
        media_type="text/event-stream",
    )


@app.get("/api/sessions/{session_id}/stream")
async def stream_session(session_id: str):
    """SSE endpoint for real-time session events."""
    manager = get_session_manager()
    session = manager.get(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator_simple():
        while True:
            await asyncio.sleep(1)
            current = manager.get(session_id)
            if not current:
                yield {"event": "error", "data": json.dumps({"error": "Session not found"})}
                break
            if current.status == SessionStatus.PROCESSING:
                yield {"event": "status", "data": json.dumps({"status": "processing", "messages": current.messages})}
            else:
                yield {"event": "status", "data": json.dumps({"status": current.status.value, "messages": current.messages})}
                break

    return EventSourceResponse(event_generator_simple())


@app.get("/api/reports/{session_id}", response_model=ReportResponse)
async def get_report(session_id: str):
    """Get the pentest report for a session."""
    manager = get_session_manager()
    session = manager.get(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if not session.report_path or not os.path.exists(session.report_path):
        raise HTTPException(status_code=404, detail="Report not found")

    with open(session.report_path, "r") as f:
        content = f.read()

    return ReportResponse(
        session_id=session_id,
        content=content,
        path=session.report_path,
    )


@app.get("/api/reports/{session_id}/download")
async def download_report(session_id: str):
    """Download the pentest report as a file."""
    from fastapi.responses import FileResponse

    manager = get_session_manager()
    session = manager.get(session_id)

    if not session or not session.report_path:
        raise HTTPException(status_code=404, detail="Report not found")

    if not os.path.exists(session.report_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    filename = os.path.basename(session.report_path)
    return FileResponse(
        path=session.report_path,
        filename=filename,
        media_type="text/markdown",
    )
