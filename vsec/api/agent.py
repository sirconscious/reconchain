"""
VSec API — Core PentestAgent class

Extracts agent logic from pentest_agent.py to be reused by both
CLI and API interfaces.
"""
import os
import time
import datetime
from typing import Any, Generator

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tools import TOOLS, _load_cve_dataset

load_dotenv()


SYSTEM_PROMPT = """
You are an elite web penetration tester running in interactive mode.

METHODOLOGY (follow in order unless told otherwise):
1. Recon & OSINT   → get_dnsdumpster, get_whois, get_http_headers, get_robots_txt, detect_technologies
2. Scanning        → get_nmap_scan, check_common_paths, run_gobuster_dirs, run_gobuster_subs
3. Reporting       → severity-tagged findings with PoC commands

RULES:
- When given a target, run ALL recon tools first before reporting.
- Every finding MUST include a PoC command.
- Prefix phases: [RECON] [SCAN] [EXPLOIT] [REPORT]
- Rank findings: Critical → High → Medium → Low
- After each phase summarize and ask if user wants to continue.
- Only operate on systems with explicit written authorization.
- When you detect a technology or service, use retrieve_cve_info to check for known CVEs.
- Use shell() freely for any custom request, curl, or manual follow-up check.
"""

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports"
)


def _load_cve_if_needed():
    """Load CVE dataset if not already loaded."""
    try:
        _load_cve_dataset()
    except Exception:
        pass


class SSECallbackHandler(BaseCallbackHandler):
    """Callback handler that yields SSE events."""

    def __init__(self):
        self.tool_start_time = None
        self.step = 0
        self.events: list[dict] = []

    def _emit(self, event_type: str, **data):
        self.events.append({"type": event_type, **data})

    def on_llm_start(self, *args, **kwargs):
        self._emit("reasoning", content="thinking...")

    def on_tool_start(self, serialized: dict, input_str: str | dict, **kwargs):
        self.tool_start_time = time.time()
        self.step += 1
        name = serialized.get("name", "unknown_tool")
        input_val = str(input_str)[:200] if isinstance(input_str, str) else str(input_str)
        self._emit("tool_start", tool=name, input=input_val, step=self.step)

    def on_tool_end(self, output: str, **kwargs):
        elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
        output_val = str(output)[:2000] if output else "(empty)"
        self._emit("tool_end", output=output_val, elapsed=round(elapsed, 2))

    def on_tool_error(self, error: Exception, **kwargs):
        elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
        self._emit("error", error=str(error), elapsed=round(elapsed, 2))

    def on_agent_finish(self, finish: Any, **kwargs):
        self._emit("done", complete=True)


class PentestAgent:
    """Core pentest agent that can be used by both CLI and API."""

    def __init__(self, model_name: str = "claude-haiku-4-5"):
        _load_cve_if_needed()

        self.model_name = model_name
        self.model = ChatAnthropic(
            model=model_name,
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            temperature=0,
            max_tokens=4096,
        )
        self.agent = create_react_agent(self.model, TOOLS, prompt=SYSTEM_PROMPT)
        self._cve_count = self._get_cve_count()

    def _get_cve_count(self) -> int:
        """Get the number of loaded CVE entries."""
        try:
            from tools import _CVE_TEXTS
            return len(_CVE_TEXTS)
        except Exception:
            return 0

    def get_tools_info(self) -> list[dict[str, str]]:
        """Get information about available tools."""
        tools_info = []
        for tool in TOOLS:
            name = getattr(tool, "name", str(tool))
            doc = getattr(tool, "description", "") or ""
            tools_info.append({"name": name, "description": doc[:100]})
        return tools_info

    def get_tools_count(self) -> int:
        """Get the number of available tools."""
        return len(TOOLS)

    def save_report(self, target: str, content: str) -> str:
        """Save a pentest report to the reports directory."""
        os.makedirs(REPORTS_DIR, exist_ok=True)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{domain}_{timestamp}.md"
        filepath = os.path.join(REPORTS_DIR, filename)
        with open(filepath, "w") as f:
            f.write(f"VSec Penetration Test Report\n")
            f.write(f"Target    : {target}\n")
            f.write(f"Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            f.write(content)
        return filepath

    def _build_langchain_messages(self, messages: list[dict]) -> list:
        """Convert simple message dicts to LangChain message objects."""
        langchain_messages = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                langchain_messages.append(HumanMessage(content=content))
            else:
                langchain_messages.append(AIMessage(content=content))
        return langchain_messages

    def invoke(
        self,
        messages: list[dict],
        stream_callback: SSECallbackHandler | None = None,
    ) -> dict[str, Any]:
        """
        Invoke the agent with a list of messages.

        Args:
            messages: List of {"role": "user"|"assistant", "content": str}
            stream_callback: Optional callback for SSE events

        Returns:
            dict with "response", "messages", and optionally "report_path"
        """
        if stream_callback is None:
            stream_callback = SSECallbackHandler()

        try:
            langchain_messages = self._build_langchain_messages(messages)

            result = self.agent.invoke(
                {"messages": langchain_messages},
                config={"callbacks": [stream_callback]},
            )

            ai_messages = [
                m for m in result["messages"]
                if hasattr(m, "content") and m.type == "ai"
            ]
            response = ai_messages[-1].content if ai_messages else ""

            report_path = None
            if any(kw in response for kw in ["[REPORT]", "[RECON]", "Finding #", "Severity", "PENETRATION TEST"]):
                target = messages[0].get("content", "unknown") if messages else "unknown"
                if "http" not in target:
                    for msg in messages:
                        if "http" in msg.get("content", ""):
                            target = msg.get("content", "unknown")
                            break
                report_path = self.save_report(target, response)

            return {
                "response": response,
                "messages": [
                    {"role": "user" if m.type == "human" else "assistant", "content": m.content}
                    for m in result["messages"]
                    if hasattr(m, "type") and m.type in ("human", "ai")
                    and isinstance(m.content, str)
                ],
                "report_path": report_path,
                "events": stream_callback.events,
            }

        except Exception as e:
            if "429" in str(e):
                stream_callback._emit("error", error="Rate limited. Please wait and try again.")
                raise Exception("Rate limited. Please wait and try again.")
            raise

    def invoke_with_retry(
        self,
        messages: list[dict],
        stream_callback: SSECallbackHandler | None = None,
        max_retries: int = 1,
    ) -> dict[str, Any]:
        """Invoke with automatic retry on rate limit."""
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                return self.invoke(messages, stream_callback)
            except Exception as e:
                last_error = e
                if "429" in str(e) and attempt < max_retries:
                    stream_callback._emit("message", content="Rate limited. Waiting 30s...")
                    time.sleep(30)
                    stream_callback._emit("message", content="Retrying...")
                else:
                    raise
        raise last_error


_agent: PentestAgent | None = None


def get_agent(model_name: str = "claude-haiku-4-5") -> PentestAgent:
    """Get or create the singleton PentestAgent instance."""
    global _agent
    if _agent is None or _agent.model_name != model_name:
        _agent = PentestAgent(model_name=model_name)
    return _agent
