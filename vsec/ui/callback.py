"""
VSec UI — Callback Handler for Real-time Tool Progress
"""
import time
import threading
from typing import TYPE_CHECKING

from langchain_core.callbacks.base import BaseCallbackHandler

if TYPE_CHECKING:
    from vsec.ui.cli import VSecTerminalUI


class LiveProgressCallback(BaseCallbackHandler):
    """Callback handler that updates TUI in real-time."""
    
    def __init__(self, ui: "VSecTerminalUI"):
        self.ui = ui
        self.tool_start_time = None
        self.current_tool = None
    
    def on_llm_start(self, *args, **kwargs):
        self.ui.set_thinking(True)
    
    def on_llm_end(self, *args, **kwargs):
        self.ui.set_thinking(False)
    
    def on_tool_start(self, serialized, input_str, **kwargs):
        self.tool_start_time = time.time()
        self.current_tool = serialized.get("name", "unknown_tool")
        self.ui.update_tool(self.current_tool, "running", input_str=str(input_str)[:60])
    
    def on_tool_end(self, output, **kwargs):
        if self.current_tool:
            elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
            lines = str(output).strip().splitlines()
            preview = lines[0][:80] if lines else "(empty)"
            self.ui.update_tool(
                self.current_tool, 
                "done", 
                elapsed=elapsed, 
                preview=preview
            )
        self.current_tool = None
        self.tool_start_time = None
    
    def on_tool_error(self, error, **kwargs):
        if self.current_tool:
            self.ui.update_tool(self.current_tool, "error", error=str(error)[:100])
        self.current_tool = None
        self.tool_start_time = None
    
    def on_agent_finish(self, finish, **kwargs):
        self.ui.set_agent_finished()


class SimpleCallback(BaseCallbackHandler):
    """Simple callback that prints to stdout (for non-TUI mode)."""
    
    def __init__(self):
        self.tool_start_time = None
        self.step = 0
    
    def on_llm_start(self, *args, **kwargs):
        print("  ◆ reasoning...", flush=True)
    
    def on_tool_start(self, serialized, input_str, **kwargs):
        self.tool_start_time = time.time()
        self.step += 1
        name = serialized.get("name", "unknown_tool")
        print(f"\n  ◆ [{self.step}] {name}", flush=True)
        print(f"    ↳ {str(input_str)[:80]}", flush=True)
    
    def on_tool_end(self, output, **kwargs):
        elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
        lines = str(output).strip().splitlines()
        preview = lines[0][:80] if lines else "(empty)"
        print(f"    ✓ {elapsed:.1f}s  {preview}", flush=True)
    
    def on_tool_error(self, error, **kwargs):
        elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
        print(f"    ✗ {elapsed:.1f}s  {str(error)[:80]}", flush=True)
    
    def on_agent_finish(self, finish, **kwargs):
        print("\n  ✔ scan complete\n", flush=True)
