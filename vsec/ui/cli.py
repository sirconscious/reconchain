"""
VSec UI — Terminal User Interface with Blessed

A modern split-panel TUI for VSec with real-time tool status updates.
"""
import os
import time
import threading
import datetime
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING

from blessed import Terminal
from langchain_core.callbacks.base import BaseCallbackHandler

from vsec.tools import TOOLS
from vsec.config import settings

if TYPE_CHECKING:
    from langchain_core.messages import BaseMessage


# ════════════════════════════════════════════════════════════════════════════════════
# THEME
# ════════════════════════════════════════════════════════════════════════════════════
C = "\033[38;2;88;166;255m"      # Cyan
G = "\033[38;2;0;255;136m"       # Green
Y = "\033[38;2;240;165;0m"       # Yellow
R = "\033[38;2;255;68;68m"       # Red
M = "\033[38;2;188;140;255m"     # Magenta
W = "\033[38;2;201;209;217m"     # White
DIM = "\033[38;2;139;148;158m"   # Dim gray
BG = "\033[48;2;13;17;23m"      # Dark background
BORDER = "\033[38;2;48;54;61m"   # Border color
RESET = "\033[0m"

TOOL_ICONS = {
    "get_dnsdumpster":     "🌐",
    "get_whois":           "📋",
    "get_http_headers":    "📡",
    "get_robots_txt":      "🤖",
    "get_nmap_scan":       "🔍",
    "check_common_paths":   "🚪",
    "run_gobuster_dirs":   "📂",
    "run_gobuster_subs":   "🌍",
    "detect_technologies": "🔬",
    "shell":               "💻",
    "retrieve_cve_info":   "🗄",
}

TOOL_COLORS = {
    "get_dnsdumpster":     C,
    "get_whois":           C,
    "get_http_headers":    C,
    "get_robots_txt":      C,
    "get_nmap_scan":       Y,
    "check_common_paths":   Y,
    "run_gobuster_dirs":   Y,
    "run_gobuster_subs":   Y,
    "detect_technologies":  M,
    "shell":               R,
    "retrieve_cve_info":    Y,
}

THINKING_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"]

term = Terminal()


# ════════════════════════════════════════════════════════════════════════════════════
# LIVE PROGRESS CALLBACK
# ════════════════════════════════════════════════════════════════════════════════════
class LiveProgressHandler(BaseCallbackHandler):
    """Callback that updates the TUI in real-time."""
    
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


# ════════════════════════════════════════════════════════════════════════════════════
# TUI CLASS
# ════════════════════════════════════════════════════════════════════════════════════
class VSecTerminalUI:
    """Main terminal UI class."""
    
    def __init__(self):
        self.agent = None  # Set by run_tui()
        self.messages = []
        self.tool_status = {}
        self.current_target = None
        self.running = True
        self.agent_running = False
        self.is_thinking = False
        self.agent_finished = False
        self.current_input = ""
        self.frame = 0
        self.command_history = deque(maxlen=100)
        self.history_index = -1
        self.lock = threading.Lock()
        self.cve_count = self._get_cve_count()
        
        # Initialize tool status
        for tool in TOOLS:
            self.tool_status[tool.name] = {
                "status": "idle",
                "input": "",
                "preview": "",
                "elapsed": None,
                "error": None,
            }
    
    def _get_cve_count(self) -> int:
        """Get CVE count from the loaded dataset."""
        try:
            from vsec.tools.defaults.cve import _CVE_TEXTS
            return len(_CVE_TEXTS)
        except (ImportError, AttributeError):
            return 0
    
    def set_thinking(self, value: bool):
        with self.lock:
            self.is_thinking = value
    
    def set_agent_finished(self):
        with self.lock:
            self.agent_finished = True
    
    def update_tool(self, name: str, status: str, **kwargs):
        with self.lock:
            if name in self.tool_status:
                self.tool_status[name]["status"] = status
                for k, v in kwargs.items():
                    self.tool_status[name][k] = v
    
    def save_report(self, target: str, content: str) -> str:
        """Save report to reports folder."""
        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{domain}_{timestamp}.md"
        filepath = settings.reports_dir / filename
        with open(filepath, "w") as f:
            f.write(f"# VSec Penetration Test Report\n\n")
            f.write(f"**Target:** {target}\n")
            f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write(content)
        return str(filepath)
    
    def render(self):
        """Render the entire UI."""
        width = max(term.width or 80, 80)
        height = term.height or 24
        sidebar_w = max(28, int(width * 0.22))
        chat_w = width - sidebar_w - 2
        chat_h = height - 8
        
        lines = []
        
        # Header
        lines.extend(self._render_header(width))
        
        # Main content: chat + sidebar
        lines.extend(self._render_main(chat_w, chat_h, sidebar_w))
        
        # Input area
        lines.extend(self._render_input(chat_w))
        
        # Status bar
        lines.extend(self._render_statusbar(width, sidebar_w))
        
        output = term.home + "\n".join(lines)
        print(output, end="", flush=True)
    
    def _render_header(self, width: int) -> list[str]:
        """Render the header bar."""
        lines = []
        target = self.current_target or "no target"
        status = f"{G}●{RESET} Ready" if not self.agent_running else f"{Y}◐{RESET} Running"
        
        lines.append(f"{BG}{' ' * width}")
        lines.append(f"{BG}{G} VSec{RESET}  {DIM}{target}{RESET}  {status}{' ' * 20}")
        lines.append(f"{BORDER}{'─' * width}")
        
        return lines
    
    def _render_main(self, chat_w: int, chat_h: int, sidebar_w: int) -> list[str]:
        """Render main content area (chat + sidebar)."""
        lines = []
        
        # Chat area
        chat_lines = self._render_chat(chat_w, chat_h)
        
        # Sidebar
        sidebar_lines = self._render_sidebar(sidebar_w)
        
        # Combine
        for i in range(max(len(chat_lines), len(sidebar_lines) + 3)):
            chat_content = chat_lines[i] if i < len(chat_lines) else f"{DIM}{' ' * chat_w}{RESET}"
            sidebar_content = sidebar_lines[i - 3] if i >= 3 and i - 3 < len(sidebar_lines) else ""
            
            # Sidebar header if first line
            if i < 3:
                if i == 0:
                    lines.append(f"{sidebar_content}")
                elif i == 1:
                    lines.append(f"{sidebar_content}")
                elif i == 2:
                    lines.append(f"{sidebar_content}")
            else:
                lines.append(f"{chat_content}  {sidebar_content}")
        
        return lines
    
    def _render_chat(self, width: int, height: int) -> list[str]:
        """Render the chat area."""
        lines = []
        
        if not self.messages:
            lines.append(f"{DIM}┌{'─' * (width - 2)}┐{RESET}")
            lines.append(f"{DIM}│{' ' * (width - 2)}│{RESET}")
            lines.append(f"{DIM}│  {RESET}{C}Enter a target URL to begin...{RESET}{DIM}{' ' * (width - 35)}│{RESET}")
            lines.append(f"{DIM}│{' ' * (width - 2)}│{RESET}")
            lines.append(f"{DIM}└{'─' * (width - 2)}┘{RESET}")
            return lines
        
        # Show last N messages
        visible = self.messages[-height:] if len(self.messages) > height else self.messages
        
        for msg in visible:
            if msg["type"] == "user":
                content = msg["content"][:width - 6]
                lines.append(f"{G}› {W}{content}{RESET}")
            elif msg["type"] == "ai":
                for line in msg["content"].split("\n"):
                    if len(line) > width - 2:
                        line = line[:width - 5] + "..."
                    lines.append(f"{W}{line}{RESET}")
            elif msg["type"] == "system":
                lines.append(f"{DIM}{msg['content']}{RESET}")
        
        # Thinking indicator
        if self.is_thinking:
            frame_idx = self.frame % len(THINKING_FRAMES)
            lines.append(f"{C}{THINKING_FRAMES[frame_idx]} Thinking...{RESET}")
        
        return lines
    
    def _render_sidebar(self, width: int) -> list[str]:
        """Render the tools sidebar."""
        lines = []
        
        lines.append(f"{W}TOOLS{RESET}")
        lines.append(f"{BORDER}{'─' * (width - 2)}")
        
        with self.lock:
            for tool in TOOLS:
                name = tool.name
                status = self.tool_status.get(name, {})
                state = status.get("status", "idle")
                elapsed = status.get("elapsed")
                
                icons = {"idle": "○", "running": "◐", "done": "●", "error": "✗"}
                colors = {"idle": DIM, "running": Y, "done": G, "error": R}
                
                icon = icons.get(state, "○")
                color = colors.get(state, DIM)
                short_name = name.replace("get_", "").replace("run_", "").replace("check_", "")[:width - 8]
                
                if state == "done" and elapsed:
                    line = f"{color}{icon}{RESET} {short_name} {DIM}{elapsed:.1f}s"
                else:
                    line = f"{color}{icon}{RESET} {short_name}"
                
                lines.append(line)
        
        lines.append(f"{BORDER}{'─' * (width - 2)}")
        lines.append(f"{DIM}CVE: {self.cve_count:,}{RESET}")
        
        return lines
    
    def _render_input(self, width: int) -> list[str]:
        """Render the input line."""
        lines = []
        
        lines.append(f"{BORDER}{'─' * (width + 30)}")
        
        cursor = "▌" if self.frame % 40 < 20 else " "
        if self.current_input:
            display = self.current_input[:width - 2] if len(self.current_input) > width - 2 else self.current_input
            lines.append(f"{C}›{RESET} {W}{display}{C}{cursor}{RESET}")
        else:
            prompt = "enter target URL..." if not self.messages else "type message..."
            lines.append(f"{C}›{RESET} {DIM}{prompt}{C}{cursor}{RESET}")
        
        return lines
    
    def _render_statusbar(self, width: int, sidebar_w: int) -> list[str]:
        """Render the status bar."""
        lines = []
        
        status = f"{G}●{RESET} Ready" if not self.agent_running else f"{Y}◐{RESET} Running"
        help_text = f"{DIM}Ctrl+C: Quit | Ctrl+N: New | ↑↓: History{RESET}"
        
        lines.append(f"{BG}{' ' * width}")
        lines.append(f"{BG}{status}  {' ' * 20}{help_text}{' ' * (sidebar_w - 20)}{RESET}")
        
        return lines
    
    def send_message(self):
        """Send message to the agent."""
        user_input = self.current_input.strip()
        if not user_input or self.agent_running:
            return
        
        if user_input.lower() in ("exit", "quit"):
            self.running = False
            return
        
        with self.lock:
            self.command_history.append(user_input)
            self.history_index = len(self.command_history)
            self.current_input = ""
            self.messages.append({"type": "user", "content": user_input})
            
            if not self.current_target and "http" in user_input:
                self.current_target = user_input.split("//")[-1].split("/")[0]
            
            # Reset tool status
            for tool in TOOLS:
                self.tool_status[tool.name] = {
                    "status": "idle",
                    "input": "",
                    "preview": "",
                    "elapsed": None,
                    "error": None,
                }
        
        self.agent_running = True
        self.is_thinking = True
        self.agent_finished = False
        self.render()
        
        def run_agent():
            try:
                with self.lock:
                    msgs = [
                        {"role": m["type"], "content": m["content"]}
                        for m in self.messages if m["type"] in ("user", "ai")
                    ]
                    msgs.append({"role": "user", "content": user_input})
                
                handler = LiveProgressHandler(self)
                result = self.agent.invoke(
                    {"messages": msgs},
                    config={"callbacks": [handler]}
                )
                
                ai_msg = [
                    m for m in result["messages"]
                    if hasattr(m, "type") and m.type == "ai"
                ]
                if ai_msg:
                    response = ai_msg[-1].content
                    if isinstance(response, str):
                        with self.lock:
                            self.messages.append({"type": "ai", "content": response})
                            
                            # Auto-save report if report detected
                            if any(kw in response for kw in ["[REPORT]", "[RECON]", "Finding #", "Severity", "PENETRATION TEST"]):
                                target = user_input if "http" in user_input else (self.messages[0].get("content", "unknown") if self.messages else "unknown")
                                filepath = self.save_report(target, response)
                                self.messages.append({"type": "system", "content": f"✔ Report saved: {filepath}"})
                
                with self.lock:
                    self.agent_running = False
                    self.is_thinking = False
                
                self.render()
                
            except Exception as e:
                import traceback
                with self.lock:
                    error_msg = f"Error: {str(e)}"
                    self.messages.append({"type": "ai", "content": error_msg})
                    self.agent_running = False
                    self.is_thinking = False
                self.render()
        
        thread = threading.Thread(target=run_agent, daemon=True)
        thread.start()
    
    def run(self, agent):
        """Run the TUI with the given agent."""
        self.agent = agent
        
        print(term.clear, end="")
        
        # Welcome screen
        logo = f"""{G}
 ██╗   ██╗███████╗███████╗ ██████╗
 ██║   ██║██╔════╝██╔════╝██╔════╝
 ██║   ██║███████╗█████╗  ██║
 ╚██╗ ██╔╝╚════██║██╔══╝  ██║
  ╚████╔╝ ███████║███████╗╚██████╗
   ╚═══╝  ╚══════╝╚══════╝ ╚═════╝{RESET}

{C}    AI-Powered Penetration Testing{RESET}
{DIM}    Type 'exit' to quit{RESET}
"""
        print(logo)
        print(f"{DIM}Loading {len(TOOLS)} security tools...{RESET}")
        print(f"{DIM}CVE database: {self.cve_count:,} entries{RESET}")
        time.sleep(1)
        
        self.render()
        
        try:
            with term.cbreak(), term.hidden_cursor():
                while self.running:
                    key = term.inkey(timeout=0.05)
                    
                    if key:
                        kn = getattr(key, 'name', None)
                        kc = getattr(key, 'char', None)
                        
                        if kn == "KEY_ENTER":
                            self.send_message()
                        elif kn == "KEY_BACKSPACE":
                            with self.lock:
                                self.current_input = self.current_input[:-1]
                            self.render()
                        elif kn == "KEY_DELETE":
                            with self.lock:
                                self.current_input = ""
                            self.render()
                        elif kn == "KEY_UP":
                            with self.lock:
                                if self.command_history and self.history_index > 0:
                                    self.history_index -= 1
                                    self.current_input = self.command_history[self.history_index]
                            self.render()
                        elif kn == "KEY_DOWN":
                            with self.lock:
                                if self.history_index < len(self.command_history) - 1:
                                    self.history_index += 1
                                    self.current_input = self.command_history[self.history_index]
                                else:
                                    self.history_index = len(self.command_history)
                                    self.current_input = ""
                            self.render()
                        elif kn == "KEY_CONTROL_N":
                            with self.lock:
                                self.messages = []
                                self.current_target = None
                                self.command_history.clear()
                                self.history_index = -1
                                for tool in TOOLS:
                                    self.tool_status[tool.name] = {
                                        "status": "idle",
                                        "input": "",
                                        "preview": "",
                                        "elapsed": None,
                                        "error": None,
                                    }
                            self.render()
                        elif kn == "KEY_CONTROL_C":
                            self.running = False
                        elif kc:
                            with self.lock:
                                self.current_input += kc
                            self.render()
                        elif str(key).isprintable():
                            with self.lock:
                                self.current_input += str(key)
                            self.render()
                    
                    self.frame += 1
                    self.render()
                    time.sleep(0.05)
        
        except Exception as e:
            print(term.clear, end="")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        
        print(term.clear + term.normal_cursor(), end="")


def run_tui(agent):
    """Entry point for the TUI."""
    ui = VSecTerminalUI()
    ui.run(agent)
