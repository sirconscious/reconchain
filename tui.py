#!/usr/bin/env python3
"""
VSec TUI - Claude Code-style terminal interface for pentest_agent.py
"""
import time
import threading
from collections import deque
from blessed import Terminal
from langchain_core.callbacks.base import BaseCallbackHandler

from pentest_agent import agent, TOOLS
from vsec.tools.defaults.cve import _CVE_TEXTS

term = Terminal()

RESET = "\033[0m"
GREEN = "\033[38;2;0;255;136m"
CYAN = "\033[38;2;88;166;255m"
YELLOW = "\033[38;2;240;165;0m"
RED = "\033[38;2;255;68;68m"
DIM = "\033[38;2;139;148;158m"
BG = "\033[48;2;13;17;23m"
BORDER = "\033[38;2;48;54;61m"
WHITE = "\033[38;2;201;209;217m"
MAGENTA = "\033[38;2;188;140;255m"

THINKING_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"]

TOOL_ICONS = {
    "get_dnsdumpster":    "🌐",
    "get_whois":          "📋",
    "get_http_headers":   "📡",
    "get_robots_txt":     "🤖",
    "get_nmap_scan":      "🔍",
    "check_common_paths":  "🚪",
    "run_gobuster_dirs":  "📂",
    "run_gobuster_subs":  "🌍",
    "detect_technologies":"🔬",
    "shell":              "💻",
    "retrieve_cve_info":  "🗄",
}

TOOL_COLORS = {
    "get_dnsdumpster":    CYAN,
    "get_whois":          CYAN,
    "get_http_headers":   CYAN,
    "get_robots_txt":     CYAN,
    "get_nmap_scan":      YELLOW,
    "check_common_paths":  YELLOW,
    "run_gobuster_dirs":  YELLOW,
    "run_gobuster_subs":  YELLOW,
    "detect_technologies":MAGENTA,
    "shell":              RED,
    "retrieve_cve_info":  YELLOW,
}


class SilentCallbackHandler(BaseCallbackHandler):
    def __init__(self, tui):
        self.tui = tui
        self.tool_start_time = None
        self.current_tool = None

    def on_tool_start(self, serialized, input_str, **kwargs):
        self.current_tool = serialized.get("name", "unknown")
        self.tool_start_time = time.time()
        self.tui.update_tool(self.current_tool, "running", input_str=str(input_str)[:60])

    def on_tool_end(self, output, **kwargs):
        if self.current_tool:
            elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
            lines = str(output).strip().splitlines()
            preview = lines[0][:80] if lines else "(empty)"
            self.tui.update_tool(self.current_tool, "done", elapsed=elapsed, preview=preview)
        self.current_tool = None
        self.tool_start_time = None

    def on_tool_error(self, error, **kwargs):
        if self.current_tool:
            self.tui.update_tool(self.current_tool, "error", error=str(error)[:100])
        self.current_tool = None

    def on_llm_start(self, *args, **kwargs):
        self.tui.set_thinking(True)

    def on_llm_end(self, *args, **kwargs):
        self.tui.set_thinking(False)


class VSecTUI:
    def __init__(self):
        self.messages = []
        self.tool_status = {}
        self.current_target = None
        self.running = True
        self.current_input = ""
        self.frame = 0
        self.is_thinking = False
        self.agent_running = False
        self.command_history = deque(maxlen=100)
        self.history_index = -1
        self.lock = threading.Lock()
        self.current_tool_name = None
        self.tool_start_time = None
        
        for tool in TOOLS:
            self.tool_status[tool.name] = {
                "status": "idle", 
                "input": "", 
                "preview": "", 
                "elapsed": None
            }
        
        self.cve_count = len(_CVE_TEXTS)

    def set_thinking(self, value):
        with self.lock:
            self.is_thinking = value

    def update_tool(self, name, status, **kwargs):
        with self.lock:
            if name in self.tool_status:
                self.tool_status[name]["status"] = status
                for k, v in kwargs.items():
                    self.tool_status[name][k] = v

    def render(self):
        w = max(term.width or 80, 80)
        sidebar_w = max(28, int(w * 0.22))
        chat_w = w - sidebar_w - 2
        
        lines = []
        lines.extend(self._render_header(w))
        lines.extend(self._render_chat(chat_w))
        lines.extend(self._render_sidebar(sidebar_w, chat_w + 1))
        lines.extend(self._render_input(chat_w))
        lines.extend(self._render_statusbar(w, sidebar_w))
        
        output = term.home + "\n".join(lines)
        print(output, end="", flush=True)

    def _render_header(self, w):
        lines = []
        target = self.current_target or "no target"
        status = f"{GREEN}●{RESET} Ready" if not self.agent_running else f"{YELLOW}◐{RESET} Running..."
        
        lines.append(f"{BG}{' ' * w}")
        lines.append(f"{BG}{GREEN} ██╗   ██╗{DIM}  {GREEN}VSec{RESET}  {DIM}{target}{RESET}  {status}{RESET}")
        lines.append(f"{BORDER}{'─' * w}")
        
        return lines

    def _render_chat(self, width):
        lines = []
        chat_h = term.height - 10
        
        if not self.messages:
            hint = "Enter a target URL to begin reconnaissance..."
            lines.append(f"{DIM}{hint}{RESET}")
            return lines
        
        visible = self.messages[-chat_h:] if len(self.messages) > chat_h else self.messages
        
        for msg in visible:
            if msg["type"] == "user":
                lines.append(f"{GREEN}› {WHITE}{msg['content']}{RESET}")
            elif msg["type"] == "ai":
                for line in msg["content"].split("\n"):
                    if len(line) > width:
                        line = line[:width-3] + "..."
                    lines.append(f"{WHITE}{line}{RESET}")
            elif msg["type"] == "tool":
                icon = msg.get("icon", "⚙")
                name = msg.get("tool", "tool")
                elapsed = msg.get("elapsed", 0)
                color = TOOL_COLORS.get(name, CYAN)
                lines.append(f"{color}{icon} {name}{RESET} {DIM}✓ {elapsed:.1f}s{RESET}")
        
        if self.is_thinking:
            frame_idx = self.frame % len(THINKING_FRAMES)
            thinking = THINKING_FRAMES[frame_idx]
            lines.append(f"{CYAN}{thinking} Thinking...{RESET}")
            
            if self.current_tool_name:
                icon = TOOL_ICONS.get(self.current_tool_name, "⚙")
                color = TOOL_COLORS.get(self.current_tool_name, CYAN)
                tool_input = self.tool_status.get(self.current_tool_name, {}).get("input", "")
                lines.append(f"{color}{icon} {self.current_tool_name}{RESET}")
                if tool_input:
                    lines.append(f"{DIM}  {tool_input[:40]}...{RESET}")
        
        return lines

    def _render_sidebar(self, sidebar_w, start_x):
        lines = []
        
        header_line = f"{WHITE}TOOLS{RESET}"
        lines.append(f"{' ' * start_x}{header_line}")
        lines.append(f"{' ' * start_x}{BORDER}{'─' * (sidebar_w - 2)}")
        
        y = 4
        with self.lock:
            for tool in TOOLS:
                name = tool.name
                status = self.tool_status.get(name, {})
                state = status.get("status", "idle")
                elapsed = status.get("elapsed")
                
                icons = {"idle": "○", "running": "◐", "done": "●", "error": "✗"}
                colors = {"idle": DIM, "running": YELLOW, "done": GREEN, "error": RED}
                
                icon = icons.get(state, "○")
                color = colors.get(state, DIM)
                short_name = name.replace("get_", "").replace("run_", "")[:sidebar_w - 8]
                
                if state == "done" and elapsed:
                    line = f"{' ' * start_x}{color}{icon}{RESET} {short_name} {DIM}{elapsed:.1f}s"
                else:
                    line = f"{' ' * start_x}{color}{icon}{RESET} {short_name}"
                
                lines.append(line)
                y += 1
                
                if state == "running":
                    preview = status.get("input", "")[:20]
                    if preview:
                        lines.append(f"{' ' * start_x}{DIM}  {preview}...{RESET}")
                        y += 1
        
        lines.append(f"{' ' * start_x}{BORDER}{'─' * (sidebar_w - 2)}")
        lines.append(f"{' ' * start_x}{DIM}CVE: {self.cve_count:,}{RESET}")
        
        return lines

    def _render_input(self, width):
        lines = []
        
        lines.append(f"{BORDER}{'─' * (width + 30)}")
        
        cursor = "▌" if self.frame % 40 < 20 else " "
        if self.current_input:
            display = self.current_input[:width-2] if len(self.current_input) > width-2 else self.current_input
            lines.append(f"{CYAN}›{RESET} {WHITE}{display}{CYAN}{cursor}{RESET}")
        else:
            lines.append(f"{CYAN}›{RESET} {DIM}enter target URL...{CYAN}{cursor}{RESET}")
        
        return lines

    def _render_statusbar(self, width, sidebar_w):
        lines = []
        
        status = f"{GREEN}●{RESET} Ready" if not self.agent_running else f"{YELLOW}◐{RESET} Running..."
        model = f"{DIM}Model: claude-haiku-4-5{RESET}"
        help_text = f"{DIM}Ctrl+C: Quit | Ctrl+N: New | ↑↓: History{RESET}"
        
        lines.append(f"{BG}{' ' * width}")
        lines.append(f"{BG}{status}  {model}  {' ' * (sidebar_w - 40)}{help_text}")
        
        return lines

    def send_message(self):
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
            
            for tool in TOOLS:
                self.tool_status[tool.name] = {
                    "status": "idle", 
                    "input": "", 
                    "preview": "", 
                    "elapsed": None
                }
        
        self.agent_running = True
        self.is_thinking = True
        self.current_tool_name = None
        self.render()
        
        def run_agent():
            try:
                with self.lock:
                    msgs = [
                        {"role": m["type"], "content": m["content"]} 
                        for m in self.messages if m["type"] in ("user", "ai")
                    ]
                    msgs.append({"role": "user", "content": user_input})
                
                handler = SilentCallbackHandler(self)
                result = agent.invoke(
                    {"messages": msgs}, 
                    config={"callbacks": [handler]}
                )
                
                ai_msg = [m for m in result["messages"] if hasattr(m, "type") and m.type == "ai"]
                if ai_msg:
                    response = ai_msg[-1].content
                    if isinstance(response, str):
                        with self.lock:
                            self.messages.append({"type": "ai", "content": response})
                
                self.agent_running = False
                self.is_thinking = False
                self.current_tool_name = None
                self.render()
                
            except Exception as e:
                import traceback
                traceback.print_exc()
                with self.lock:
                    self.messages.append({"type": "ai", "content": f"Error: {e}"})
                self.agent_running = False
                self.is_thinking = False
                self.current_tool_name = None
                self.render()
        
        t = threading.Thread(target=run_agent)
        t.start()

    def run(self):
        print(term.clear, end="")
        
        logo = f"""{GREEN}
 ██╗   ██╗███████╗███████╗ ██████╗
 ██║   ██║██╔════╝██╔════╝██╔════╝
 ██║   ██║███████╗█████╗  ██║
 ╚██╗ ██╔╝╚════██║██╔══╝  ██║
  ╚████╔╝ ███████║███████╗╚██████╗
   ╚═══╝  ╚══════╝╚══════╝ ╚═════╝{RESET}

{CYAN}    AI-Powered Penetration Testing Agent{RESET}
{DIM}    Phase 1 — Reconnaissance & OSINT{RESET}
"""
        print(logo)
        print(f"{DIM}Loading {len(TOOLS)} security tools...{RESET}")
        print(f"{DIM}CVE database: {self.cve_count:,} entries{RESET}")
        time.sleep(1.5)
        
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
                                        "elapsed": None
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


def run_tui():
    app = VSecTUI()
    app.run()


if __name__ == "__main__":
    run_tui()
