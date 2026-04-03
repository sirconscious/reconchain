#!/usr/bin/env python3
"""
VSec Main Entry Point — AI-Powered Penetration Testing Framework
"""
import os
import sys
import time
import datetime
import argparse

from dotenv import load_dotenv
from colorama import Fore, Style, init as colorama_init
from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks.base import BaseCallbackHandler
from langgraph.prebuilt import create_react_agent

from vsec.tools import TOOLS
from vsec.config import settings

colorama_init(autoreset=True)
load_dotenv()


# ════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS: Colors
# ════════════════════════════════════════════════════════════════════════════════════
G   = Fore.GREEN
C   = Fore.CYAN
Y   = Fore.YELLOW
R   = Fore.RED
M   = Fore.MAGENTA
W   = Fore.WHITE
DIM = Style.DIM
B   = Style.BRIGHT
RS  = Style.RESET_ALL


# ════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS: UI Elements
# ════════════════════════════════════════════════════════════════════════════════════
BANNER = f"""
{G}{B}
 ██╗   ██╗███████╗███████╗ ██████╗
 ██║   ██║██╔════╝██╔════╝██╔════╝
 ██║   ██║███████╗█████╗  ██║
 ╚██╗ ██╔╝╚════██║██╔══╝  ██║
  ╚████╔╝ ███████║███████╗╚██████╗
   ╚═══╝  ╚══════╝╚══════╝ ╚═════╝{RS}
{C}        AI-Powered Penetration Testing Agent{RS}
{DIM}        Phase 1 — Reconnaissance & OSINT{RS}
"""

DIV  = f"{G}{DIM}{'─' * 60}{RS}"
DIV2 = f"{G}{'━' * 60}{RS}"


# ════════════════════════════════════════════════════════════════════════════════════
# CALLBACKS
# ════════════════════════════════════════════════════════════════════════════════════
TOOL_ICONS = {
    "get_dnsdumpster":     ("🌐", C),
    "get_whois":           ("📋", C),
    "get_http_headers":    ("📡", C),
    "get_robots_txt":      ("🤖", C),
    "get_nmap_scan":       ("🔍", Y),
    "check_common_paths":   ("🚪", Y),
    "run_gobuster_dirs":   ("📂", Y),
    "run_gobuster_subs":   ("🌍", Y),
    "detect_technologies": ("🔬", M),
    "shell":              ("💻", R),
    "retrieve_cve_info":   ("🗄", Y),
}


class LiveProgressHandler(BaseCallbackHandler):
    def __init__(self):
        self.tool_start_time = None
        self.step = 0

    def _ts(self) -> str:
        return f"{DIM}{datetime.datetime.now().strftime('%H:%M:%S')}{RS}"

    def on_llm_start(self, *args, **kwargs):
        print(f"  {self._ts()} {M}◆{RS} {DIM}reasoning...{RS}", flush=True)

    def on_tool_start(self, serialized, input_str, **kwargs):
        self.tool_start_time = time.time()
        self.step += 1
        name = serialized.get("name", "unknown_tool")
        icon, color = TOOL_ICONS.get(name, ("⚙", W))
        print(f"\n  {self._ts()} {color}{B}{icon} [{self.step}] {name}{RS}", flush=True)
        print(f"  {DIM}           ↳ {str(input_str)[:80]}{RS}", flush=True)

    def on_tool_end(self, output, **kwargs):
        elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
        lines = str(output).strip().splitlines()
        preview = lines[0][:80] if lines else "(empty)"
        print(f"  {DIM}           ✓ {elapsed:.1f}s  {G}{preview}{RS}", flush=True)

    def on_tool_error(self, error, **kwargs):
        elapsed = time.time() - self.tool_start_time if self.tool_start_time else 0
        print(f"  {DIM}           {R}✗ {elapsed:.1f}s  {str(error)[:80]}{RS}", flush=True)

    def on_agent_finish(self, finish, **kwargs):
        print(f"\n  {self._ts()} {G}{B}✔ scan complete{RS}\n", flush=True)


# ════════════════════════════════════════════════════════════════════════════════════
# PROMPTS
# ════════════════════════════════════════════════════════════════════════════════════
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


# ════════════════════════════════════════════════════════════════════════════════════
# UTILS: Helpers
# ════════════════════════════════════════════════════════════════════════════════════
def save_report(target: str, content: str) -> str:
    """Save report to reports/ folder with timestamp."""
    os.makedirs(settings.reports_dir, exist_ok=True)
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.md"
    filepath = settings.reports_dir / filename
    with open(filepath, "w") as f:
        f.write(f"VSec Penetration Test Report\n")
        f.write(f"Target    : {target}\n")
        f.write(f"Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(content)
    return str(filepath)


# ════════════════════════════════════════════════════════════════════════════════════
# AGENT SETUP
# ════════════════════════════════════════════════════════════════════════════════════
model = ChatAnthropic(
    model="claude-haiku-4-5",
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
    temperature=0,
    max_tokens=4096,
)

agent = create_react_agent(model, TOOLS, prompt=SYSTEM_PROMPT)


# ════════════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════════
def run_cli():
    """Run the interactive CLI."""
    print(BANNER)
    print(DIV)
    print(f"  {C}◆{RS} Connecting to Anthropic API...", flush=True)
    print(f"  {G}✔{RS} Model   : {B}claude-haiku-4-5{RS}")
    print(f"  {G}✔{RS} Tools   : {B}{len(TOOLS)} active{RS}")
    print(f"  {G}✔{RS} Status  : {G}{B}ready{RS}")
    print(DIV)
    print(f"\n  {Y}commands:{RS}")
    print(f"  {DIM}  new   → fresh engagement{RS}")
    print(f"  {DIM}  exit  → quit VSec{RS}")
    print(f"  {DIM}  --tui → launch modern TUI interface{RS}")
    print(DIV2)

    messages = []
    print(f"\n  {C}{B}VSec >{RS} What target would you like to assess?\n")

    while True:
        try:
            user_input = input(f"  {G}{B}you   >{RS} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {Y}Goodbye.{RS}\n")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print(f"\n  {Y}Goodbye.{RS}\n")
            break

        if user_input.lower() == "new":
            messages = []
            print(DIV)
            print(f"  {C}◆ New engagement started.{RS}")
            print(DIV)
            print(f"\n  {C}{B}VSec >{RS} What target would you like to assess?\n")
            continue

        messages.append({"role": "user", "content": user_input})
        print(DIV)

        try:
            result = agent.invoke(
                {"messages": messages},
                config={"callbacks": [LiveProgressHandler()]},
            )

            ai_messages = [
                m for m in result["messages"]
                if hasattr(m, "content") and m.type == "ai"
            ]
            response = ai_messages[-1].content if ai_messages else str(result["messages"][-1].content)

            print(DIV)
            print(f"\n  {C}{B}VSec >{RS}\n")
            for line in response.splitlines():
                print(f"  {line}")
            print()

            if any(kw in response for kw in ["[REPORT]", "[RECON]", "Finding #", "Severity", "PENETRATION TEST"]):
                filepath = save_report(
                    user_input if "http" in user_input else messages[0].get("content", "unknown"),
                    response
                )
                print(f"  {G}✔ Report saved →{RS} {DIM}{filepath}{RS}\n")

            messages = [
                {"role": "user" if m.type == "human" else "assistant", "content": m.content}
                for m in result["messages"]
                if hasattr(m, "type") and m.type in ("human", "ai")
                and isinstance(m.content, str)
            ]

        except Exception as e:
            if "429" in str(e):
                print(f"\n  {R}✗ Rate limited. Waiting 30s...{RS}\n")
                time.sleep(30)
                print(f"  {C}{B}VSec >{RS} Ready. Repeat your last message.\n")
            else:
                print(f"\n  {R}✗ Error: {e}{RS}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="VSec — AI-Powered Penetration Testing")
    parser.add_argument("--tui", action="store_true", help="Launch TUI interface")
    args = parser.parse_args()
    
    if args.tui:
        try:
            from vsec_tui import run_tui
            run_tui()
        except ImportError:
            print(f"  {R}✗ TUI module not found. Run: pip install blessed{RS}")
    else:
        run_cli()


if __name__ == "__main__":
    main()
