#!/usr/bin/env python3
"""
VSec — AI-Powered Penetration Testing Framework
Main entry point for the CLI/TUI interface.
"""
import os
import sys
import time
import asyncio
import datetime
import argparse
import threading
from queue import Queue, Empty

from dotenv import load_dotenv
from colorama import Fore, Style, init as colorama_init
from langgraph.prebuilt import create_react_agent

from vsec.tools import TOOLS
from vsec.config import settings
from vsec.providers import (
    create_model,
    list_providers,
    get_provider_info,
    check_provider_config,
    get_default_provider,
)

colorama_init(autoreset=True)
load_dotenv()


# ════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
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
# AGENT SETUP
# ════════════════════════════════════════════════════════════════════════════════════
DEFAULT_TIMEOUT = 120


def _thinking_spinner(stop_event: threading.Event, message: str = "thinking"):
    """Display a thinking spinner while waiting."""
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        print(f"\r  {C}{spinner[i % len(spinner)]}{RS} {Y}{message}...{RS} ", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  {G}✔ done{RS}" + " " * 20 + "\n")


def invoke_with_timeout(agent, messages: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run agent.invoke() with timeout and progress indicator."""
    result_queue: Queue = Queue()
    error_queue: Queue = Queue()
    stop_event = threading.Event()

    def run_agent():
        try:
            result = agent.invoke(messages)
            result_queue.put(("success", result))
        except Exception as e:
            error_queue.put(("error", e))
        finally:
            stop_event.set()

    spinner_thread = threading.Thread(target=_thinking_spinner, args=(stop_event, "thinking"))
    agent_thread = threading.Thread(target=run_agent)

    print(f"  {C}◆{RS} Processing request... (timeout: {timeout}s)")
    spinner_thread.start()
    agent_thread.start()

    agent_thread.join(timeout=timeout)

    if agent_thread.is_alive():
        stop_event.set()
        spinner_thread.join(timeout=1)
        raise TimeoutError(f"Request timed out after {timeout} seconds")

    spinner_thread.join(timeout=0.5)
    stop_event.set()

    if not result_queue.empty():
        status, result = result_queue.get()
        if status == "success":
            return result

    if not error_queue.empty():
        status, error = error_queue.get()
        raise error

    raise RuntimeError("Agent returned no result")


def create_agent(provider: str | None = None, model: str | None = None):
    """Create the LangChain agent with specified or default provider."""
    # Use config settings if not specified
    if provider is None:
        provider = settings.provider
    if model is None:
        model = settings.model
    
    # Create model using provider
    llm = create_model(provider=provider, model=model)
    
    # Get model info for display
    provider_info = get_provider_info(provider)
    display_model = model or provider_info.default_model if provider_info else "unknown"
    
    return create_react_agent(llm, TOOLS, prompt=SYSTEM_PROMPT), display_model


def save_report(target: str, content: str) -> str:
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


# ════════════════════════════════════════════════════════════════════════════════════
# PROVIDER INFO DISPLAY
# ════════════════════════════════════════════════════════════════════════════════════
def print_provider_status():
    """Print the status of all configured providers."""
    print(f"\n  {Y}Available Providers:{RS}")
    
    providers = list_providers()
    for p in providers:
        check = check_provider_config(p.name)
        status = f"{G}✓ configured{RS}" if check["available"] else f"{R}✗ {check['reason']}{RS}"
        models = ", ".join(check.get("models", [])[:3])
        if len(check.get("models", [])) > 3:
            models += "..."
        print(f"  {DIM}  {p.name:12}{RS} {p.display_name:20} {status}")
        print(f"  {DIM}           Models: {models}{RS}")
        print()


# ════════════════════════════════════════════════════════════════════════════════════
# CLI MODE
# ════════════════════════════════════════════════════════════════════════════════════
def run_cli(agent, model_name: str, timeout: int = DEFAULT_TIMEOUT):
    """Run simple CLI mode."""
    print(BANNER)
    print(DIV)
    
    # Show provider info
    provider = settings.provider
    provider_info = get_provider_info(provider)
    display_name = provider_info.display_name if provider_info else provider
    
    print(f"  {C}◆{RS} Initializing agent...", flush=True)
    print(f"  {G}✔{RS} Provider: {B}{display_name}{RS}")
    print(f"  {G}✔{RS} Model   : {B}{model_name}{RS}")
    print(f"  {G}✔{RS} Tools   : {B}{len(TOOLS)} active{RS}")
    print(f"  {G}✔{RS} Status  : {G}{B}ready{RS}")
    print(DIV)
    
    print_provider_status()
    
    print(f"\n  {Y}commands:{RS}")
    print(f"  {DIM}  new    → fresh engagement{RS}")
    print(f"  {DIM}  exit   → quit VSec{RS}")
    print(f"  {DIM}  --tui  → launch modern TUI interface{RS}")
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
            result = invoke_with_timeout(agent, {"messages": messages}, timeout=timeout)

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

        except TimeoutError as e:
            print(f"\n  {Y}⚠ Timeout: {e}{RS}")
            print(f"  {DIM}Try again or use a faster model/provider.{RS}\n")
        except Exception as e:
            if "429" in str(e):
                print(f"\n  {R}✗ Rate limited. Waiting 30s...{RS}\n")
                time.sleep(30)
                print(f"  {C}{B}VSec >{RS} Ready. Repeat your last message.\n")
            else:
                print(f"\n  {R}✗ Error: {e}{RS}\n")


# ════════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════════
def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="VSec — AI-Powered Penetration Testing")
    parser.add_argument("--tui", action="store_true", help="Launch modern TUI interface")
    parser.add_argument("--cli", action="store_true", help="Launch CLI interface (default)")
    parser.add_argument("--model", "-m", type=str, default="claude-haiku-4-5", help="Model name (default: claude-haiku-4-5)")
    parser.add_argument("--provider", "-p", type=str, default="anthropic", help="AI provider (default: anthropic)")
    parser.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--list-providers", action="store_true", help="List available providers")
    args = parser.parse_args()
    
    # List providers and exit
    if args.list_providers:
        print(BANNER)
        print_provider_status()
        return
    
    # Create agent
    try:
        agent, model_name = create_agent(
            provider=args.provider,
            model=args.model
        )
    except ValueError as e:
        print(f"\n  {R}✗ {e}{RS}\n")
        print(f"  {DIM}Use --list-providers to see available options{RS}\n")
        sys.exit(1)
    
    # Run appropriate interface
    if args.tui:
        try:
            from vsec.ui import run_tui
            run_tui(agent)
        except ImportError as e:
            print(f"  {R}✗ TUI error: {e}{RS}")
            print(f"  {DIM}Falling back to CLI mode...{RS}")
            run_cli(agent, model_name, timeout=args.timeout)
    else:
        run_cli(agent, model_name, timeout=args.timeout)


if __name__ == "__main__":
    main()
