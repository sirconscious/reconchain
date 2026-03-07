import os
import subprocess
import httpx
from dotenv import load_dotenv

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain.tools import tool

load_dotenv()

DNSDUMPSTER_API_KEY = os.getenv("DNSDumpster_API_KEY")

# ── System Prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are an elite web penetration tester with 10+ years of hands-on experience.

METHODOLOGY (follow in order):
1. Recon & OSINT      → run DNSDumpster first, then WHOIS, HTTP headers, robots.txt
2. Scanning & Enum    → nmap port/service scan
3. Exploitation       → targeted attacks based on findings
4. Reporting          → severity-tagged, reproducible findings

RULES:
- Be direct and technical. Exact commands, flags, payloads.
- Prefix each phase: [RECON] [SCAN] [EXPLOIT] [REPORT]
- Rank findings: Critical → High → Medium → Low
- Only operate on systems with explicit written authorization.
"- You MUST call every tool before writing the report. Never skip a tool."
"""

# ── Helpers ────────────────────────────────────────────────────────────────────
def _domain(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").split("/")[0]

# ── Tools ──────────────────────────────────────────────────────────────────────
@tool
def get_dnsdumpster(domain: str) -> str:
    """Query DNSDumpster for DNS recon: A, MX, NS, TXT records and subdomains. Use this FIRST."""
    if not DNSDUMPSTER_API_KEY:
        return "DNSDumpster_API_KEY not set in .env"
    target = _domain(domain)
    try:
        with httpx.Client(timeout=30) as c:
            r = c.get(
                f"https://api.dnsdumpster.com/domain/{target}",
                headers={"X-API-Key": DNSDUMPSTER_API_KEY},
            )
        if r.status_code == 401: return "DNSDumpster: bad API key"
        if r.status_code == 429: return "DNSDumpster: rate limited"
        if r.status_code != 200: return f"DNSDumpster: HTTP {r.status_code}"
        data = r.json()
        lines = [f"=== DNSDumpster: {target} ==="]
        for section in ["a", "mx", "ns"]:
            recs = data.get(section, [])
            if recs:
                lines.append(f"\n[{section.upper()}]")
                for rec in recs:
                    host = rec.get("host") or rec.get("name") or ""
                    ip   = rec.get("ip", "")
                    asn  = rec.get("asn", "")
                    lines.append(f"  {host}  {ip}  {asn}".strip())
        txt = data.get("txt", [])
        if txt:
            lines.append("\n[TXT]")
            for t in txt:
                lines.append(f"  {t.get('value') or t}")
        subs = data.get("dns_records", {}).get("host", []) or data.get("subdomains", [])
        if subs:
            lines.append("\n[SUBDOMAINS]")
            for s in subs:
                lines.append(f"  {s.get('host') or s.get('name') or ''}  {s.get('ip', '')}".strip())
        return "\n".join(lines)
    except Exception as e:
        return f"DNSDumpster error: {e}"


@tool
def get_nmap_scan(url: str) -> str:
    """Run nmap to discover open ports and services on a target."""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "--top-ports", "100", _domain(url)],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return "nmap not installed — sudo apt/dnf install nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out."


@tool
def get_whois(url: str) -> str:
    """Run WHOIS lookup to get domain registration and ownership info."""
    try:
        result = subprocess.run(
            ["whois", _domain(url)],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout[:2000]
    except FileNotFoundError:
        return "whois not installed — sudo apt/dnf install whois"
    except subprocess.TimeoutExpired:
        return "whois timed out."


@tool
def get_http_headers(url: str) -> str:
    """Fetch HTTP response headers to fingerprint web server and tech stack."""
    try:
        result = subprocess.run(
            ["curl", "-I", "-L", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return "curl not installed."
    except subprocess.TimeoutExpired:
        return "curl timed out."


@tool
def get_robots_txt(url: str) -> str:
    """Fetch robots.txt to discover hidden paths and directories."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "10", url.rstrip("/") + "/robots.txt"],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout or "robots.txt not found."
    except FileNotFoundError:
        return "curl not installed."
    except subprocess.TimeoutExpired:
        return "curl timed out."


# ── Model ──────────────────────────────────────────────────────────────────────
model = init_chat_model(
    "qwen2.5:7b",
            model_provider="ollama",
)

# ── Agent ──────────────────────────────────────────────────────────────────────
agent = create_agent(
    model=model,
    tools=[get_dnsdumpster, get_nmap_scan, get_whois, get_http_headers, get_robots_txt],
    system_prompt=SYSTEM_PROMPT,
)

# ── Run ────────────────────────────────────────────────────────────────────────
# Replace the bottom of your script with this:
try:
    result = agent.invoke({
        "messages": [{
            "role": "user",
            "content": (
                "Target: https://sberdiltek.com\n"
                "Run these tools in order:\n"
                "1) get_dnsdumpster\n"
                "2) get_whois\n"
                "3) get_http_headers\n"
                "4) get_robots_txt\n"
                "5) get_nmap_scan\n"
                "After all tools run, write a concise pentest report."
            )
        }]
    })
    print(result["messages"][-1].content)
except Exception as e:
    print(f"ERROR: {e}")
