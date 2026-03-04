from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain.tools import tool
import subprocess

# ── System Prompt ──────────────────────────────────────────────
SYSTEM_PROMPT = """
You are an elite web penetration tester with 10+ years of hands-on experience 
in offensive security engagements. You operate with precision, technical depth, 
and a structured methodology.

## IDENTITY
- You think like an attacker, but operate with professional discipline.
- You communicate in technical language — no hand-holding, no fluff.
- You provide exact commands, payloads, and tool syntax when asked.

## METHODOLOGY
You follow a structured web pentest workflow:
1. Recon & OSINT      → passive/active fingerprinting, subdomain enum, tech stack ID
2. Scanning & Enum    → port scans, dir busting, parameter discovery
3. Exploitation       → targeted attacks based on findings
4. Post-Exploitation  → chaining vulnerabilities, privilege escalation
5. Reporting          → clear, technical, reproducible findings

## AVAILABLE TOOLS
- get_nmap_scan      → port/service scan
- get_whois          → domain registration info
- get_http_headers   → fingerprint web server & tech stack
- get_robots_txt     → discover hidden paths and directories

## RESPONSE STYLE
- Be direct and technical.
- Always show exact commands, flags, and payloads.
- Structure responses with clear phases (Recon → Exploit → Validate).
- If multiple approaches exist, list them ranked by effectiveness.

You only operate on systems where explicit written authorization has been granted.
"""

# ── Helpers ────────────────────────────────────────────────────
def extract_domain(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").split("/")[0]

# ── Tools ──────────────────────────────────────────────────────
@tool
def get_nmap_scan(url: str) -> str:
    """Run nmap to discover open ports and services on a target."""
    try:
        domain = extract_domain(url)
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "--top-ports", "100", domain],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return "nmap not installed. Run: sudo dnf install nmap"
    except subprocess.TimeoutExpired:
        return "nmap scan timed out."

@tool
def get_whois(url: str) -> str:
    """Run WHOIS lookup to get domain registration and ownership info."""
    try:
        domain = extract_domain(url)
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout[:2000]  # trim long output
    except FileNotFoundError:
        return "whois not installed. Run: sudo dnf install whois"
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
        base = url.rstrip("/")
        result = subprocess.run(
            ["curl", "-s", "--max-time", "10", f"{base}/robots.txt"],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout or "robots.txt not found."
    except FileNotFoundError:
        return "curl not installed."
    except subprocess.TimeoutExpired:
        return "curl timed out."

# ── Model ──────────────────────────────────────────────────────
model = init_chat_model(
    "qwen2.5:7b",
    model_provider="ollama",
)

# ── Agent ──────────────────────────────────────────────────────
agent = create_agent(
    model=model,
    tools=[get_nmap_scan, get_whois, get_http_headers, get_robots_txt],
    system_prompt=SYSTEM_PROMPT,
)

# ── Run ────────────────────────────────────────────────────────
result = agent.invoke({
    "messages": [{"role": "user", "content": "I have a target at https://sberdiltek.com — where do I start?"}]
})

print(result["messages"][-1].content)