import os
import subprocess
import httpx
import time
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain.tools import tool

load_dotenv()

DNSDUMPSTER_API_KEY = os.getenv("DNSDumpster_API_KEY")
WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "common.txt")
WORDLIST_SUB = os.path.join(os.path.dirname(__file__), "subdomains.txt")

# ── System Prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are an elite web penetration tester with 10+ years of hands-on experience.
You are running in interactive mode — the user will give you targets and instructions conversationally.

METHODOLOGY (follow in order unless told otherwise):
1. Recon & OSINT      → DNSDumpster first, then WHOIS, HTTP headers, robots.txt, Wappalyzer
2. Scanning & Enum    → nmap port/service scan, path probe, gobuster dirs & subdomains
3. Exploitation       → targeted attacks based on findings
4. Reporting          → severity-tagged, reproducible findings

RULES:
- Be direct and technical. Exact commands, flags, payloads.
- Prefix each phase: [RECON] [SCAN] [EXPLOIT] [REPORT]
- Rank findings: Critical → High → Medium → Low
- You MUST call every relevant tool before writing the report.
- Only operate on systems with explicit written authorization.
- When the user gives you a target, start recon immediately without asking for permission.
- After each phase, summarize what you found and ask if they want to continue to the next phase.
"""

# ── Helpers ────────────────────────────────────────────────────────────────────
def _domain(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def _trim_whois(raw: str) -> str:
    keywords = ["registrar", "name server", "creation", "expir",
                "registrant", "country", "org", "abuse", "updated"]
    lines = [l for l in raw.splitlines()
             if any(k in l.lower() for k in keywords) and l.strip()]
    return "\n".join(lines[:30])

# ── Tools ──────────────────────────────────────────────────────────────────────
@tool
def get_dnsdumpster(domain: str) -> str:
    """Query DNSDumpster API for DNS recon: A, MX, NS, TXT records and subdomains. Use this FIRST."""
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
                host = s.get("host") or s.get("name") or ""
                ip   = s.get("ip", "")
                lines.append(f"  {host}  {ip}".strip())
        return "\n".join(lines)
    except Exception as e:
        return f"DNSDumpster error: {e}"


@tool
def get_whois(url: str) -> str:
    """WHOIS lookup: registrar, name servers, registration dates, org info."""
    try:
        r = subprocess.run(["whois", _domain(url)],
                           capture_output=True, text=True, timeout=20)
        return _trim_whois(r.stdout)
    except Exception as e:
        return str(e)


@tool
def get_http_headers(url: str) -> str:
    """Fetch HTTP response headers: server banner, CDN, security headers, framework leaks."""
    try:
        r = subprocess.run(["curl", "-I", "-L", "--max-time", "10", url],
                           capture_output=True, text=True, timeout=15)
        return r.stdout or r.stderr
    except Exception as e:
        return str(e)


@tool
def get_robots_txt(url: str) -> str:
    """Fetch robots.txt to discover hidden paths, admin panels, sensitive endpoints."""
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", url.rstrip("/") + "/robots.txt"],
            capture_output=True, text=True, timeout=15)
        return r.stdout or "robots.txt not found."
    except Exception as e:
        return str(e)


@tool
def get_nmap_scan(url: str) -> str:
    """nmap -sV fast scan: open ports, service versions, OS hints."""
    try:
        r = subprocess.run(
            ["nmap", "-sV", "-F", "--open", _domain(url)],
            capture_output=True, text=True, timeout=60)
        return r.stdout or r.stderr
    except FileNotFoundError:
        return "nmap not installed — sudo dnf install nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out"


@tool
def check_common_paths(url: str) -> str:
    """
    Probe high-value paths: /.env, /.git/HEAD, /admin, /api, /swagger, /actuator etc.
    Returns HTTP status codes and body preview for 200 responses.
    """
    paths = [
        "/admin", "/login", "/dashboard", "/api", "/api/v1", "/api/v2",
        "/swagger", "/swagger-ui.html", "/openapi.json", "/graphql",
        "/.git/HEAD", "/.env", "/config", "/backup", "/uploads",
        "/wp-admin", "/phpinfo.php", "/server-status", "/actuator",
        "/actuator/env", "/actuator/health", "/console", "/debug",
        "/metrics", "/status", "/.well-known/security.txt",
    ]
    results = []
    for path in paths:
        try:
            code_r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "5", url.rstrip("/") + path],
                capture_output=True, text=True, timeout=8)
            code = code_r.stdout.strip()
            if code in ("404", ""):
                continue
            line = f"  {code}  {path}"
            if code == "200":
                body_r = subprocess.run(
                    ["curl", "-s", "--max-time", "5", url.rstrip("/") + path],
                    capture_output=True, text=True, timeout=8)
                body = body_r.stdout.strip()[:300]
                if body:
                    line += f"\n         BODY: {body}"
            results.append(line)
        except Exception:
            pass
    return "\n".join(results) if results else "No interesting paths found"


@tool
def run_gobuster_dirs(url: str) -> str:
    """
    Directory fuzzing with gobuster dir.
    Discovers hidden directories and files on the target web server.
    """
    if not os.path.exists(WORDLIST_DIR):
        return f"Wordlist not found: {WORDLIST_DIR}"
    try:
        r = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", WORDLIST_DIR,
             "-t", "20", "-q", "--no-error", "-o", "/tmp/gobuster_dirs.txt"],
            capture_output=True, text=True, timeout=120)
        if os.path.exists("/tmp/gobuster_dirs.txt"):
            with open("/tmp/gobuster_dirs.txt") as f:
                out = f.read().strip()
            if out:
                return out
        return r.stdout.strip() or "No directories found"
    except FileNotFoundError:
        return "gobuster not installed — sudo dnf install gobuster"
    except subprocess.TimeoutExpired:
        if os.path.exists("/tmp/gobuster_dirs.txt"):
            with open("/tmp/gobuster_dirs.txt") as f:
                return f.read().strip() or "gobuster timed out"
        return "gobuster timed out"


@tool
def run_gobuster_subs(url: str) -> str:
    """
    Subdomain fuzzing with gobuster dns.
    Discovers subdomains of the target domain.
    """
    if not os.path.exists(WORDLIST_SUB):
        return f"Subdomain wordlist not found: {WORDLIST_SUB}"
    domain = _domain(url)
    try:
        r = subprocess.run(
            ["gobuster", "dns", "-d", domain, "-w", WORDLIST_SUB,
             "-t", "20", "-q", "--no-error", "-o", "/tmp/gobuster_subs.txt"],
            capture_output=True, text=True, timeout=120)
        if os.path.exists("/tmp/gobuster_subs.txt"):
            with open("/tmp/gobuster_subs.txt") as f:
                out = f.read().strip()
            if out:
                return out
        return r.stdout.strip() or "No subdomains found"
    except FileNotFoundError:
        return "gobuster not installed — sudo dnf install gobuster"
    except subprocess.TimeoutExpired:
        if os.path.exists("/tmp/gobuster_subs.txt"):
            with open("/tmp/gobuster_subs.txt") as f:
                return f.read().strip() or "gobuster timed out"
        return "gobuster timed out"


@tool
def detect_technologies(url: str) -> str:
    """
    Detect technologies, frameworks, and CMS used by the target.
    Tries webanalyze, then wappalyzer CLI, then falls back to header parsing.
    """
    for cmd in [
        ["webanalyze", "-host", url, "-output", "json"],
        ["wappalyzer", url],
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()[:2000]
        except FileNotFoundError:
            continue

    # Header-based fallback
    try:
        r = subprocess.run(["curl", "-sI", "--max-time", "10", url],
                           capture_output=True, text=True, timeout=15)
        techs = []
        checks = {
            "x-powered-by": "Runtime/Framework",
            "x-shopify":    "Shopify",
            "x-wp-":        "WordPress",
            "x-drupal":     "Drupal",
            "x-magento":    "Magento",
            "x-laravel":    "Laravel",
            "x-aspnet":     "ASP.NET",
            "cloudflare":   "Cloudflare CDN/WAF",
            "server: nginx":"nginx",
            "server: apache":"Apache",
            "server: iis":  "IIS",
        }
        for key, label in checks.items():
            if key in r.stdout.lower():
                for line in r.stdout.splitlines():
                    if key.lower() in line.lower():
                        techs.append(f"  {label}: {line.strip()}")
                        break
        return "\n".join(techs) if techs else "No technologies detected"
    except Exception as e:
        return f"Tech detection error: {e}"


# ── Model with fallback ────────────────────────────────────────────────────────
FREE_MODELS = [
    "google/gemma-3-27b-it:free",
    "openai/gpt-oss-120b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
]

def get_model():
    for name in FREE_MODELS:
        try:
            m = ChatOpenAI(
                model=name,
                openai_api_key=os.getenv("OPENROUTER_API_KEY"),
                openai_api_base="https://openrouter.ai/api/v1",
                temperature=0,
                max_tokens=4096,
                default_headers={
                    "HTTP-Referer": "https://pentest-agent.local",
                    "X-Title": "Pentest Agent",
                },
            )
            m.invoke([{"role": "user", "content": "hi"}])
            print(f"[+] Model: {name}")
            return m
        except Exception as e:
            if "429" in str(e) or "rate" in str(e).lower():
                print(f"[-] {name} rate limited, trying next...")
                time.sleep(2)
            else:
                raise
    raise Exception("All free models rate limited. Try again in a few minutes.")

# ── Agent ──────────────────────────────────────────────────────────────────────
print("\n[*] Connecting to OpenRouter...", flush=True)
model = get_model()

agent = create_agent(
    model=model,
    tools=[
        get_dnsdumpster,
        get_whois,
        get_http_headers,
        get_robots_txt,
        get_nmap_scan,
        check_common_paths,
        run_gobuster_dirs,
        run_gobuster_subs,
        detect_technologies,
    ],
    system_prompt=SYSTEM_PROMPT,
)

# ── Interactive Chat Loop ──────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  PENTEST AGENT — Interactive Mode")
print("  Type 'exit' or 'quit' to stop")
print("  Type 'new' to start a fresh engagement")
print("=" * 60)

messages = []

# Greet the user
print("\nAgent: What target would you like to assess? (provide full URL or domain)\n")

while True:
    try:
        user_input = input("You: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n[*] Exiting. Goodbye.")
        break

    if not user_input:
        continue

    if user_input.lower() in ("exit", "quit"):
        print("\n[*] Exiting. Goodbye.")
        break

    if user_input.lower() == "new":
        messages = []
        print("\n[*] Conversation cleared. New engagement started.")
        print("Agent: What target would you like to assess?\n")
        continue

    # Add user message to history
    messages.append({"role": "user", "content": user_input})

    try:
        result = agent.invoke({"messages": messages})

        # Get the last assistant message
        response = result["messages"][-1].content
        print(f"\nAgent: {response}\n")

        # Keep full message history for context
        messages = [m for m in result["messages"]
                    if hasattr(m, "type") and m.type in ("human", "ai")]
        # Fallback if .type not available
        if not messages:
            messages.append({"role": "assistant", "content": response})

    except Exception as e:
        if "429" in str(e):
            print(f"\n[!] Rate limited. Waiting 30 seconds...\n")
            time.sleep(30)
            print("Agent: Ready. Please repeat your last message.\n")
        else:
            print(f"\n[!] Error: {e}\n")