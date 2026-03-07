import os
import subprocess
import httpx
from dotenv import load_dotenv
from langchain.chat_models import init_chat_model

load_dotenv()

DNSDUMPSTER_API_KEY = os.getenv("DNSDumpster_API_KEY")

# ── System Prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are a senior offensive security engineer writing a formal penetration test report.
You have been given raw recon data. Your job is to analyze it — not repeat it back.

STRICT RULES:
- Every finding MUST have a PoC command. No exceptions.
- Do NOT write generic advice like "keep software updated".
- Be specific to THIS target. Reference actual IPs, headers, and paths found.
- If a finding has a known CVE, cite it.
- Severity:
    Critical = direct RCE or full data breach possible
    High     = significant data exposure or auth bypass
    Medium   = information disclosure or indirect risk
    Low      = minor misconfiguration, low exploitability

OUTPUT FORMAT — use EXACTLY this structure:

====================================================
PENETRATION TEST REPORT
Target   : <url>
Platform : <detected stack>
====================================================

[ATTACK SURFACE]
List every confirmed entry point with its IP / port / path.

[FINDINGS]
One block per finding:

  Finding #N
  Severity : Critical / High / Medium / Low
  Title    : <short name>
  Vector   : <exact attack path>
  PoC      : <exact command or payload>
  Impact   : <what the attacker gains>

[SUBDOMAINS & DNS RISKS]
Subdomain takeover candidates, exposed mail servers, DNS misconfigs.

[NEXT STEPS]
Numbered, ranked by ease of exploitation. Name the tool and exact flags.
"""

# ── Helpers ────────────────────────────────────────────────────────────────────
def _domain(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def _trim_whois(raw: str) -> str:
    """Keep only the useful WHOIS fields — strip boilerplate."""
    keywords = ["registrar", "name server", "creation", "expir",
                "registrant", "country", "org", "abuse", "updated"]
    lines = [l for l in raw.splitlines()
             if any(k in l.lower() for k in keywords) and l.strip()]
    return "\n".join(lines[:30])  # cap at 30 lines

# ── Recon Functions ────────────────────────────────────────────────────────────
def get_dnsdumpster(domain: str) -> str:
    if not DNSDUMPSTER_API_KEY:
        return "DNSDumpster API key missing — set DNSDumpster_API_KEY in .env"
    target = _domain(domain)
    try:
        with httpx.Client(timeout=20) as c:
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


def get_whois(url: str) -> str:
    try:
        r = subprocess.run(
            ["whois", _domain(url)],
            capture_output=True, text=True, timeout=20
        )
        return _trim_whois(r.stdout)
    except Exception as e:
        return str(e)


def get_headers(url: str) -> str:
    try:
        r = subprocess.run(
            ["curl", "-I", "-L", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout or r.stderr
    except Exception as e:
        return str(e)


def get_robots(url: str) -> str:
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", url.rstrip("/") + "/robots.txt"],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout or "robots.txt not found"
    except Exception as e:
        return str(e)


def get_nmap(url: str) -> str:
    try:
        r = subprocess.run(
            ["nmap", "-sV", "-F", "--open", _domain(url)],
            capture_output=True, text=True, timeout=60
        )
        return r.stdout or r.stderr
    except FileNotFoundError:
        return "nmap not installed — sudo apt/dnf install nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out"


def check_common_paths(url: str) -> str:
    """
    Probe generic high-value paths and record their HTTP status codes.
    No assumptions about the tech stack — works on any web target.
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
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "5", url.rstrip("/") + path],
                capture_output=True, text=True, timeout=8
            )
            code = r.stdout.strip()
            if code not in ("404", ""):
                results.append(f"  {code}  {path}")
        except Exception:
            pass
    return "\n".join(results) if results else "No interesting paths found"


# ── Model ──────────────────────────────────────────────────────────────────────
model = init_chat_model(
    "qwen2.5:3b",
    model_provider="ollama",
)

# ── Run ────────────────────────────────────────────────────────────────────────
target = "https://sberdiltek.com"

print("=" * 60)
print(f"[*] Target : {target}")
print("=" * 60)

print("[1/5] DNSDumpster...", flush=True)
dns = get_dnsdumpster(target)

print("[2/5] WHOIS...", flush=True)
whois = get_whois(target)

print("[3/5] HTTP Headers...", flush=True)
headers = get_headers(target)

print("[4/5] robots.txt...", flush=True)
robots = get_robots(target)

print("[5/5] Nmap...", flush=True)
scan = get_nmap(target)

print("[+] Probing common paths...", flush=True)
paths = check_common_paths(target)

print("\n[*] All recon done. Sending to LLM...\n")
print("=" * 60)

# ── Build analysis prompt ──────────────────────────────────────────────────────
analysis_prompt = f"""
You are analyzing a real target. Use the recon data below to write your report.
Do not summarize the data — analyze it and produce findings.

TARGET: {target}

--- DNS (DNSDumpster) ---
{dns}

--- WHOIS (key fields) ---
{whois}

--- HTTP RESPONSE HEADERS ---
{headers}

--- ROBOTS.TXT ---
{robots}

--- NMAP SCAN ---
{scan}

--- HTTP PATH PROBE (non-404 responses) ---
{paths}

Now write the full penetration test report following your format exactly.
"""

# ── LLM call (streaming) ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("PENETRATION TEST REPORT — GENERATING")
print("=" * 60 + "\n")

try:
    # stream=True prints each token as it arrives — no more blank waiting
    for chunk in model.stream([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": analysis_prompt},
    ]):
        print(chunk.content, end="", flush=True)
    print("\n")
except Exception as e:
    print(f"[!] LLM error: {e}")