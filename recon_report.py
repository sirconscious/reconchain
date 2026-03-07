import os
import subprocess
import httpx
from dotenv import load_dotenv
from langchain.chat_models import init_chat_model

load_dotenv()

DNSDUMPSTER_API_KEY = os.getenv("DNSDumpster_API_KEY")

# Wordlist paths — adjust if yours are somewhere else
# ── Wordlists ──────────────────────────────────────────────────────────────────
DIR_WORDLIST = os.path.join(os.path.dirname(__file__), "common.txt")
SUB_WORDLIST = os.path.join(os.path.dirname(__file__), "subdomains.txt")

# ── System Prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are a senior offensive security engineer writing a formal penetration test report.
You have been given raw recon data. Your job is to analyze it — not repeat it back.

STRICT RULES:
- Every finding MUST have a PoC command. No exceptions.
- Do NOT write generic advice like "keep software updated".
- Be specific to THIS target. Reference actual IPs, headers, paths, and technologies found.
- If a finding has a known CVE, cite it.
- Cross-reference technologies detected by Wappalyzer with known CVEs or attack vectors.
- Severity:
    Critical = direct RCE or full data breach possible
    High     = significant data exposure or auth bypass
    Medium   = information disclosure or indirect risk
    Low      = minor misconfiguration, low exploitability

OUTPUT FORMAT — use EXACTLY this structure:

====================================================
PENETRATION TEST REPORT
Target   : <url>
Platform : <detected stack from Wappalyzer>
====================================================

[ATTACK SURFACE]
List every confirmed entry point with its IP / port / path.

[TECHNOLOGY ANALYSIS]
For each detected technology:
  - Version (if known) → known CVEs or attack vectors
  - Specific exploitation angle for THIS target

[FINDINGS]
One block per finding:

  Finding #N
  Severity : Critical / High / Medium / Low
  Title    : <short name>
  Vector   : <exact attack path>
  PoC      : <exact command or payload>
  Impact   : <what the attacker gains>

[FUZZING RESULTS]
Notable directories and subdomains discovered.
Flag anything that looks like admin, API, backup, or login surfaces.

[SUBDOMAINS & DNS RISKS]
Subdomain takeover candidates, exposed mail servers, DNS misconfigs.

[NEXT STEPS]
Numbered, ranked by ease of exploitation. Name the tool and exact flags.
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
        r = subprocess.run(["whois", _domain(url)],
                           capture_output=True, text=True, timeout=20)
        return _trim_whois(r.stdout)
    except Exception as e:
        return str(e)


def get_headers(url: str) -> str:
    try:
        r = subprocess.run(["curl", "-I", "-L", "--max-time", "10", url],
                           capture_output=True, text=True, timeout=15)
        return r.stdout or r.stderr
    except Exception as e:
        return str(e)


def get_robots(url: str) -> str:
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", url.rstrip("/") + "/robots.txt"],
            capture_output=True, text=True, timeout=15)
        return r.stdout or "robots.txt not found"
    except Exception as e:
        return str(e)


def get_nmap(url: str) -> str:
    try:
        r = subprocess.run(
            ["nmap", "-sV", "-F", "--open", _domain(url)],
            capture_output=True, text=True, timeout=60)
        return r.stdout or r.stderr
    except FileNotFoundError:
        return "nmap not installed — sudo dnf install nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out"


def check_common_paths(url: str) -> str:
    """Probe high-value paths and grab body snippet on 200."""
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
                    line += f"\n         BODY PREVIEW: {body}"
            results.append(line)
        except Exception:
            pass
    return "\n".join(results) if results else "No interesting paths found"


def run_gobuster_dirs(url: str) -> str:
    """Directory fuzzing with gobuster."""
    if not os.path.exists(DIR_WORDLIST):
        return (f"Wordlist not found: {DIR_WORDLIST}\n"
                "Install with: sudo dnf install dirb  OR  sudo dnf install seclists")
    try:
        r = subprocess.run(
            [
                "gobuster", "dir",
                "-u", url,
                "-w", DIR_WORDLIST,
                "-t", "20",          # 20 threads — safe on CPU
                "-q",                # quiet: only print results
                "--no-error",
                "-o", "/tmp/gobuster_dirs.txt",
            ],
            capture_output=True, text=True, timeout=120,
        )
        output = r.stdout.strip() or r.stderr.strip()
        # Also read the output file if it exists
        if os.path.exists("/tmp/gobuster_dirs.txt"):
            with open("/tmp/gobuster_dirs.txt") as f:
                file_out = f.read().strip()
            if file_out:
                return file_out
        return output or "No directories found"
    except FileNotFoundError:
        return "gobuster not installed — sudo dnf install gobuster"
    except subprocess.TimeoutExpired:
        # Return partial results if timed out
        if os.path.exists("/tmp/gobuster_dirs.txt"):
            with open("/tmp/gobuster_dirs.txt") as f:
                return f.read().strip() or "gobuster timed out (no results yet)"
        return "gobuster dir scan timed out"


def run_gobuster_subs(url: str) -> str:
    """Subdomain fuzzing with gobuster."""
    if not os.path.exists(SUB_WORDLIST):
        return (f"Subdomain wordlist not found: {SUB_WORDLIST}\n"
                "Install with: sudo dnf install seclists")
    domain = _domain(url)
    try:
        r = subprocess.run(
            [
                "gobuster", "dns",
                "-d", domain,
                "-w", SUB_WORDLIST,
                "-t", "20",
                "-q",
                "--no-error",
                "-o", "/tmp/gobuster_subs.txt",
            ],
            capture_output=True, text=True, timeout=120,
        )
        output = r.stdout.strip() or r.stderr.strip()
        if os.path.exists("/tmp/gobuster_subs.txt"):
            with open("/tmp/gobuster_subs.txt") as f:
                file_out = f.read().strip()
            if file_out:
                return file_out
        return output or "No subdomains found"
    except FileNotFoundError:
        return "gobuster not installed — sudo dnf install gobuster"
    except subprocess.TimeoutExpired:
        if os.path.exists("/tmp/gobuster_subs.txt"):
            with open("/tmp/gobuster_subs.txt") as f:
                return f.read().strip() or "gobuster timed out (no results yet)"
        return "gobuster dns scan timed out"


def run_wappalyzer(url: str) -> str:
    """
    Detect technologies using webanalyze (Go) or wappalyzer (Node).
    Falls back to header-based detection if neither is installed.
    """
    # Try webanalyze first (Go binary, fast)
    try:
        r = subprocess.run(
            ["webanalyze", "-host", url, "-output", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()[:2000]
    except FileNotFoundError:
        pass

    # Try wappalyzer CLI (Node)
    try:
        r = subprocess.run(
            ["wappalyzer", url],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()[:2000]
    except FileNotFoundError:
        pass

    # Fallback — parse headers ourselves for tech hints
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15,
        )
        headers = r.stdout.lower()
        techs = []
        checks = {
            "x-powered-by":    "Framework/runtime via X-Powered-By header",
            "x-shopify":       "Shopify",
            "x-wp-":           "WordPress",
            "x-drupal":        "Drupal",
            "x-generator":     "CMS via X-Generator",
            "x-magento":       "Magento",
            "x-laravel":       "Laravel",
            "x-aspnet":        "ASP.NET",
            "set-cookie: laravel": "Laravel (session cookie)",
            "set-cookie: wordpress": "WordPress (session cookie)",
            "cloudflare":      "Cloudflare CDN/WAF",
            "server: nginx":   "nginx web server",
            "server: apache":  "Apache web server",
            "server: iis":     "Microsoft IIS",
        }
        for header_key, label in checks.items():
            if header_key in headers:
                # Extract the actual line
                for line in r.stdout.splitlines():
                    if header_key.lower() in line.lower():
                        techs.append(f"  {label}: {line.strip()}")
                        break
        return "\n".join(techs) if techs else "No technologies detected from headers"
    except Exception as e:
        return f"Wappalyzer fallback error: {e}"


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

print("[1/8] DNSDumpster...",     flush=True)
dns = get_dnsdumpster(target)

print("[2/8] WHOIS...",           flush=True)
whois = get_whois(target)

print("[3/8] HTTP Headers...",    flush=True)
headers = get_headers(target)

print("[4/8] robots.txt...",      flush=True)
robots = get_robots(target)

print("[5/8] Nmap...",            flush=True)
scan = get_nmap(target)

print("[6/8] Path probe...",      flush=True)
paths = check_common_paths(target)

print("[7/8] Gobuster dirs...",   flush=True)
gobuster_dirs = run_gobuster_dirs(target)

print("[7/8] Gobuster subs...",   flush=True)
gobuster_subs = run_gobuster_subs(target)

print("[8/8] Wappalyzer...",      flush=True)
tech = run_wappalyzer(target)

print("\n[*] All recon done. Sending to LLM...\n")
print("=" * 60)

# ── Analysis prompt ────────────────────────────────────────────────────────────
analysis_prompt = f"""
Analyze this recon data and write a penetration test report.
Do not repeat the data — produce findings with PoC commands.

TARGET: {target}

--- TECHNOLOGIES (Wappalyzer) ---
{tech}

--- DNS (DNSDumpster) ---
{dns}

--- WHOIS ---
{whois}

--- HTTP HEADERS ---
{headers}

--- ROBOTS.TXT ---
{robots}

--- NMAP ---
{scan}

--- PATH PROBE (non-404) ---
{paths}

--- GOBUSTER DIRECTORY FUZZ ---
{gobuster_dirs}

--- GOBUSTER SUBDOMAIN FUZZ ---
{gobuster_subs}

Write the full report now using your exact format.
"""

# ── LLM streaming ──────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("PENETRATION TEST REPORT — GENERATING")
print("=" * 60 + "\n")

try:
    for chunk in model.stream([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": analysis_prompt},
    ]):
        print(chunk.content, end="", flush=True)
    print("\n")
except Exception as e:
    print(f"[!] LLM error: {e}")