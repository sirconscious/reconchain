"""
VSec Tools — All @tool functions for the penetration testing agent
"""
import os
import subprocess
import httpx
import csv

from langchain_core.tools import tool


# ════════════════════════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════════════════════════
DNSDUMPSTER_API_KEY = os.getenv("DNSDumpster_API_KEY")
WORDLIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common.txt")
WORDLIST_SUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subdomains.txt")
CVE_CSV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cve-common-vulnerabilities-and-exposures",
    "cve.csv"
)


# ════════════════════════════════════════════════════════════════════════════════════
# UTILS: Helpers
# ════════════════════════════════════════════════════════════════════════════════════
def _domain(url: str) -> str:
    """Extract domain from URL."""
    return url.replace("https://", "").replace("http://", "").split("/")[0]


def _trim_whois(raw: str) -> str:
    """Filter WHOIS output to relevant lines."""
    keywords = [
        "registrar", "name server", "creation", "expir",
        "registrant", "country", "org", "abuse", "updated"
    ]
    lines = [
        l for l in raw.splitlines()
        if any(k in l.lower() for k in keywords) and l.strip()
    ]
    return "\n".join(lines[:30])


# ════════════════════════════════════════════════════════════════════════════════════
# TOOLS: DNS & Network
# ════════════════════════════════════════════════════════════════════════════════════
@tool
def get_dnsdumpster(domain: str) -> str:
    """Query DNSDumpster for DNS recon: A, MX, NS, TXT records and subdomains."""
    if not DNSDUMPSTER_API_KEY:
        return "DNSDumpster_API_KEY not set in .env"
    target = _domain(domain)
    try:
        with httpx.Client(timeout=30) as c:
            r = c.get(
                f"https://api.dnsdumpster.com/domain/{target}",
                headers={"X-API-Key": DNSDUMPSTER_API_KEY},
            )
        if r.status_code == 401:
            return "DNSDumpster: bad API key"
        if r.status_code == 429:
            return "DNSDumpster: rate limited"
        if r.status_code != 200:
            return f"DNSDumpster: HTTP {r.status_code}"
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
    """WHOIS lookup: registrar, nameservers, registration dates, org info."""
    try:
        r = subprocess.run(
            ["whois", _domain(url)],
            capture_output=True, text=True, timeout=20
        )
        return _trim_whois(r.stdout) or "No WHOIS data found"
    except Exception as e:
        return str(e)


# ════════════════════════════════════════════════════════════════════════════════════
# TOOLS: Web Recon
# ════════════════════════════════════════════════════════════════════════════════════
@tool
def get_http_headers(url: str) -> str:
    """Fetch HTTP headers: server banner, CDN detection, security headers."""
    try:
        r = subprocess.run(
            ["curl", "-I", "-L", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout or r.stderr
    except Exception as e:
        return str(e)


@tool
def get_robots_txt(url: str) -> str:
    """Fetch robots.txt to discover hidden paths and admin panels."""
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", url.rstrip("/") + "/robots.txt"],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout or "robots.txt not found"
    except Exception as e:
        return str(e)


@tool
def get_nmap_scan(url: str) -> str:
    """nmap fast scan: open ports, service versions."""
    try:
        r = subprocess.run(
            ["nmap", "-sV", "-F", "--open", _domain(url)],
            capture_output=True, text=True, timeout=60
        )
        return r.stdout or r.stderr
    except FileNotFoundError:
        return "nmap not installed — sudo dnf install nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out"


@tool
def check_common_paths(url: str) -> str:
    """Probe high-value paths: /.env /.git/HEAD /admin /api /swagger etc."""
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
                capture_output=True, text=True, timeout=8
            )
            code = code_r.stdout.strip()
            if code in ("404", ""):
                continue
            line = f"  {code}  {path}"
            if code == "200":
                body_r = subprocess.run(
                    ["curl", "-s", "--max-time", "5", url.rstrip("/") + path],
                    capture_output=True, text=True, timeout=8
                )
                body = body_r.stdout.strip()[:300]
                if body:
                    line += f"\n         BODY: {body}"
            results.append(line)
        except Exception:
            pass
    return "\n".join(results) if results else "No interesting paths found"


# ════════════════════════════════════════════════════════════════════════════════════
# TOOLS: Fuzzing & Discovery
# ════════════════════════════════════════════════════════════════════════════════════
@tool
def run_gobuster_dirs(url: str) -> str:
    """Directory fuzzing with gobuster dir — discovers hidden directories."""
    if not os.path.exists(WORDLIST_DIR):
        return f"Wordlist not found: {WORDLIST_DIR}"
    try:
        r = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", WORDLIST_DIR,
             "-t", "20", "-q", "--no-error", "-o", "/tmp/gbdirs.txt"],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists("/tmp/gbdirs.txt"):
            with open("/tmp/gbdirs.txt") as f:
                out = f.read().strip()
            if out:
                return out
        return r.stdout.strip() or "No directories found"
    except FileNotFoundError:
        return "gobuster not installed — sudo dnf install gobuster"
    except subprocess.TimeoutExpired:
        if os.path.exists("/tmp/gbdirs.txt"):
            with open("/tmp/gbdirs.txt") as f:
                return f.read().strip() or "gobuster timed out"
        return "gobuster dir timed out"


@tool
def run_gobuster_subs(url: str) -> str:
    """Subdomain fuzzing with gobuster dns — discovers subdomains."""
    if not os.path.exists(WORDLIST_SUB):
        return f"Subdomain wordlist not found: {WORDLIST_SUB}"
    domain = _domain(url)
    try:
        r = subprocess.run(
            ["gobuster", "dns", "-d", domain, "-w", WORDLIST_SUB,
             "-t", "20", "-q", "--no-error", "-o", "/tmp/gbsubs.txt"],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists("/tmp/gbsubs.txt"):
            with open("/tmp/gbsubs.txt") as f:
                out = f.read().strip()
            if out:
                return out
        return r.stdout.strip() or "No subdomains found"
    except FileNotFoundError:
        return "gobuster not installed — sudo dnf install gobuster"
    except subprocess.TimeoutExpired:
        if os.path.exists("/tmp/gbsubs.txt"):
            with open("/tmp/gbsubs.txt") as f:
                return f.read().strip() or "gobuster timed out"
        return "gobuster dns timed out"


@tool
def detect_technologies(url: str) -> str:
    """Detect tech stack: tries webanalyze, then wappalyzer, then header parsing."""
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
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        techs = []
        checks = {
            "x-powered-by":    "Framework/runtime",
            "x-shopify":        "Shopify",
            "x-wp-":           "WordPress",
            "x-drupal":        "Drupal",
            "x-magento":       "Magento",
            "x-laravel":       "Laravel",
            "x-aspnet":        "ASP.NET",
            "cloudflare":      "Cloudflare CDN/WAF",
            "server: nginx":   "nginx",
            "server: apache":  "Apache",
            "server: iis":     "IIS",
        }
        for key, label in checks.items():
            if key in r.stdout.lower():
                for line in r.stdout.splitlines():
                    if key.lower() in line.lower():
                        techs.append(f"  {label}: {line.strip()}")
                        break
        return "\n".join(techs) if techs else "No technologies detected from headers"
    except Exception as e:
        return f"Tech detection error: {e}"


# ════════════════════════════════════════════════════════════════════════════════════
# TOOLS: CVE Database
# ════════════════════════════════════════════════════════════════════════════════════
_CVE_TEXTS: list[str] = []


def _load_cve_dataset() -> None:
    """Load CVE dataset from CSV file."""
    global _CVE_TEXTS
    if not os.path.exists(CVE_CSV_PATH):
        print(f"  ⚠  CVE dataset not found at {CVE_CSV_PATH}")
        print(f"      CVE lookup will be unavailable")
        return
    try:
        with open(CVE_CSV_PATH, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id  = row.get("", "").strip()
                cvss    = row.get("cvss", "N/A").strip()
                cwe     = row.get("cwe_name", "").strip()
                summary = row.get("summary", "").strip()
                if cve_id.startswith("CVE") and summary:
                    _CVE_TEXTS.append(
                        f"{cve_id} (CVSS: {cvss}, CWE: {cwe}): {summary}"
                    )
        print(f"  ✔ CVE dataset: {len(_CVE_TEXTS):,} entries loaded")
    except Exception as e:
        print(f"  ✗ CVE dataset load error: {e}")


@tool
def retrieve_cve_info(query: str) -> str:
    """Search local CVE database for vulnerabilities matching a query."""
    if not _CVE_TEXTS:
        return "CVE dataset not loaded — place cve.csv in cve-common-vulnerabilities-and-exposures/ folder."
    query_words = query.lower().split()
    scored = []
    for text in _CVE_TEXTS:
        score = sum(1 for word in query_words if word in text.lower())
        if score > 0:
            scored.append((score, text))
    top = sorted(scored, reverse=True)[:8]
    if not top:
        return f"No CVEs found matching: {query}"
    return "\n\n".join(text for _, text in top)


# ════════════════════════════════════════════════════════════════════════════════════
# TOOLS: Utilities
# ════════════════════════════════════════════════════════════════════════════════════
@tool
def shell(command: str) -> str:
    """Execute any shell command and return the output."""
    try:
        r = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=60
        )
        output = r.stdout + r.stderr
        return output[:3000] if output.strip() else "(no output)"
    except subprocess.TimeoutExpired:
        return "command timed out after 60s"
    except Exception as e:
        return f"shell error: {e}"


# ════════════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ════════════════════════════════════════════════════════════════════════════════════
TOOLS = [
    get_dnsdumpster, get_whois,
    get_http_headers, get_robots_txt, get_nmap_scan, check_common_paths,
    run_gobuster_dirs, run_gobuster_subs, detect_technologies,
    retrieve_cve_info,
    # shell,  # disabled by default
]
