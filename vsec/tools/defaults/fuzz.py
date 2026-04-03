"""VSec Tools — Fuzzing & Discovery Tools"""
import subprocess
import os

from langchain_core.tools import tool

from vsec.config import settings


def _domain(url: str) -> str:
    """Extract domain from URL."""
    return url.replace("https://", "").replace("http://", "").split("/")[0]


@tool
def run_gobuster_dirs(url: str) -> str:
    """Directory fuzzing with gobuster dir — discovers hidden directories."""
    if not os.path.exists(settings.wordlist_dir):
        return f"Wordlist not found: {settings.wordlist_dir}"
    
    try:
        r = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", settings.wordlist_dir,
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
    if not os.path.exists(settings.wordlist_sub):
        return f"Subdomain wordlist not found: {settings.wordlist_sub}"
    
    domain = _domain(url)
    
    try:
        r = subprocess.run(
            ["gobuster", "dns", "-d", domain, "-w", settings.wordlist_sub,
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
            "x-shopify":      "Shopify",
            "x-wp-":          "WordPress",
            "x-drupal":       "Drupal",
            "x-magento":      "Magento",
            "x-laravel":      "Laravel",
            "x-aspnet":       "ASP.NET",
            "cloudflare":     "Cloudflare CDN/WAF",
            "server: nginx":  "nginx",
            "server: apache": "Apache",
            "server: iis":    "IIS",
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
