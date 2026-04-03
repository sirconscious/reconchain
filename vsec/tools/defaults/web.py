"""VSec Tools — Web Reconnaissance Tools"""
import subprocess
import os

from langchain_core.tools import tool


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
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        r = subprocess.run(
            ["nmap", "-sV", "-F", "--open", domain],
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
