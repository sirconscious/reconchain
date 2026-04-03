---
name: vsec-framework
description: VSec AI-powered penetration testing framework. Use this skill when creating tools for VSec, understanding how the framework works, or extending its capabilities.
---

# VSec Framework Skill

## Overview

VSec is an AI-powered penetration testing framework that uses LangChain/LangGraph with a modular tool system. The AI agent (Claude) calls tools to perform reconnaissance, scanning, and vulnerability assessment.

**Key locations:**
- `vsec/tools/custom/` — Add custom tools here
- `vsec/tools/defaults/` — Built-in tools (don't modify)
- `vsec/config.py` — Configuration settings

---

## Tool Anatomy

Every tool follows this pattern:

```python
from langchain_core.tools import tool

@tool
def tool_name(param: str) -> str:
    """
    One-line description for the AI agent.
    
    More detailed explanation if needed. The AI reads this to 
    understand when and how to use the tool.
    """
    try:
        # implementation
        return "success message with results"
    except SpecificException as e:
        return f"Error: {e}"  # Always return string, never raise
```

### Rules

1. **Always use `@tool` decorator** from `langchain_core.tools`
2. **Return type must be `str`** — never raise exceptions
3. **Docstring is read by the AI** — make it descriptive
4. **Location: `vsec/tools/custom/*.py`**
5. **Restart VSec** after adding/modifying tools

---

## Tool Patterns

### 1. HTTP Requests (httpx)

```python
from langchain_core.tools import tool
import httpx

@tool
def fetch_url(url: str) -> str:
    """Fetch and return content from a URL."""
    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.text[:5000]  # Limit output size
    except httpx.TimeoutException:
        return "Request timed out"
    except httpx.HTTPStatusError as e:
        return f"HTTP {e.response.status_code}: {e}"
    except Exception as e:
        return f"Error: {e}"
```

### 2. HTTP Requests (curl subprocess)

```python
from langchain_core.tools import tool
import subprocess

@tool
def get_headers(url: str) -> str:
    """Fetch HTTP headers using curl."""
    try:
        result = subprocess.run(
            ["curl", "-I", "-L", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "Request timed out"
    except Exception as e:
        return f"Error: {e}"
```

### 3. External Tools (nmap, gobuster)

```python
from langchain_core.tools import tool
import subprocess

@tool
def run_nmap(domain: str) -> str:
    """Run nmap fast scan on domain."""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-F", "--open", domain],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return "nmap not installed"
    except subprocess.TimeoutExpired:
        return "nmap timed out"
    except Exception as e:
        return f"Error: {e}"
```

### 4. Processing Results

```python
@tool
def parse_dns_records(json_data: str) -> str:
    """Parse DNS records from JSON response."""
    import json
    
    try:
        data = json.loads(json_data)
        lines = ["=== DNS Records ==="]
        
        for record in data.get("a", []):
            host = record.get("host", "")
            ip = record.get("ip", "")
            lines.append(f"  {host} -> {ip}")
        
        return "\n".join(lines) if lines else "No records found"
    except json.JSONDecodeError:
        return "Invalid JSON data"
    except Exception as e:
        return f"Error: {e}"
```

---

## Real Examples from VSec

### DNS Reconnaissance

```python
@tool
def get_dnsdumpster(domain: str) -> str:
    """Query DNSDumpster for DNS recon: A, MX, NS, TXT records."""
    from vsec.config import settings
    
    if not settings.dnsdumpster_api_key:
        return "DNSDumpster_API_KEY not set in .env"
    
    target = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        with httpx.Client(timeout=30) as c:
            r = c.get(
                f"https://api.dnsdumpster.com/domain/{target}",
                headers={"X-API-Key": settings.dnsdumpster_api_key},
            )
        
        if r.status_code != 200:
            return f"DNSDumpster: HTTP {r.status_code}"
        
        data = r.json()
        lines = [f"=== DNSDumpster: {target} ==="]
        
        for section in ["a", "mx", "ns"]:
            for rec in data.get(section, []):
                host = rec.get("host") or rec.get("name") or ""
                ip = rec.get("ip", "")
                lines.append(f"  {host}  {ip}")
        
        return "\n".join(lines)
    except Exception as e:
        return f"DNSDumpster error: {e}"
```

### WHOIS Lookup

```python
@tool
def get_whois(url: str) -> str:
    """WHOIS lookup: registrar, nameservers, registration dates."""
    import subprocess
    
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    keywords = ["registrar", "name server", "creation", "expir", "registrant"]
    
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=20
        )
        lines = [
            l for l in result.stdout.splitlines()
            if any(k in l.lower() for k in keywords)
        ]
        return "\n".join(lines[:30]) or "No WHOIS data found"
    except Exception as e:
        return str(e)
```

### Path Discovery

```python
@tool
def check_common_paths(url: str) -> str:
    """Probe high-value paths: /admin /api /.env /wp-admin etc."""
    import subprocess
    
    paths = [
        "/admin", "/login", "/dashboard", "/api",
        "/.git/HEAD", "/.env", "/config", "/backup",
        "/wp-admin", "/phpinfo.php", "/actuator/env",
    ]
    results = []
    
    for path in paths:
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "5", url.rstrip("/") + path],
                capture_output=True, text=True, timeout=8
            )
            code = result.stdout.strip()
            if code not in ("404", ""):
                results.append(f"  {code}  {path}")
        except Exception:
            pass
    
    return "\n".join(results) if results else "No interesting paths found"
```

### Technology Detection

```python
@tool
def detect_technologies(url: str) -> str:
    """Detect tech stack from HTTP headers."""
    import subprocess
    
    try:
        result = subprocess.run(
            ["curl", "-sI", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        
        techs = []
        checks = {
            "x-powered-by": "Framework",
            "x-shopify": "Shopify",
            "x-wp-": "WordPress",
            "x-drupal": "Drupal",
            "cloudflare": "Cloudflare",
            "server: nginx": "nginx",
            "server: apache": "Apache",
        }
        
        for key, label in checks.items():
            if key.lower() in result.stdout.lower():
                techs.append(f"  {label}")
        
        return "\n".join(techs) if techs else "No technologies detected"
    except Exception as e:
        return f"Tech detection error: {e}"
```

---

## Error Handling Patterns

### Always Return Strings

```python
# BAD - raises exception
@tool
def bad_tool(url: str) -> str:
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError("Failed!")  # DON'T DO THIS
    return response.text

# GOOD - returns error string
@tool
def good_tool(url: str) -> str:
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        return f"Error: {e}"
```

### Handle Common Exceptions

```python
try:
    # operation
except FileNotFoundError:
    return "Required tool not installed"
except subprocess.TimeoutExpired:
    return "Command timed out"
except httpx.TimeoutException:
    return "Request timed out"
except httpx.HTTPStatusError as e:
    return f"HTTP {e.response.status_code}: {e}"
except Exception as e:
    return f"Error: {e}"
```

### Limit Output Size

```python
# Prevent overwhelming the AI with huge outputs
return output[:3000]  # First 3000 chars
return output.strip()[:5000]  # With some cleanup
```

---

## Built-in Tools

| Tool | Description |
|------|-------------|
| `get_dnsdumpster` | DNS enumeration via DNSDumpster API |
| `get_whois` | WHOIS lookup for domain registration |
| `get_http_headers` | Fetch and analyze HTTP headers |
| `get_robots_txt` | Parse robots.txt for hidden paths |
| `get_nmap_scan` | Port scanning via nmap |
| `check_common_paths` | Probe common web paths |
| `run_gobuster_dirs` | Directory fuzzing with gobuster |
| `run_gobuster_subs` | Subdomain enumeration |
| `detect_technologies` | Identify web technologies |
| `retrieve_cve_info` | Search CVE database (89k+ entries) |
| `shell` | Execute shell commands |

---

## Configuration

Access settings in `vsec/config.py`:

```python
from vsec.config import settings

# Available settings
settings.dnsdumpster_api_key  # DNSDumpster API key
settings.shell_enabled         # Enable shell tool (default: False)
settings.cve_enabled          # Enable CVE lookup (default: True)
settings.wordlist_dir         # Path to directory wordlist
settings.wordlist_sub         # Path to subdomain wordlist
settings.cve_csv_path         # Path to CVE database
settings.reports_dir          # Path to reports directory
```

---

## Tool Discovery System

Tools are auto-discovered when VSec starts:

1. Scans `vsec/tools/defaults/` for built-in tools
2. Scans `vsec/tools/custom/` for user tools
3. Registers all `@tool` decorated functions
4. Loads CVE dataset if enabled

**To add a tool:**
```bash
# 1. Create file
touch vsec/tools/custom/my_tool.py

# 2. Write tool code (see patterns above)

# 3. Restart VSec
python -m vsec
```

---

## Testing Your Tool

### 1. Import Test

```python
from vsec.tools import get_tool
tool = get_tool("your_tool_name")
print(tool.invoke("test_input"))
```

### 2. Direct Test

```bash
cd /path/to/vsec
source venv/bin/activate
python -c "
from vsec.tools.custom.my_tool import your_tool_name
result = your_tool_name.invoke('test_input')
print(result)
"
```

### 3. Integration Test

```bash
python -m vsec
> test your tool with a real target
```

---

## Example: Creating a CVE Lookup Tool

```python
# vsec/tools/custom/cve_lookup.py
from langchain_core.tools import tool
import csv

@tool
def lookup_cve(keyword: str) -> str:
    """
    Search local CVE database for vulnerabilities matching keyword.
    Returns top 10 most relevant CVEs.
    """
    from vsec.config import settings
    
    cve_path = settings.cve_csv_path
    results = []
    
    try:
        with open(cve_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                desc = row.get("Description", "").lower()
                if keyword.lower() in desc:
                    cve_id = row.get("ID", "Unknown")
                    score = row.get("CVSS", "N/A")
                    results.append(f"{cve_id} (CVSS: {score})")
                    if len(results) >= 10:
                        break
        
        if not results:
            return f"No CVEs found for: {keyword}"
        
        return f"=== CVEs for '{keyword}' ===\n" + "\n".join(results)
    except Exception as e:
        return f"CVE lookup error: {e}"
```

---

## Checklist for New Tools

- [ ] Uses `@tool` decorator from `langchain_core.tools`
- [ ] Returns `str`, never raises exceptions
- [ ] Has descriptive docstring
- [ ] Handles timeouts appropriately
- [ ] Returns meaningful error messages
- [ ] Placed in `vsec/tools/custom/`
- [ ] Tested with real input
- [ ] Restarts VSec after adding

---

## Quick Reference

**Import:**
```python
from langchain_core.tools import tool
```

**Location:** `vsec/tools/custom/*.py`

**Restart:** After adding/modifying tools

**Config:** `from vsec.config import settings`

**Test:** `python -c "from vsec.tools import get_tool; print(get_tool('name').invoke('input'))"`
