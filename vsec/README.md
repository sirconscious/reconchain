# VSec Framework

## Project Structure

```
vsec/
├── __init__.py           # Package init, exports
├── main.py               # Entry point: python -m vsec
├── config.py             # Configuration settings
│
└── tools/
    ├── __init__.py       # Tool discovery & registry
    │
    ├── defaults/         # Built-in tools (shipped with VSec)
    │   ├── __init__.py
    │   ├── dns.py        # DNS recon tools
    │   ├── web.py        # Web recon tools
    │   ├── fuzz.py       # Fuzzing tools
    │   ├── cve.py        # CVE lookup tools
    │   └── utils.py      # Utility tools
    │
    └── custom/           # User-added tools (gitignored!)
        └── example_custom_tools.py  # Sample tools
```

## Adding Custom Tools

1. **Create a new file** in `vsec/tools/custom/`:
   ```bash
   # Example: my_scanner.py
   touch vsec/tools/custom/my_scanner.py
   ```

2. **Define your tool**:
   ```python
   from langchain_core.tools import tool

   @tool
   def my_custom_scan(url: str) -> str:
       """
       Describe what your tool does here.
       This docstring is shown to the AI agent.
       """
       # Your implementation
       return "result"
   ```

3. **Restart VSec** — your tool is auto-loaded!

## Enabling/Disabling Tools

Tools are enabled by default in `vsec/config.py`:

```python
@dataclass
class Settings:
    shell_enabled: bool = False  # Set to True to enable shell tool
    cve_enabled: bool = True
```

## Available Default Tools

| Tool | Description |
|------|-------------|
| `get_dnsdumpster` | DNS recon via DNSDumpster API |
| `get_whois` | WHOIS lookup |
| `get_http_headers` | Fetch HTTP headers |
| `get_robots_txt` | Fetch robots.txt |
| `get_nmap_scan` | nmap port scanning |
| `check_common_paths` | Probe common paths |
| `run_gobuster_dirs` | Directory fuzzing |
| `run_gobuster_subs` | Subdomain enumeration |
| `detect_technologies` | Tech stack detection |
| `retrieve_cve_info` | CVE database lookup |
| `shell` | Execute shell commands |

## Running VSec

```bash
# Via the vsec package
python -m vsec

# Or directly
python vsec/main.py
```
