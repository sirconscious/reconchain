# VSec Framework

AI-powered penetration testing framework built with LangChain/LangGraph. Automate reconnaissance, vulnerability scanning, and security assessments with customizable tools.

## Features

- **AI-Powered**: Uses Anthropic Claude for intelligent security analysis
- **Extensible Tool System**: Drop Python files into `tools/custom/` to add new tools
- **Recon Automation**: Automated DNS, WHOIS, subdomain enumeration, and technology detection
- **CVE Database**: Built-in lookup for 89,000+ known vulnerabilities
- **Multiple Interfaces**: Classic CLI or modern TUI mode

## Quick Start

### 1. Install Dependencies

```bash
pip install langchain langchain-anthropic langchain-openai langchain-ollama langchain-core langgraph anthropic httpx colorama python-dotenv blessed
```

### 2. Configure API Keys

Create a `.env` file in the project root:

```env
# At least one of these is required:
ANTHROPIC_API_KEY=sk-ant-...        # For Anthropic Claude
OPENAI_API_KEY=sk-...              # For OpenAI GPT
GROQ_API_KEY=gsk_...               # For Groq (free, fast)
```

For **Ollama** (local models, no API key needed):
```bash
ollama pull llama3.2
```

### 3. Run

```bash
# Classic CLI mode (default)
python -m vsec

# Modern TUI mode
python -m vsec --tui

# With specific provider
python -m vsec --provider groq --model llama-3.1-8b-instant
```

---

## Configuration

### API Key

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=sk-ant-...
```

### Available Models

| Model | Description |
|-------|-------------|
| `claude-haiku-4-5` | Fast, cost-effective (default) |
| `claude-sonnet-4-5` | Balanced performance |
| `claude-opus-4-5` | Most capable model |

### Switching Models

**Command line:**
```bash
python -m vsec --model claude-sonnet-4-5
python -m vsec -m claude-opus-4-5
```

**Environment variables:**
```env
VSEC_MODEL=claude-sonnet-4-5
```

---

## Tools

### Built-in Tools

| Tool | Description |
|------|-------------|
| `get_dnsdumpster` | DNS enumeration via DNSDumpster API |
| `get_whois` | WHOIS lookup for domain registration |
| `get_http_headers` | Fetch and analyze HTTP headers |
| `get_robots_txt` | Parse robots.txt for hidden paths |
| `get_nmap_scan` | Port scanning via nmap |
| `check_common_paths` | Probe for common web paths |
| `run_gobuster_dirs` | Directory fuzzing with wordlists |
| `run_gobuster_subs` | Subdomain enumeration |
| `detect_technologies` | Identify web technologies |
| `retrieve_cve_info` | Search CVE database |

### Adding Custom Tools

Create a new `.py` file in `vsec/tools/custom/`:

```python
# vsec/tools/custom/my_tools.py
from langchain_core.tools import tool

@tool
def sql_injection_test(url: str) -> str:
    """
    Test a URL for basic SQL injection vulnerabilities.
    Returns list of vulnerable parameters.
    """
    # Your implementation here
    return f"Testing {url}..."
```

**Rules:**
- Use the `@tool` decorator from `langchain_core.tools`
- Return a **string** (never raise exceptions)
- The docstring is shown to the AI agent

Tools are auto-loaded on restart.

---

## Configuration

### Environment Variables

```env
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Optional
VSEC_MODEL=claude-sonnet-4-5
DNSDumpster_API_KEY=
```

### Tool Settings

Edit `vsec/config.py`:

```python
@dataclass
class Settings:
    cve_enabled: bool = True      # Enable CVE lookup
    shell_enabled: bool = False   # Enable shell execution
```

---

## CLI Options

```bash
python -m vsec [options]

Options:
  --tui, --cli          Launch TUI or CLI interface (CLI is default)
  --model, -m           Model name (default: claude-haiku-4-5)
  --timeout, -t         Request timeout in seconds (default: 120)
  --list-providers      Show available models
```

**Examples:**
```bash
python -m vsec --model claude-sonnet-4-5 --timeout 60
python -m vsec -m claude-opus-4-5
```

---

## Architecture

```
vsec/
├── __init__.py              # Package exports
├── __main__.py              # CLI entry point
├── main.py                  # Main agent logic
├── config.py                # Settings & configuration
│
├── tools/                   # Tool system
│   ├── __init__.py         # Tool discovery
│   ├── defaults/           # Built-in tools
│   │   ├── dns.py
│   │   ├── web.py
│   │   ├── fuzz.py
│   │   ├── cve.py
│   │   └── utils.py
│   └── custom/             # User tools (add here!)
│
└── ui/                      # User interfaces
    ├── cli.py              # Classic CLI
    └── callback.py         # TUI callbacks
```

---

## Examples

### Basic Reconnaissance

```
you > scan example.com
VSec > [RECON] Running DNS lookup...
VSec > [RECON] Fetching WHOIS info...
VSec > [SCAN] Running nmap scan...
VSec > [RECON] Technology detection...
VSec > Found: nginx 1.18, WordPress 6.0
VSec > [CVE] Checking for known vulnerabilities...
```

### Directory Fuzzing

```
you > fuzz directories on https://target.com
VSec > Running gobuster with common.txt wordlist...
VSec > Found: /admin, /wp-login.php, /config.php
```

### CVE Lookup

```
you > what CVEs affect WordPress 6.0?
VSec > Searching CVE database...
VSec > CVE-2024-1234: WordPress <= 6.0 - Authenticated RCE
VSec > CVE-2024-5678: WordPress <= 6.0 - Stored XSS in comments
```

---

## Requirements

- Python 3.10+
- See `requirements.txt` for full dependency list

## License

MIT License - See LICENSE file for details.

## Disclaimer

**For authorized security testing only.** Only use VSec on systems you have explicit written permission to test.
