```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║     ███████║███████║██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║╚██████╗██║  ██║██║  ██║██║██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
```
> AI-powered web reconnaissance agent — fully local, no API keys, no cloud.

---

## How it works

Give it a target. It autonomously chains recon tools together, reasons about the results, and maps the attack surface — the same way a pentester would.

```
$ python3 main.py

Target URL: https://target.com

[*] Running nmap scan         → open ports & services detected
[*] Fetching HTTP headers     → server fingerprinted
[*] Running WHOIS lookup      → domain ownership retrieved  
[*] Fetching robots.txt       → hidden paths discovered

### Reconnaissance Report
...
```

---

## Stack

| Component | Details |
|-----------|---------|
| LLM | `qwen2.5:7b` via Ollama |
| Agent Framework | LangChain 1.x |
| Recon Tools | nmap, whois, curl |
| Language | Python 3.13 |
| Runs | 100% locally |

---

## Setup

```bash
# 1. Install Ollama and pull the model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b

# 2. Install system tools
sudo dnf install nmap whois curl -y    # Fedora
sudo apt install nmap whois curl -y    # Debian/Ubuntu

# 3. Clone and install Python deps
git clone https://github.com/yourusername/reconchain.git
cd reconchain
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

```bash
# Start Ollama
ollama serve

# Run the agent
python3 main.py
```

---

## Tools

| Tool | What it does |
|------|-------------|
| `get_nmap_scan` | Discovers open ports and running services |
| `get_whois` | Pulls domain registration and ownership info |
| `get_http_headers` | Fingerprints web server and tech stack |
| `get_robots_txt` | Reveals hidden paths and disallowed directories |

---

## Roadmap

- [ ] Interactive CLI — pass target as argument
- [ ] `gobuster` integration for directory brute-forcing
- [ ] `nikto` web vulnerability scanning
- [ ] Auto-generate markdown report after scan
- [ ] Multi-target support

---

## Disclaimer

For **authorized penetration testing and educational purposes only**.  
Only use against systems you own or have explicit written permission to test.  
Unauthorized use is illegal.