# reconchain

AI-powered web reconnaissance agent built with LangChain and Ollama. Runs fully local — no API keys, no cloud.

## Demo

```
$ python3 main.py
Target: https://sberdiltek.com

[*] Running nmap scan...
[*] Fetching HTTP headers...
[*] Running WHOIS lookup...
[*] Fetching robots.txt...

### Reconnaissance Phase
- Port 80/tcp open (HTTP)
- Port 443/tcp open (HTTPS)
- Server behind Cloudflare CDN
- Shopify detected from headers
- robots.txt reveals disallowed paths...
```

## Stack

- **LLM** — `qwen2.5:7b` via Ollama
- **Agent framework** — LangChain 1.x
- **Tools** — nmap, whois, curl
- **Language** — Python 3.13

## Requirements

```bash
# Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b

# System tools
sudo dnf install nmap whois curl -y    # Fedora
# sudo apt install nmap whois curl -y  # Debian/Ubuntu

# Python deps
pip install langchain langchain-ollama langchain-community langchain-core
```

## Usage

```bash
git clone https://github.com/yourusername/reconchain.git
cd reconchain
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Make sure Ollama is running
ollama serve

python3 main.py
```

## Tools

| Tool | Description |
|------|-------------|
| `get_nmap_scan` | Port and service discovery |
| `get_whois` | Domain registration info |
| `get_http_headers` | Web server and tech stack fingerprinting |
| `get_robots_txt` | Hidden paths and directories |

## Roadmap

- [ ] Interactive CLI (pass target as argument)
- [ ] Add `dirb` / `gobuster` for directory brute-forcing
- [ ] Add `nikto` web vulnerability scanner
- [ ] Auto-generate markdown report after scan

## Disclaimer

For authorized penetration testing and educational purposes only. Only use against systems you own or have explicit written permission to test.