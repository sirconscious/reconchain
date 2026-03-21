```
 ██╗   ██╗███████╗███████╗ ██████╗
 ██║   ██║██╔════╝██╔════╝██╔════╝
 ██║   ██║███████╗█████╗  ██║
 ╚██╗ ██╔╝╚════██║██╔══╝  ██║
  ╚████╔╝ ███████║███████╗╚██████╗
   ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
```

> AI-powered penetration testing agent — autonomous recon, CVE lookup, code security review, Telegram bot, and VSCode extension.

---

## What is VSec?

VSec is a modular AI-powered penetration testing pipeline built with Python and Claude (Anthropic). It autonomously chains real security tools together, reasons about the results using a large language model, and produces structured pentest reports — the same methodology a professional red team follows.

This is not a script. It's an agent that thinks.

```
you > https://target.com

agent → runs DNSDumpster, WHOIS, headers, robots.txt, nmap,
        gobuster, path probe, tech detection, CVE lookup
agent → cross-references 89,000+ CVEs against findings
agent → produces severity-ranked report with PoC commands
agent → saves report to /reports/target_timestamp.txt
```

---

## Project Structure

```
vsec/
├── pentest_agent.py         ← Phase 1 & 2: interactive recon agent (terminal)
├── code_review.py           ← Phase 6: AI code security reviewer (terminal)
├── bot.py                   ← Telegram bot interface for pentest agent
├── vsec-extension/          ← VSCode extension for code review
│   ├── src/extension.ts
│   ├── package.json
│   └── vsec-0.1.0.vsix
├── common.txt               ← wordlist for directory fuzzing
├── subdomains.txt           ← wordlist for subdomain fuzzing
├── reports/                 ← auto-saved pentest reports
├── code_reports/            ← auto-saved code review reports
├── cve-common-vulnerabilities-and-exposures/
│   └── cve.csv              ← local CVE database (89k+ entries)
└── .env                     ← API keys
```

---

## Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 — Reconnaissance | ✅ Done | Passive + active recon, full attack surface mapping |
| 2 — Vulnerability Analysis | 🔄 In Progress | Nuclei, Nikto, sqlmap integration |
| 3 — Exploitation | 📅 Planned | Shell-based agent on Kali Linux, Metasploit |
| 4 — Reporting | 📅 Planned | Auto-generated PDF reports |
| 5 — Log Classifier | 📅 Planned | ML model detecting attacks in web server logs |
| 6 — Secure Code Review | ✅ Done | AI-powered source code vulnerability scanner |

---

## Tools (Phase 1 — Recon Agent)

| Tool | Purpose |
|------|---------|
| `get_dnsdumpster` | Passive DNS recon — A, MX, NS, TXT records, subdomains |
| `get_whois` | Domain registration, registrar, nameservers |
| `get_http_headers` | Server fingerprinting, CDN detection, security headers |
| `get_robots_txt` | Hidden paths, admin panels, sensitive endpoints |
| `get_nmap_scan` | Open ports and service versions |
| `check_common_paths` | Probes /.env /.git/HEAD /admin /api /swagger etc |
| `run_gobuster_dirs` | Directory fuzzing with custom wordlist |
| `run_gobuster_subs` | Subdomain enumeration |
| `detect_technologies` | Tech stack detection (Shopify, WordPress, nginx...) |
| `retrieve_cve_info` | Local CVE database search — 89,660 entries |
| `shell` | Execute any shell command for custom checks |

---

## Stack

| Component | Details |
|-----------|---------|
| LLM | `claude-haiku-4-5` via Anthropic API |
| Agent Framework | LangChain + LangGraph (`create_react_agent`) |
| Recon Tools | nmap, gobuster, curl, whois, DNSDumpster API |
| CVE Database | Local CSV — 89,660 CVE entries |
| Telegram Bot | python-telegram-bot |
| VSCode Extension | TypeScript + Anthropic SDK |
| Language | Python 3.13 / TypeScript |
| Cost per scan | ~$0.01–0.03 |

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/sirconscious/vsec.git
cd vsec
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install system tools

```bash
# Fedora
sudo dnf install nmap whois curl gobuster git -y

# Debian/Ubuntu/Kali
sudo apt install nmap whois curl gobuster git -y

# Nuclei (Phase 2)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### 3. Set up environment

Create a `.env` file:

```env
ANTHROPIC_API_KEY=sk-ant-...
DNSDumpster_API_KEY=your_key_here
TELEGRAM_BOT_TOKEN=your_token_here
```

Get your keys:
- Anthropic API: https://console.anthropic.com
- DNSDumpster API: https://dnsdumpster.com
- Telegram Bot: message @BotFather on Telegram → `/newbot`

### 4. CVE Database

```bash
git clone https://github.com/r-spacex/cve-common-vulnerabilities-and-exposures.git
```

Make sure the folder is in the same directory as `pentest_agent.py`.

---

## Usage

### 1. Pentest Agent — Terminal

```bash
python3 pentest_agent.py
```

```
VSec > What target would you like to assess?
you   > https://target.com
```

Commands inside the agent:
- `new` — start a fresh engagement
- `exit` — quit VSec

---

### 2. Pentest Agent — Telegram Bot

```bash
python3 bot.py
```

Open your bot in Telegram and send a target URL directly.

Bot commands:
- `/start` — welcome message
- `/new` — clear session, fresh engagement
- `/help` — show usage

---

### 3. Code Review Agent — Terminal

```bash
python3 code_review.py
```

```
VSec > Enter repository URL (or 'exit' to quit):
you   > https://github.com/user/repo.git
```

The agent clones the repo, scans all source files, and streams a full security review. Report saved to `code_reports/`.

---

### 4. Code Review — VSCode Extension

**Install:**
```bash
cd vsec-extension
npm install
npx tsc -p ./
npx vsce package
code --install-extension vsec-0.1.0.vsix
```

**Set API key:**
`Ctrl+,` → search `vsec` → paste Anthropic API key

**Use:**
- Right-click any file in explorer → **VSec: Review This File**
- Right-click any folder → **VSec: Review This Folder**
- Right-click inside open file → **VSec: Review This File**

A dark panel opens on the right streaming the security analysis in real time.

---

## Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✔ CVE dataset: 89,660 entries loaded
  ✔ Model   : claude-haiku-4-5
  ✔ Tools   : 11 active
  ✔ Status  : ready

  19:32:59 🌐 [1] get_dnsdumpster      ✓ 0.6s
  19:33:00 📡 [2] get_http_headers     ✓ 0.4s
  19:33:01 📋 [3] get_whois            ✓ 0.2s
  19:33:02 🤖 [4] get_robots_txt       ✓ 0.4s
  19:33:03 🔬 [5] detect_technologies  ✓ 0.2s
  19:33:04 🚪 [6] check_common_paths   ✓ 8.9s
  19:33:13 📂 [7] run_gobuster_dirs    ✓ 0.4s
  19:33:14 🔍 [8] get_nmap_scan        ✓ 15.6s
  19:33:22 🗄 [9] retrieve_cve_info    ✓ 0.3s

  ✔ scan complete

  ✔ Report saved → reports/target.com_20260321_193344.txt
```

---

## Requirements

```
langchain-anthropic
langchain-core
langgraph
langchain
anthropic
httpx
colorama
python-dotenv
python-telegram-bot
```

Install:
```bash
pip install -r requirements.txt
```

---

## Roadmap

- [x] Phase 1 — Full recon pipeline (11 tools)
- [x] Phase 1 — Interactive chat mode
- [x] Phase 1 — CVE database integration (89k entries)
- [x] Phase 1 — Live progress callbacks with colors
- [x] Phase 1 — Auto-save reports
- [x] Phase 6 — AI code security reviewer (terminal)
- [x] Phase 6 — VSCode extension with streaming panel
- [x] Telegram bot interface
- [ ] Phase 2 — Nuclei vulnerability scanner
- [ ] Phase 2 — Nikto web scanner
- [ ] Phase 2 — sqlmap SQL injection
- [ ] Phase 3 — Kali Linux shell agent
- [ ] Phase 3 — Metasploit integration
- [ ] Phase 4 — PDF report generation
- [ ] Phase 5 — Web server log attack classifier

---

## Disclaimer

For **authorized penetration testing and educational purposes only**.
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal and unethical.

This tool is part of a university cybersecurity research project.