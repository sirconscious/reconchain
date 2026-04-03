# AGENTS.md — VSec Development Guide

## Project Overview
VSec is an AI-powered penetration testing and security code review system:
- **Python**: Main agent logic using LangChain/LangGraph (`pentest_agent.py`, `code_review.py`, `bot.py`)
- **TypeScript/VSCode**: VSCode extension (`vsec-extension/src/extension.ts`)
- **No formal test suite** — testing is done manually

## Build & Run Commands

### Python
```bash
source venv/bin/activate
pip install langchain langchain-anthropic langchain-openai langchain-ollama langchain-core langgraph anthropic httpx colorama python-dotenv python-telegram-bot blessed
python3 pentest_agent.py              # Classic mode
python3 pentest_agent.py --tui         # Modern TUI (Claude Code-style)
python3 code_review.py                 # Code security reviewer
python3 bot.py                         # Telegram bot
```

### TypeScript/VSCode Extension
```bash
cd vsec-extension
npm install
npx tsc -p ./              # Compile
npm run watch               # Watch mode
npm run package             # Package .vsix
code --install-extension vsec-*.vsix  # Install locally
```

## Code Style Guidelines

### Python Style

**Imports** (standard → third-party → local):
```python
import os
import subprocess
import httpx
from dotenv import load_dotenv
from colorama import Fore, Style, init as colorama_init
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
```

**Naming Conventions**:
- `CONSTANTS` — UPPER_SNAKE_CASE
- `functions` — snake_case
- `Classes` — PascalCase
- `variables` — snake_case
- Private: `_leading_underscore`

**Colors** (VSec convention):
```python
G = Fore.GREEN; C = Fore.CYAN; Y = Fore.YELLOW; R = Fore.RED
M = Fore.MAGENTA; W = Fore.WHITE; DIM = Style.DIM; B = Style.BRIGHT; RS = Style.RESET_ALL
```

**Function Structure**:
```python
@tool
def get_whois(url: str) -> str:
    """WHOIS lookup: registrar, nameservers, registration dates."""
    try:
        # implementation
    except Exception as e:
        return str(e)
```

**Error Handling**:
- Catch specific exceptions, not bare `except:`
- Tools must return strings, never raise
- Log errors with colorama for visibility

**String Formatting**: Use f-strings and `\n` for multi-line strings

### TypeScript Style

**tsconfig.json**:
```json
{"module": "commonjs", "target": "ES2020", "outDir": "./out", "rootDir": "./src", "strict": false, "esModuleInterop": true}
```

**Imports**: `import * as` for Node modules, default imports for SDKs:
```typescript
import * as vscode from 'vscode';
import * as fs from 'fs';
import Anthropic from '@anthropic-ai/sdk';
```

**VSCode Extension Patterns**:
- Use `vscode.ExtensionContext` for subscriptions
- Dispose subscriptions in `deactivate`
- Use webview panels for UI

### TUI Interface (blessed)
- Layout: Left panel (80%) for chat, right sidebar (20%) for tools
- Colors: Background `#0d1117`, Accent Green `#00ff88`, Cyan `#58a6ff`
- Shortcuts: Enter=send, ↑/↓=scroll, Ctrl+C=quit, Ctrl+N=new session

## Project Structure
```
langChain/
├── pentest_agent.py      # Phase 1-2: Recon agent (LangGraph REACT)
├── tools.py              # All @tool functions (DNS, Web, Fuzzing, CVE, Shell)
├── code_review.py        # Phase 6: Code security reviewer
├── bot.py                # Telegram bot interface
├── tui.py                # Modern TUI (blessed)
├── data.py               # Data utilities
├── common.txt            # Directory fuzzing wordlist
├── subdomains-top1million-20000.txt  # Subdomain wordlist
├── cve-common-vulnerabilities-and-exposures/cve.csv  # 89k+ CVE entries
├── reports/              # Auto-saved pentest reports
├── code_reports/         # Auto-saved code review reports
├── vsec-extension/src/extension.ts  # VSCode extension
└── vsec/                 # New modular package
    ├── __init__.py
    ├── __main__.py
    ├── main.py           # CLI entry point
    ├── config.py         # Settings with provider config
    ├── tools/
    │   ├── __init__.py  # Tool discovery system
    │   ├── defaults/     # Built-in tools (dns, web, fuzz, cve, utils)
    │   └── custom/      # Custom tools (drop .py files here)
    ├── ui/
    │   ├── __init__.py
    │   ├── cli.py       # Blessed TUI
    │   └── callback.py  # LiveProgressHandler
    └── providers/       # AI provider system
        ├── __init__.py  # Provider factory (create_model, list_providers)
        ├── base.py      # BaseModel, ModelInfo, register_provider
        ├── anthropic.py # Anthropic Claude provider
        ├── openai.py    # OpenAI GPT provider
        ├── groq.py      # Groq free inference provider
        └── ollama.py    # Ollama local models provider
```

### File Responsibilities

| File | Responsibility |
|------|----------------|
| `pentest_agent.py` | Agent setup, CLI, callbacks, prompts (263 lines) |
| `tools.py` | All `@tool` functions, helpers, CVE loading (363 lines) |
| `vsec/providers/__init__.py` | Provider factory: `create_model()`, `list_providers()` |
| `vsec/providers/base.py` | `BaseModel`, `ModelInfo`, `register_provider()` decorator |
| `vsec/providers/*.py` | Provider implementations (Anthropic, OpenAI, Groq, Ollama) |

## Key Patterns

### LangChain Tool Definition (in tools.py)
```python
@tool
def tool_name(param: str) -> str:
    """One-line description for LLM."""
    try:
        return result
    except SpecificException as e:
        return f"Error message: {e}"
```

### Importing from tools.py
```python
from tools import (
    TOOLS,
    get_dnsdumpster, get_whois, get_http_headers,
    _load_cve_dataset,
)
```

### Provider System (vsec/providers/)
Each provider is a module that defines a provider class and registers it:

```python
from vsec.providers.base import BaseModel, ModelInfo, register_provider

class MyProvider(BaseModel):
    name = "myprovider"
    display_name = "My Provider"
    
    def create(self, **kwargs) -> Any:
        # Return model instance
        ...

# Register after class definition (NOT as decorator - see note below)
register_provider(ModelInfo(
    name="myprovider",
    display_name="My Provider",
    class_path="vsec.providers.myprovider:MyProvider",
    default_model="my-model",
    available_models=["my-model"],
    env_key="MY_API_KEY",
    api_key_required=True,
    supports_system_message=True,
))
```

**Important Note on Registration Pattern:**
The `@register_provider(ModelInfo(...))` decorator syntax DOES NOT WORK when applied to class definitions due to a Python import cycle issue. Always use explicit `register_provider(ModelInfo(...))` calls after the class definition instead.

**Using the Provider System:**
```python
from vsec.providers import create_model, list_providers, get_default_provider

# List available providers
providers = list_providers()

# Get default provider based on available API keys
provider = get_default_provider()

# Create a model
model = create_model(provider="anthropic", model="claude-haiku-4-5")
```

### Callback Handler
```python
class LiveProgressHandler(BaseCallbackHandler):
    def __init__(self):
        self.tool_start_time = None
        self.step = 0
    def on_tool_start(self, serialized, input_str, **kwargs): ...
    def on_tool_end(self, output, **kwargs): ...
```

### Message Loop
```python
messages = []
while True:
    user_input = input(...).strip()
    if user_input.lower() in ("exit", "quit"): break
    messages.append({"role": "user", "content": user_input})
    result = agent.invoke({"messages": messages})
```

## Environment Variables
```env
ANTHROPIC_API_KEY=sk-ant-...
DNSDumpster_API_KEY=...
TELEGRAM_BOT_TOKEN=...
```

## Linting
```bash
# Python
pip install ruff black mypy
ruff check . && black . && mypy .

# TypeScript
cd vsec-extension && npx eslint src/extension.ts && npx prettier --write src/extension.ts
```

## Installed Skills

These skills are installed globally and available for this project:

| Skill | Purpose |
|-------|---------|
| `langgraph-fundamentals` | LangGraph/LangChain patterns and best practices |
| `pentest-checklist` | Penetration testing methodology and checklists |
| `pentest-expert` | Advanced pentest patterns |
| `python-testing-patterns` | Pytest and testing patterns for Python |
| `code-review-excellence` | Code review best practices |
| `find-skills` | Skill discovery and installation |

## Important Notes
1. **No tests exist** — validate manually by running scripts
2. **API keys required** — set environment variables before running
3. **File paths** — use `os.path.abspath(__file__)` for relative paths
4. **Agent tools** — always return strings, never raise
