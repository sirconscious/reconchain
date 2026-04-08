# AGENTS.md — VSec Development Guide

## Project Overview
VSec is an AI-powered penetration testing and security code review system:
- **Python**: Main agent logic using LangChain/LangGraph (`pentest_agent.py`, `code_review.py`, `bot.py`)
- **Python API**: FastAPI backend for web UI integration (`vsec/api/`)
- **TypeScript/VSCode**: VSCode extension (`vsec-extension/src/extension.ts`)
- **No formal test suite** — testing is done manually

## Build & Run Commands

### Python Dependencies
```bash
pip install langchain langchain-anthropic langchain-openai langchain-ollama langchain-core langgraph anthropic httpx colorama python-dotenv python-telegram-bot blessed
pip install fastapi uvicorn sse-starlette
```

### Python Entry Points
```bash
python3 pentest_agent.py              # Classic CLI mode
python3 pentest_agent.py --tui         # Modern TUI
python3 -m vsec.api                  # API server (port 8000)
python3 code_review.py                 # Code security reviewer
python3 bot.py                         # Telegram bot
```

### API Server
```bash
python -m vsec.api                           # Default (0.0.0.0:8000)
python -m vsec.api --host 127.0.0.1        # Local only
python -m vsec.api --port 9000              # Custom port
python -m vsec.api --reload                 # Auto-reload
```

### TypeScript/VSCode Extension
```bash
cd vsec-extension
npm install
npx tsc -p ./              # Compile
npm run watch               # Watch mode
npm run package             # Package .vsix
code --install-extension vsec-*.vsix
```

## Project Structure
```
vsec/
├── api/                    # FastAPI backend
│   ├── __init__.py
│   ├── __main__.py        # python -m vsec.api
│   ├── schemas.py         # Pydantic models
│   ├── session.py          # Session manager
│   ├── agent.py            # PentestAgent class
│   ├── routes.py           # API routes + SSE
│   └── code_review/       # Code review API
│       ├── agent.py       # CodeReviewAgent
│       ├── schemas.py     # Review models
│       └── routes.py      # Review endpoints
├── tools/                  # Tool discovery
│   ├── defaults/           # Built-in tools
│   └── custom/            # User tools (drop .py here)
└── providers/              # AI provider system

pentest_agent.py            # CLI + PentestAgent wrapper
tools.py                    # All @tool functions
reports/                    # Generated pentest reports
code_reports/              # Generated code review reports
```

## API Layer (vsec/api/)

### Pentest Agent Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/tools` | List available tools |
| POST | `/api/sessions` | Create new session |
| GET | `/api/sessions` | List all sessions |
| GET | `/api/sessions/{id}` | Get session details |
| DELETE | `/api/sessions/{id}` | Delete session |
| POST | `/api/sessions/{id}/message` | Send message (SSE) |
| GET | `/api/sessions/{id}/stream` | SSE status stream |
| GET | `/api/reports/{session_id}` | Get report content |
| GET | `/api/reports/{session_id}/download` | Download report |

### Code Review Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/code-review/reviews` | Start new review |
| GET | `/api/code-review/reviews` | List all reviews |
| GET | `/api/code-review/reviews/{id}` | Get review status |
| DELETE | `/api/code-review/reviews/{id}` | Delete review |
| POST | `/api/code-review/reviews/{id}/run` | Run review (SSE) |
| POST | `/api/code-review/reviews/{id}/start` | Run review (blocking) |
| GET | `/api/code-review/reports/{id}` | Get review report |
| GET | `/api/code-review/reports/{id}/download` | Download report |

### SSE Events (Pentest)

| Type | Fields | Description |
|------|--------|-------------|
| `tool_start` | `tool`, `input`, `step` | Tool execution started |
| `tool_end` | `tool`, `output`, `elapsed` | Tool execution completed |
| `message` | `content` | AI response |
| `done` | `report_path` | Analysis complete |

### SSE Events (Code Review)

| Type | Fields | Description |
|------|--------|-------------|
| `status` | `status`, `message` | Current status |
| `progress` | `progress` (0-100) | Progress update |
| `quick_finding` | `finding` | Pattern match found |
| `done` | `report_path`, `files_found` | Review complete |
| `error` | `error` | Error occurred |

### API Usage Examples

```bash
# === Pentest Agent ===
# Create session
curl -X POST http://localhost:8000/api/sessions

# Send message (streaming)
curl -X POST http://localhost:8000/api/sessions/{id}/message \
  -H "Content-Type: application/json" \
  -d '{"content": "https://example.com"}'

# Get report
curl http://localhost:8000/api/reports/{session_id}

# === Code Review ===
# Start review
curl -X POST http://localhost:8000/api/code-review/reviews \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo"}'

# Run review (SSE streaming)
curl -X POST http://localhost:8000/api/code-review/reviews/{id}/run

# Get review report
curl http://localhost:8000/api/code-review/reports/{id}
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

### PentestAgent (vsec/api/agent.py)
```python
from vsec.api.agent import PentestAgent, get_agent

agent = get_agent(model_name="claude-haiku-4-5")

# Non-streaming
result = agent.invoke(messages)
print(result["response"])

# With SSE callback
callback = SSECallbackHandler()
result = agent.invoke(messages, stream_callback=callback)
for event in callback.events:
    print(event)
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
5. **API is local-only by default** — use reverse proxy for production
