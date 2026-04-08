"""
VSec Code Review Agent

Extracts code review logic from code_review.py for API use.
"""
import os
import subprocess
import tempfile
import shutil
import datetime
import uuid
from pathlib import Path
from typing import Generator

from dotenv import load_dotenv
from anthropic import Anthropic
from langchain_core.callbacks.base import BaseCallbackHandler

load_dotenv()


SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go",
    ".java", ".c", ".cpp", ".cs", ".rs", ".sh", ".env", ".yml",
    ".yaml", ".json", ".xml", ".sql", ".tf", ".dockerfile", ".php"
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".next", "vendor", "target",
}

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "code_reports"
)

SYSTEM_PROMPT = """
You are a senior application security engineer specializing in secure code review.
You have been given source code from a real repository. Your job is to analyze it deeply.

YOUR OUTPUT FORMAT — use EXACTLY this structure:

===================================================
CODE SECURITY REVIEW
Repository : <repo url>
Language(s): <detected languages>
Files      : <number analyzed>
===================================================

[EXECUTIVE SUMMARY]
2-3 sentences on the overall security posture. Be direct.

[VULNERABILITIES]
One block per vulnerability found:

  Vuln #N
  Severity : Critical / High / Medium / Low
  Type     : <e.g. SQL Injection, Hardcoded Secret, XSS, Path Traversal, etc.>
  File     : <filename:line_number>
  Code     : <the vulnerable code snippet>
  Exploit  : <exact proof-of-concept showing how it's exploited>
  Fix      : <the corrected code or mitigation>

[SECURITY MISCONFIGURATIONS]
Infrastructure, config files, dependency issues, exposed secrets.
Same block format as vulnerabilities.

[CODE QUALITY & SECURITY IMPROVEMENTS]
Not vulnerabilities but weaknesses that could become vulnerabilities.
List with file references and specific fixes.

[DEPENDENCY RISKS]
Outdated or vulnerable libraries/packages detected. Include CVE if known.

[VERDICT]
Overall risk rating: Critical / High / Medium / Low
Top 3 things to fix immediately.
"""


def clone_repo(url: str, dest: str) -> bool:
    """Clone a git repo into dest directory."""
    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode == 0
    except Exception:
        return False


def collect_files(repo_path: str) -> list[tuple[str, str]]:
    """Walk repo and collect (relative_path, content) for supported file types."""
    files = []
    repo = Path(repo_path)
    for path in sorted(repo.rglob("*")):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            if path.name.lower() not in ("dockerfile", ".env", ".env.example",
                                          "makefile", "requirements.txt",
                                          "package.json", "gemfile", "cargo.toml"):
                continue
        try:
            content = path.read_text(errors="replace")
            rel = str(path.relative_to(repo))
            files.append((rel, content))
        except Exception:
            pass
    return files


def build_context(files: list[tuple[str, str]], max_chars: int = 80000) -> str:
    """Bundle all file contents into a single analysis context."""
    parts = []
    total = 0
    skipped = 0
    for rel, content in files:
        snippet = f"\n{'='*50}\nFILE: {rel}\n{'='*50}\n{content}\n"
        if total + len(snippet) > max_chars:
            skipped += 1
            continue
        parts.append(snippet)
        total += len(snippet)
    if skipped:
        parts.append(f"\n[NOTE: {skipped} files skipped due to size limit]")
    return "".join(parts)


def detect_quick_wins(files: list[tuple[str, str]]) -> list[dict]:
    """Fast regex-free scan for obvious issues."""
    issues = []
    patterns = [
        ("hardcoded password", ["password =", "passwd =", "pwd =", "secret ="]),
        ("hardcoded API key", ["api_key =", "apikey =", "api_secret =", "ACCESS_KEY ="]),
        ("eval() usage", ["eval(", "exec("]),
        ("shell=True", ["shell=True"]),
        ("SQL string concat", ["SELECT * FROM", "SELECT * from", "+ ' WHERE"]),
        (".env file present", [".env"]),
        ("debug mode enabled", ["DEBUG = True", "debug=True", "DEBUG=True"]),
        ("hardcoded IP", ["127.0.0.1", "0.0.0.0"]),
    ]
    for rel, content in files:
        for label, triggers in patterns:
            for trigger in triggers:
                if trigger in content:
                    line_num = next(
                        (str(i+1) for i, l in enumerate(content.splitlines()) if trigger in l),
                        "?"
                    )
                    issues.append({
                        "type": label,
                        "file": rel,
                        "line": line_num,
                        "description": f"{label} in {rel}:{line_num}"
                    })
                    break
    return issues


def save_report(repo_url: str, content: str) -> str:
    """Save report to code_reports/ folder."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(REPORTS_DIR, f"{repo_name}_{timestamp}.md")
    with open(filepath, "w") as f:
        f.write(f"VSec Code Security Review\n")
        f.write(f"Repository : {repo_url}\n")
        f.write(f"Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(content)
    return filepath


def get_repo_name(url: str) -> str:
    """Extract repository name from URL."""
    return url.rstrip("/").split("/")[-1].replace(".git", "")


class SSECallbackHandler(BaseCallbackHandler):
    """Callback handler for SSE events."""

    def __init__(self):
        self.events = []
        self.full_response = []

    def _emit(self, event_type: str, **data):
        self.events.append({"type": event_type, **data})


class CodeReviewAgent:
    """Agent for conducting code security reviews."""

    def __init__(self, model_name: str = "claude-haiku-4-5"):
        self.client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model_name = model_name

    def review(
        self,
        repo_url: str,
        max_chars: int = 80000,
        callback: SSECallbackHandler | None = None,
    ) -> Generator[dict, None, None]:
        """
        Conduct a code review on a repository.
        
        Yields SSE events as the review progresses.
        """
        if callback is None:
            callback = SSECallbackHandler()

        tmpdir = None
        try:
            # Status: Cloning
            callback._emit("status", status="cloning", message="Cloning repository...")
            yield {"type": "status", "status": "cloning", "message": "Cloning repository..."}

            # Clone repo
            tmpdir = tempfile.mkdtemp(prefix="vsec_review_")
            repo_name = get_repo_name(repo_url)
            repo_path = os.path.join(tmpdir, repo_name)

            if not clone_repo(repo_url, repo_path):
                callback._emit("error", error="Failed to clone repository")
                yield {"type": "error", "error": "Failed to clone repository"}
                return

            # Status: Scanning files
            callback._emit("status", status="scanning", message="Scanning files...")
            yield {"type": "status", "status": "scanning", "message": "Scanning files..."}

            files = collect_files(repo_path)
            if not files:
                callback._emit("error", error="No supported source files found")
                yield {"type": "error", "error": "No supported source files found"}
                return

            callback._emit("progress", progress=20)
            yield {"type": "progress", "progress": 20, "message": f"Found {len(files)} files"}

            # Quick wins scan
            callback._emit("status", status="scanning", message="Running pattern scan...")
            yield {"type": "status", "status": "scanning", "message": "Running pattern scan..."}

            quick_findings = detect_quick_wins(files)
            for finding in quick_findings[:20]:  # Limit findings sent via SSE
                callback._emit("quick_finding", finding=finding)
                yield {"type": "quick_finding", "finding": finding}

            callback._emit("progress", progress=30)
            yield {"type": "progress", "progress": 30, "message": f"Pattern scan complete: {len(quick_findings)} issues found"}

            # Build context
            callback._emit("status", status="analyzing", message="Preparing analysis...")
            yield {"type": "status", "status": "analyzing", "message": "Preparing analysis..."}

            context = build_context(files, max_chars)
            callback._emit("progress", progress=40)
            yield {"type": "progress", "progress": 40, "message": f"Analyzing {len(context):,} characters of code..."}

            # Build prompt
            analysis_prompt = f"""
Repository URL: {repo_url}
Files analyzed: {len(files)}
File list: {', '.join(rel for rel, _ in files[:50])}

SOURCE CODE:
{context}

Perform a full security analysis. Find every vulnerability, misconfiguration, and security weakness.
Be specific — reference exact file names and line numbers.
"""

            # Stream analysis
            callback._emit("status", status="analyzing", message="Running security analysis...")
            yield {"type": "status", "status": "analyzing", "message": "Running security analysis..."}

            full_response = []
            with self.client.messages.stream(
                model=self.model_name,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": analysis_prompt}],
            ) as stream:
                for text in stream.text_stream:
                    full_response.append(text)
                    callback.full_response.append(text)

            callback._emit("progress", progress=90)
            yield {"type": "progress", "progress": 90, "message": "Analysis complete, saving report..."}

            # Save report
            report_content = "".join(full_response)
            report_path = save_report(repo_url, report_content)

            callback._emit("progress", progress=100)
            callback._emit("done", report_path=report_path, quick_findings=quick_findings)
            yield {
                "type": "done",
                "report_path": report_path,
                "report_content": report_content,
                "quick_findings": quick_findings,
                "files_found": len(files),
            }

        except Exception as e:
            error_msg = str(e)
            callback._emit("error", error=error_msg)
            yield {"type": "error", "error": error_msg}

        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)


_agent: CodeReviewAgent | None = None


def get_review_agent(model_name: str = "claude-haiku-4-5") -> CodeReviewAgent:
    """Get or create the singleton CodeReviewAgent instance."""
    global _agent
    if _agent is None or _agent.model_name != model_name:
        _agent = CodeReviewAgent(model_name=model_name)
    return _agent
