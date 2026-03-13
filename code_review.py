import os
import sys
import subprocess
import tempfile
import shutil
import datetime
from pathlib import Path
from colorama import Fore, Style, init as colorama_init
from anthropic import Anthropic
from dotenv import load_dotenv

colorama_init(autoreset=True)
load_dotenv()

# ── Colors ─────────────────────────────────────────────────────────────────────
G   = Fore.GREEN
C   = Fore.CYAN
Y   = Fore.YELLOW
R   = Fore.RED
M   = Fore.MAGENTA
W   = Fore.WHITE
DIM = Style.DIM
B   = Style.BRIGHT
RS  = Style.RESET_ALL

# ── File extensions to analyze ─────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go",
    ".java", ".c", ".cpp", ".cs", ".rs", ".sh", ".env", ".yml",
    ".yaml", ".json", ".xml", ".sql", ".tf", ".dockerfile",".php"
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".next", "vendor", "target",
}

# ── Reports dir ────────────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "code_reports")

# ── Banner ─────────────────────────────────────────────────────────────────────
BANNER = f"""
{G}{B}
 ██╗   ██╗███████╗███████╗ ██████╗
 ██║   ██║██╔════╝██╔════╝██╔════╝
 ██║   ██║███████╗█████╗  ██║
 ╚██╗ ██╔╝╚════██║██╔══╝  ██║
  ╚████╔╝ ███████║███████╗╚██████╗
   ╚═══╝  ╚══════╝╚══════╝ ╚═════╝{RS}
{C}        AI-Powered Code Security Analyzer{RS}
{DIM}        Phase 6 — Secure Code Review{RS}
"""

DIV  = f"{G}{DIM}{'─' * 60}{RS}"
DIV2 = f"{G}{'━' * 60}{RS}"

# ── System prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """
You are a senior application security engineer specializing in secure code review.
You have been given source code from a real repository. Your job is to analyze it deeply.

YOUR OUTPUT FORMAT — use EXACTLY this structure:

====================================================
CODE SECURITY REVIEW
Repository : <repo url>
Language(s): <detected languages>
Files      : <number analyzed>
====================================================

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

# ── Helpers ────────────────────────────────────────────────────────────────────
def clone_repo(url: str, dest: str) -> bool:
    """Clone a git repo into dest directory."""
    print(f"  {C}◆{RS} Cloning repository...", flush=True)
    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            print(f"  {R}✗ Clone failed: {r.stderr.strip()[:200]}{RS}")
            return False
        print(f"  {G}✔{RS} Cloned successfully")
        return True
    except FileNotFoundError:
        print(f"  {R}✗ git not installed — sudo dnf install git{RS}")
        return False
    except subprocess.TimeoutExpired:
        print(f"  {R}✗ Clone timed out{RS}")
        return False


def collect_files(repo_path: str) -> list[tuple[str, str]]:
    """Walk repo and collect (relative_path, content) for supported file types."""
    files = []
    repo = Path(repo_path)
    for path in sorted(repo.rglob("*")):
        # Skip unwanted dirs
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            # Also catch Dockerfile, .env files without extensions
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
    """Bundle all file contents into a single analysis context, capped at max_chars."""
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


def detect_quick_wins(files: list[tuple[str, str]]) -> list[str]:
    """Fast regex-free scan for obvious issues before sending to LLM."""
    issues = []
    patterns = [
        ("hardcoded password",   ["password =", "passwd =", "pwd =", "secret ="]),
        ("hardcoded API key",    ["api_key =", "apikey =", "api_secret =", "ACCESS_KEY ="]),
        ("eval() usage",         ["eval(", "exec("]),
        ("shell=True",           ["shell=True"]),
        ("SQL string concat",    ["SELECT * FROM", "SELECT * from", "+ ' WHERE"]),
        (".env file present",    [".env"]),
        ("debug mode enabled",   ["DEBUG = True", "debug=True", "DEBUG=True"]),
        ("hardcoded IP",         ["127.0.0.1", "0.0.0.0"]),
    ]
    for rel, content in files:
        for label, triggers in patterns:
            for trigger in triggers:
                if trigger in content:
                    line_num = next(
                        (i+1 for i, l in enumerate(content.splitlines()) if trigger in l),
                        "?"
                    )
                    issues.append(f"  {Y}⚠{RS}  {label} in {C}{rel}:{line_num}{RS}")
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


# ── Main ───────────────────────────────────────────────────────────────────────
print(BANNER)
print(DIV2)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

while True:
    print(f"\n  {C}{B}VSec >{RS} Enter repository URL (or 'exit' to quit):\n")
    try:
        repo_url = input(f"  {G}{B}you   >{RS} ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {Y}Goodbye.{RS}\n")
        sys.exit(0)

    if repo_url.lower() in ("exit", "quit"):
        print(f"\n  {Y}Goodbye.{RS}\n")
        sys.exit(0)

    if not repo_url.startswith(("http://", "https://", "git@")):
        print(f"  {R}✗ Invalid URL. Use full https:// or git@ format.{RS}")
        continue

    print(DIV)

    # Clone into temp dir
    tmpdir = tempfile.mkdtemp(prefix="vsec_")
    try:
        if not clone_repo(repo_url, tmpdir):
            continue

        # Collect files
        print(f"  {C}◆{RS} Scanning files...", flush=True)
        files = collect_files(tmpdir)
        if not files:
            print(f"  {R}✗ No supported source files found.{RS}")
            continue

        print(f"  {G}✔{RS} Found {B}{len(files)} files{RS} to analyze")

        # Quick wins scan
        print(f"  {C}◆{RS} Running quick pattern scan...", flush=True)
        quick_issues = detect_quick_wins(files)
        if quick_issues:
            print(f"\n  {Y}{B}Quick Findings:{RS}")
            for issue in quick_issues[:15]:  # cap display at 15
                print(f"  {issue}")
            if len(quick_issues) > 15:
                print(f"  {DIM}  ... and {len(quick_issues)-15} more (see full report){RS}")
        else:
            print(f"  {G}✔{RS} No obvious patterns found")

        # Build context for LLM
        print(f"\n  {C}◆{RS} Preparing code context...", flush=True)
        context = build_context(files)
        char_count = len(context)
        print(f"  {G}✔{RS} Context: {B}{char_count:,} chars{RS} / ~{B}{char_count//4:,} tokens{RS}")

        # Stream analysis
        print(DIV)
        print(f"\n  {C}{B}VSec >{RS} Analyzing code with Claude...\n")
        print(DIV2)
        print()

        analysis_prompt = f"""
Repository URL: {repo_url}
Files analyzed: {len(files)}
File list: {', '.join(rel for rel, _ in files[:50])}

SOURCE CODE:
{context}

Perform a full security analysis. Find every vulnerability, misconfiguration, and security weakness.
Be specific — reference exact file names and line numbers.
"""

        full_response = []
        with client.messages.stream(
            model="claude-haiku-4-5",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": analysis_prompt}],
        ) as stream:
            for text in stream.text_stream:
                print(f"  {text}", end="", flush=True)
                full_response.append(text)

        print(f"\n\n{DIV2}")

        # Save report
        report_content = "".join(full_response)
        filepath = save_report(repo_url, report_content)
        print(f"\n  {G}✔ Report saved →{RS} {DIM}{filepath}{RS}\n")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(DIV)
    print(f"\n  {C}{B}VSec >{RS} Analyze another repository?\n")