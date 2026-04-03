"""VSec Tools — Utility Tools"""
import subprocess

from langchain_core.tools import tool


@tool
def shell(command: str) -> str:
    """Execute any shell command and return the output."""
    try:
        r = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=60
        )
        output = r.stdout + r.stderr
        return output[:3000] if output.strip() else "(no output)"
    except subprocess.TimeoutExpired:
        return "command timed out after 60s"
    except Exception as e:
        return f"shell error: {e}"
