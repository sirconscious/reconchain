"""VSec Tools — CVE Database Tools"""
import csv
import os

from langchain_core.tools import tool

from vsec.config import settings


_CVE_TEXTS: list[str] = []


def _load_cve_dataset() -> None:
    """Load CVE dataset from CSV file."""
    global _CVE_TEXTS
    
    if not os.path.exists(settings.cve_csv_path):
        print(f"  ⚠  CVE dataset not found at {settings.cve_csv_path}")
        print(f"      CVE lookup will be unavailable")
        return
    
    try:
        with open(settings.cve_csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id  = row.get("", "").strip()
                cvss    = row.get("cvss", "N/A").strip()
                cwe     = row.get("cwe_name", "").strip()
                summary = row.get("summary", "").strip()
                if cve_id.startswith("CVE") and summary:
                    _CVE_TEXTS.append(
                        f"{cve_id} (CVSS: {cvss}, CWE: {cwe}): {summary}"
                    )
        print(f"  ✔ CVE dataset: {len(_CVE_TEXTS):,} entries loaded")
    except Exception as e:
        print(f"  ✗ CVE dataset load error: {e}")


@tool
def retrieve_cve_info(query: str) -> str:
    """Search local CVE database for vulnerabilities matching a query."""
    if not _CVE_TEXTS:
        return "CVE dataset not loaded — place cve.csv in cve-common-vulnerabilities-and-exposures/ folder."
    
    query_words = query.lower().split()
    scored = []
    for text in _CVE_TEXTS:
        score = sum(1 for word in query_words if word in text.lower())
        if score > 0:
            scored.append((score, text))
    
    top = sorted(scored, reverse=True)[:8]
    if not top:
        return f"No CVEs found matching: {query}"
    
    return "\n\n".join(text for _, text in top)
