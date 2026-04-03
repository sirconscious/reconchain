"""VSec Tools — DNS & Network Reconnaissance Tools"""
import subprocess
import httpx

from langchain_core.tools import tool

from vsec.config import settings


@tool
def get_dnsdumpster(domain: str) -> str:
    """Query DNSDumpster for DNS recon: A, MX, NS, TXT records and subdomains."""
    if not settings.dnsdumpster_api_key:
        return "DNSDumpster_API_KEY not set in .env"
    
    target = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        with httpx.Client(timeout=30) as c:
            r = c.get(
                f"https://api.dnsdumpster.com/domain/{target}",
                headers={"X-API-Key": settings.dnsdumpster_api_key},
            )
        if r.status_code == 401:
            return "DNSDumpster: bad API key"
        if r.status_code == 429:
            return "DNSDumpster: rate limited"
        if r.status_code != 200:
            return f"DNSDumpster: HTTP {r.status_code}"
        
        data = r.json()
        lines = [f"=== DNSDumpster: {target} ==="]
        
        for section in ["a", "mx", "ns"]:
            recs = data.get(section, [])
            if recs:
                lines.append(f"\n[{section.upper()}]")
                for rec in recs:
                    host = rec.get("host") or rec.get("name") or ""
                    ip   = rec.get("ip", "")
                    asn  = rec.get("asn", "")
                    lines.append(f"  {host}  {ip}  {asn}".strip())
        
        txt = data.get("txt", [])
        if txt:
            lines.append("\n[TXT]")
            for t in txt:
                lines.append(f"  {t.get('value') or t}")
        
        subs = data.get("dns_records", {}).get("host", []) or data.get("subdomains", [])
        if subs:
            lines.append("\n[SUBDOMAINS]")
            for s in subs:
                host = s.get("host") or s.get("name") or ""
                ip   = s.get("ip", "")
                lines.append(f"  {host}  {ip}".strip())
        
        return "\n".join(lines)
    except Exception as e:
        return f"DNSDumpster error: {e}"


@tool
def get_whois(url: str) -> str:
    """WHOIS lookup: registrar, nameservers, registration dates, org info."""
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    keywords = [
        "registrar", "name server", "creation", "expir",
        "registrant", "country", "org", "abuse", "updated"
    ]
    
    try:
        r = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=20
        )
        raw = r.stdout
        lines = [
            l for l in raw.splitlines()
            if any(k in l.lower() for k in keywords) and l.strip()
        ]
        return "\n".join(lines[:30]) or "No WHOIS data found"
    except Exception as e:
        return str(e)
