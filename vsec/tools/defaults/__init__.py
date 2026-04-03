"""
VSec Defaults Package — Built-in tools
"""
from vsec.tools.defaults.dns import get_dnsdumpster, get_whois
from vsec.tools.defaults.web import get_http_headers, get_robots_txt, get_nmap_scan, check_common_paths
from vsec.tools.defaults.fuzz import run_gobuster_dirs, run_gobuster_subs, detect_technologies
from vsec.tools.defaults.cve import retrieve_cve_info
from vsec.tools.defaults.utils import shell

__all__ = [
    "get_dnsdumpster",
    "get_whois",
    "get_http_headers",
    "get_robots_txt",
    "get_nmap_scan",
    "check_common_paths",
    "run_gobuster_dirs",
    "run_gobuster_subs",
    "detect_technologies",
    "retrieve_cve_info",
    "shell",
]
