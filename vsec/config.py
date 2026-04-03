"""
VSec Configuration — Settings and paths
"""
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    """VSec configuration settings."""
    
    # API Keys
    anthropic_api_key: str | None = None
    dnsdumpster_api_key: str | None = None
    
    # Paths
    base_dir: Path = Path(__file__).parent.parent
    wordlist_dir: Path = None
    wordlist_sub: Path = None
    cve_csv_path: Path = None
    reports_dir: Path = None
    
    # Tool settings
    shell_enabled: bool = False
    cve_enabled: bool = True
    
    def __post_init__(self):
        """Initialize paths based on base_dir."""
        if self.anthropic_api_key is None:
            self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        if self.dnsdumpster_api_key is None:
            self.dnsdumpster_api_key = os.getenv("DNSDumpster_API_KEY")
        
        if self.wordlist_dir is None:
            self.wordlist_dir = self.base_dir / "common.txt"
        if self.wordlist_sub is None:
            self.wordlist_sub = self.base_dir / "subdomains-top1million-20000.txt"
        if self.cve_csv_path is None:
            self.cve_csv_path = self.base_dir / "cve-common-vulnerabilities-and-exposures" / "cve.csv"
        if self.reports_dir is None:
            self.reports_dir = self.base_dir / "reports"


# Global settings instance
settings = Settings()
