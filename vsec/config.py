"""
VSec Configuration — Settings and paths

Configuration can be set via environment variables or .env file.

Provider Settings:
    VSEC_PROVIDER    - Provider to use (anthropic, openai, groq, ollama)
    VSEC_MODEL       - Model name (optional, defaults to provider's default)

Provider API Keys:
    ANTHROPIC_API_KEY  - For Anthropic Claude
    OPENAI_API_KEY     - For OpenAI GPT
    GROQ_API_KEY       - For Groq (free)

Tool Settings:
    DNSDumpster_API_KEY - For DNS recon
"""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    """VSec configuration settings."""
    
    # Provider settings
    provider: str = "anthropic"
    model: str = "claude-haiku-4-5"
    
    # API Keys (loaded from env)
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    groq_api_key: str | None = None
    dnsdumpster_api_key: str | None = None
    
    # Paths
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    wordlist_dir: Path | None = None
    wordlist_sub: Path | None = None
    cve_csv_path: Path | None = None
    reports_dir: Path | None = None
    
    # Tool settings
    shell_enabled: bool = False
    cve_enabled: bool = True
    
    def __post_init__(self):
        """Initialize settings from environment variables."""
        # Provider settings
        self.provider = os.getenv("VSEC_PROVIDER", self.provider)
        self.model = os.getenv("VSEC_MODEL", self.model)
        
        # API Keys
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.dnsdumpster_api_key = os.getenv("DNSDumpster_API_KEY")
        
        # Paths
        if self.wordlist_dir is None:
            self.wordlist_dir = self.base_dir / "common.txt"
        if self.wordlist_sub is None:
            self.wordlist_sub = self.base_dir / "subdomains-top1million-20000.txt"
        if self.cve_csv_path is None:
            self.cve_csv_path = self.base_dir / "cve-common-vulnerabilities-and-exposures" / "cve.csv"
        if self.reports_dir is None:
            self.reports_dir = self.base_dir / "reports"
    
    def to_dict(self) -> dict[str, Any]:
        """Return settings as a dictionary (for display)."""
        return {
            "provider": self.provider,
            "model": self.model or "default",
            "shell_enabled": self.shell_enabled,
            "cve_enabled": self.cve_enabled,
            "reports_dir": str(self.reports_dir),
        }


# Global settings instance
settings = Settings()
