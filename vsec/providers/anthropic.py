"""
VSec Providers — Anthropic (Claude)

Provider for Anthropic's Claude models.
"""
import os
import sys
from typing import Any

from vsec.providers.base import BaseModel, ModelInfo, register_provider


class AnthropicProvider(BaseModel):
    """Anthropic Claude model provider."""
    
    name = "anthropic"
    display_name = "Anthropic Claude"
    
    def create(self, **kwargs) -> Any:
        from langchain_anthropic import ChatAnthropic
        
        api_key = os.getenv(self.get_env_key())
        model = kwargs.get("model", self.get_default_model())
        temperature = kwargs.get("temperature", 0)
        max_tokens = kwargs.get("max_tokens", 4096)
        
        return ChatAnthropic(
            model=model,
            anthropic_api_key=api_key,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    
    @staticmethod
    def get_env_key() -> str:
        return "ANTHROPIC_API_KEY"
    
    @staticmethod
    def get_default_model() -> str:
        return "claude-haiku-4-5"
    
    @staticmethod
    def get_available_models() -> list[str]:
        return [
            "claude-haiku-4-5",
            "claude-sonnet-4-5",
            "claude-opus-4-5",
        ]


# Register the provider
register_provider(ModelInfo(
    name="anthropic",
    display_name="Anthropic Claude",
    class_path="vsec.providers.anthropic:AnthropicProvider",
    default_model="claude-haiku-4-5",
    available_models=[
        "claude-haiku-4-5",
        "claude-sonnet-4-5",
        "claude-sonnet-4-20250514",
        "claude-opus-4-5",
    ],
    env_key="ANTHROPIC_API_KEY",
    api_key_required=True,
    supports_system_message=True,
))
