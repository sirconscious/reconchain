"""
VSec Providers — OpenAI

Provider for OpenAI's GPT models.
"""
import os
from typing import Any

from vsec.providers.base import BaseModel, ModelInfo, register_provider


class OpenAIProvider(BaseModel):
    """OpenAI GPT model provider."""
    
    name = "openai"
    display_name = "OpenAI GPT"
    
    def create(self, **kwargs) -> Any:
        from langchain_openai import ChatOpenAI
        
        api_key = os.getenv(self.get_env_key())
        model = kwargs.get("model", self.get_default_model())
        temperature = kwargs.get("temperature", 0)
        max_tokens = kwargs.get("max_tokens", 4096)
        
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    
    @staticmethod
    def get_env_key() -> str:
        return "OPENAI_API_KEY"
    
    @staticmethod
    def get_default_model() -> str:
        return "gpt-4o-mini"
    
    @staticmethod
    def get_available_models() -> list[str]:
        return [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
        ]


register_provider(ModelInfo(
    name="openai",
    display_name="OpenAI GPT",
    class_path="vsec.providers.openai:OpenAIProvider",
    default_model="gpt-4o-mini",
    available_models=[
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-3.5-turbo",
    ],
    env_key="OPENAI_API_KEY",
    api_key_required=True,
    supports_system_message=True,
))
