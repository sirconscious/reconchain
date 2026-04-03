"""
VSec Providers — Groq

Provider for Groq's free fast inference API.
Uses OpenAI-compatible API.
"""
import os
from typing import Any

from vsec.providers.base import BaseModel, ModelInfo, register_provider


class GroqProvider(BaseModel):
    """Groq free inference provider."""
    
    name = "groq"
    display_name = "Groq (Free)"
    
    def create(self, **kwargs) -> Any:
        from langchain_openai import ChatOpenAI
        
        api_key = os.getenv(self.get_env_key())
        model = kwargs.get("model", self.get_default_model())
        temperature = kwargs.get("temperature", 0)
        max_tokens = kwargs.get("max_tokens", 4096)
        
        return ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            temperature=temperature,
            max_tokens=max_tokens,
        )
    
    @staticmethod
    def get_env_key() -> str:
        return "GROQ_API_KEY"
    
    @staticmethod
    def get_default_model() -> str:
        return "llama-3.1-8b-instant"
    
    @staticmethod
    def get_available_models() -> list[str]:
        return [
            "llama-3.1-8b-instant",
            "llama-3.1-70b-versatile",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
        ]


register_provider(ModelInfo(
    name="groq",
    display_name="Groq (Free)",
    class_path="vsec.providers.groq:GroqProvider",
    default_model="llama-3.1-8b-instant",
    available_models=[
        "llama-3.1-8b-instant",
        "llama-3.1-70b-versatile",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ],
    env_key="GROQ_API_KEY",
    api_key_required=True,
    supports_system_message=True,
))
