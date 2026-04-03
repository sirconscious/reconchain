"""
VSec Providers — Ollama

Provider for local Ollama models.
Runs models locally on your machine.
"""
import os
from typing import Any

from vsec.providers.base import BaseModel, ModelInfo, register_provider


class OllamaProvider(BaseModel):
    """Ollama local model provider."""
    
    name = "ollama"
    display_name = "Ollama (Local)"
    
    def create(self, **kwargs) -> Any:
        from langchain_ollama import ChatOllama
        
        model = kwargs.get("model", self.get_default_model())
        temperature = kwargs.get("temperature", 0)
        base_url = kwargs.get("base_url", "http://localhost:11434")
        
        return ChatOllama(
            model=model,
            base_url=base_url,
            temperature=temperature,
        )
    
    @staticmethod
    def get_env_key() -> str:
        return ""
    
    @staticmethod
    def get_default_model() -> str:
        return "llama3.2"
    
    @staticmethod
    def get_available_models() -> list[str]:
        return [
            "llama3.2",
            "llama3.1",
            "llama3",
            "mistral",
            "codellama",
            "phi3",
            "qwen2.5",
        ]


register_provider(ModelInfo(
    name="ollama",
    display_name="Ollama (Local)",
    class_path="vsec.providers.ollama:OllamaProvider",
    default_model="llama3.2",
    available_models=[
        "llama3.2",
        "llama3.1",
        "llama3",
        "mistral",
        "codellama",
        "phi3",
        "qwen2.5",
    ],
    env_key="",
    api_key_required=False,
    supports_system_message=True,
))
