"""
VSec Providers — AI Model Provider System

Provides a unified interface for multiple AI providers:
- Anthropic (Claude)
- OpenAI (GPT)
- Groq (Free fast inference)
- Ollama (Local models)

Usage:
    from vsec.providers import create_model, list_providers, get_provider_info
    
    model = create_model(provider="groq", model="llama-3.1-8b-instant")
"""
import os
import importlib
from typing import Any

# Import base classes from base module
from vsec.providers.base import BaseModel, ModelInfo, PROVIDERS, register_provider

# Import all providers - they register themselves when imported
# Use absolute imports to avoid circular dependency issues
import vsec.providers.anthropic
import vsec.providers.openai
import vsec.providers.groq
import vsec.providers.ollama


def list_providers() -> list[ModelInfo]:
    """Return list of all registered providers."""
    return list(PROVIDERS.values())


def get_provider_info(provider_name: str) -> ModelInfo | None:
    """Get information about a specific provider."""
    return PROVIDERS.get(provider_name)


def get_default_provider() -> str:
    """Get the default provider based on available API keys."""
    priority = ["anthropic", "groq", "openai", "ollama"]
    
    for provider_name in priority:
        provider = PROVIDERS.get(provider_name)
        if provider:
            env_key = provider.env_key
            if env_key and os.getenv(env_key):
                return provider_name
    
    return "anthropic"


def create_model(
    provider: str | None = None,
    model: str | None = None,
    **kwargs
) -> Any:
    """
    Create a model instance for the specified provider.
    
    Args:
        provider: Provider name (anthropic, openai, groq, ollama)
                 If None, auto-detects based on available API keys
        model: Model name. If None, uses provider's default
        **kwargs: Additional arguments passed to the model
    
    Returns:
        Model instance (ChatAnthropic, ChatOpenAI, etc.)
    """
    if provider is None:
        provider = get_default_provider()
    
    provider_info = PROVIDERS.get(provider)
    if provider_info is None:
        available = ", ".join(PROVIDERS.keys())
        raise ValueError(
            f"Unknown provider: {provider}. "
            f"Available providers: {available}"
        )
    
    if model is None:
        model = provider_info.default_model
    
    # Import and instantiate the provider
    provider_module = _import_provider(provider_info.class_path)
    instance = provider_module()
    
    return instance.create(model=model, **kwargs)


def _import_provider(class_path: str) -> type[BaseModel]:
    """Import a provider class from its class path."""
    module_path, class_name = class_path.rsplit(":", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def check_provider_config(provider_name: str) -> dict[str, Any]:
    """Check if a provider is properly configured."""
    provider_info = PROVIDERS.get(provider_name)
    if not provider_info:
        return {"available": False, "reason": "Unknown provider"}
    
    env_key = provider_info.env_key
    
    if provider_info.api_key_required:
        api_key = os.getenv(env_key) if env_key else None
        if not api_key:
            return {
                "available": False,
                "reason": f"API key not set. Set {env_key} in .env"
            }
    
    return {
        "available": True,
        "env_key": env_key,
        "default_model": provider_info.default_model,
        "models": provider_info.available_models,
    }


__all__ = [
    "BaseModel",
    "ModelInfo",
    "PROVIDERS",
    "register_provider",
    "list_providers",
    "get_provider_info",
    "get_default_provider",
    "create_model",
    "check_provider_config",
]
