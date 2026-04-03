"""
VSec Providers — Base Interface

Defines the interface all AI providers must implement.
"""
from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseModel(ABC):
    """Base class for all AI model providers."""
    
    name: str = "base"
    display_name: str = "Base Model"
    supports_system_message: bool = True
    
    @abstractmethod
    def create(self, **kwargs) -> Any:
        """Create and return the model instance."""
        pass
    
    @staticmethod
    def get_env_key() -> str:
        """Return the environment variable name for the API key."""
        return "API_KEY"
    
    @staticmethod
    def get_default_model() -> str:
        """Return the default model name."""
        return "default"
    
    @staticmethod
    def get_available_models() -> list[str]:
        """Return list of available model names for this provider."""
        return []


class ModelInfo:
    """Information about a model provider."""
    
    def __init__(
        self,
        name: str,
        display_name: str,
        class_path: str,
        default_model: str,
        available_models: list[str],
        env_key: str,
        api_key_required: bool = True,
        supports_system_message: bool = True,
    ):
        self.name = name
        self.display_name = display_name
        self.class_path = class_path
        self.default_model = default_model
        self.available_models = available_models
        self.env_key = env_key
        self.api_key_required = api_key_required
        self.supports_system_message = supports_system_message
    
    def __repr__(self):
        return f"<ModelInfo: {self.display_name} ({self.name})>"


# Registry of all available providers
PROVIDERS: dict[str, ModelInfo] = {}


def register_provider(provider: ModelInfo):
    """Decorator to register a provider."""
    PROVIDERS[provider.name] = provider
    return provider
