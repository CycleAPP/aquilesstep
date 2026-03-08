"""Configurable AI provider for Aquiles.

Supports:
- DeepSeek (default, via OpenAI-compatible API)
- OpenAI
- Any OpenAI-compatible API (Ollama, LMStudio, etc.)

Configuration via environment variables:
- AQUILES_AI_PROVIDER: "deepseek" | "openai" | "custom"
- AQUILES_AI_API_KEY: API key (falls back to DEEPSEEK_API_KEY or OPENAI_API_KEY)
- AQUILES_AI_BASE_URL: Custom base URL (auto-set for deepseek/openai)
- AQUILES_AI_MODEL: Model name (defaults per provider)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class AIConfig:
    """AI provider configuration."""
    provider: str
    api_key: str
    base_url: str
    model: str
    available: bool

    @property
    def chat_model(self) -> str:
        return self.model


# Provider presets
PROVIDERS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.1",
        "env_key": "",
    },
}


def get_ai_config() -> AIConfig:
    """
    Resolve AI configuration from environment variables.
    
    Priority:
    1. AQUILES_AI_PROVIDER + AQUILES_AI_API_KEY (explicit)
    2. DEEPSEEK_API_KEY exists → use deepseek
    3. OPENAI_API_KEY exists → use openai
    4. No key → AI unavailable
    """
    provider = os.environ.get("AQUILES_AI_PROVIDER", "").lower()
    api_key = os.environ.get("AQUILES_AI_API_KEY", "")
    base_url = os.environ.get("AQUILES_AI_BASE_URL", "")
    model = os.environ.get("AQUILES_AI_MODEL", "")

    # Auto-detect provider from available keys
    if not provider:
        if os.environ.get("DEEPSEEK_API_KEY"):
            provider = "deepseek"
            api_key = api_key or os.environ["DEEPSEEK_API_KEY"]
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
            api_key = api_key or os.environ["OPENAI_API_KEY"]
        else:
            return AIConfig(
                provider="none",
                api_key="",
                base_url="",
                model="",
                available=False,
            )

    # Resolve from presets
    preset = PROVIDERS.get(provider, {})
    if not base_url:
        base_url = preset.get("base_url", "https://api.deepseek.com")
    if not model:
        model = preset.get("model", "deepseek-chat")
    if not api_key:
        env_key = preset.get("env_key", "")
        if env_key:
            api_key = os.environ.get(env_key, "")

    return AIConfig(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model,
        available=bool(api_key),
    )


def get_ai_client(config: AIConfig | None = None):
    """Create an OpenAI-compatible client with the configured provider."""
    if config is None:
        config = get_ai_config()

    if not config.available:
        return None

    from openai import OpenAI
    return OpenAI(
        api_key=config.api_key,
        base_url=config.base_url,
    )
