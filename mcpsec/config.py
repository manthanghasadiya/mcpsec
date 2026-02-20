"""
mcpsec configuration — API key management and provider config.

Config file: ~/.mcpsec/config.json
Resolution order: env var → config file → None
"""

import json
from pathlib import Path
from typing import Optional, Tuple

CONFIG_DIR = Path.home() / ".mcpsec"
CONFIG_FILE = CONFIG_DIR / "config.json"

PROVIDERS = {
    "deepseek": {
        "name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "env_var": "DEEPSEEK_API_KEY",
        "key_url": "https://platform.deepseek.com/api_keys",
        "description": "cheapest, recommended",
    },
    "groq": {
        "name": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "env_var": "GROQ_API_KEY",
        "key_url": "https://console.groq.com/keys",
        "description": "fast, free tier",
    },
    "openai": {
        "name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "env_var": "OPENAI_API_KEY",
        "key_url": "https://platform.openai.com/api-keys",
        "description": "GPT-4o",
    },
    "anthropic": {
        "name": "Anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-sonnet-4-20250514",
        "env_var": "ANTHROPIC_API_KEY",
        "key_url": "https://console.anthropic.com/",
        "description": "Claude",
    },
    "google": {
        "name": "Google",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "model": "gemini-2.0-flash",
        "env_var": "GOOGLE_API_KEY",
        "key_url": "https://aistudio.google.com/apikey",
        "description": "Gemini",
    },
    "ollama": {
        "name": "Ollama",
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.2",
        "env_var": None,
        "key_url": "https://ollama.com/download",
        "description": "local, free",
    },
}


def load_config() -> dict:
    """Load config from ~/.mcpsec/config.json."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_config(provider: str, api_key: str = "") -> None:
    """Save provider and API key to config file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    provider_info = PROVIDERS.get(provider, {})
    config = {
        "ai_provider": provider,
        "api_key": api_key,
        "model": provider_info.get("model", ""),
        "base_url": provider_info.get("base_url", ""),
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")


def get_api_key() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Resolve API key. Returns (provider, api_key, base_url, model).
    
    Resolution order:
    1. Environment variables (highest priority)
    2. ~/.mcpsec/config.json
    3. Ollama (if running locally)
    4. (None, None, None, None)
    """
    import os
    
    # 1. Check environment variables
    for provider_id, info in PROVIDERS.items():
        env_var = info.get("env_var")
        if env_var and os.environ.get(env_var):
            return (provider_id, os.environ[env_var], info["base_url"], info["model"])
    
    # 2. Check config file
    config = load_config()
    if config.get("ai_provider") and config.get("api_key"):
        provider_id = config["ai_provider"]
        info = PROVIDERS.get(provider_id, {})
        return (
            provider_id,
            config["api_key"],
            config.get("base_url") or info.get("base_url", ""),
            config.get("model") or info.get("model", ""),
        )
    
    # 3. Check Ollama
    if config.get("ai_provider") == "ollama":
        info = PROVIDERS["ollama"]
        return ("ollama", "", info["base_url"], config.get("model") or info["model"])
    
    try:
        import httpx
        resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
        if resp.status_code == 200:
            info = PROVIDERS["ollama"]
            return ("ollama", "", info["base_url"], info["model"])
    except Exception:
        pass
    
    # 4. Nothing found
    return (None, None, None, None)
