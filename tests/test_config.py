"""Tests for configuration management."""
import pytest

from mcpsec.config import PROVIDERS, get_api_key


def test_providers_defined():
    """PROVIDERS dict should have ≥5 entries with key providers present."""
    assert len(PROVIDERS) >= 5
    assert "deepseek" in PROVIDERS
    assert "openai" in PROVIDERS
    assert "anthropic" in PROVIDERS
    assert "ollama" in PROVIDERS


def test_provider_entries_have_required_keys():
    """Each provider entry should have name, base_url, and model."""
    for pid, info in PROVIDERS.items():
        assert "name" in info, f"Provider {pid} missing 'name'"
        assert "base_url" in info, f"Provider {pid} missing 'base_url'"
        assert "model" in info, f"Provider {pid} missing 'model'"


def test_get_api_key_returns_4_tuple():
    """get_api_key() should return a 4-tuple (provider, key, base_url, model)."""
    result = get_api_key()
    assert isinstance(result, tuple)
    assert len(result) == 4
