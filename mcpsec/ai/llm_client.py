"""LLM client supporting multiple providers."""

import json
import httpx
from typing import Optional

from mcpsec.config import get_api_key, PROVIDERS


class LLMClient:
    """Calls LLM APIs. Supports DeepSeek, Groq, OpenAI, Anthropic, Google, Ollama."""
    
    def __init__(self):
        provider, api_key, base_url, model = get_api_key()
        
        self.provider = provider
        self.api_key = api_key or ""
        self.base_url = base_url or ""
        self.model = model or ""
    
    @property
    def available(self) -> bool:
        return self.provider is not None
    
    async def chat(self, system: str, user: str, temperature: float = 0.1) -> Optional[str]:
        """Send a chat completion request."""
        if not self.available:
            return None
        
        if self.provider == "anthropic":
            return await self._call_anthropic(system, user, temperature)
        elif self.provider == "google":
            return await self._call_google(system, user, temperature)
        else:
            # DeepSeek, Groq, OpenAI, Ollama — all OpenAI-compatible
            return await self._call_openai_compat(system, user, temperature)
    
    async def _call_openai_compat(self, system: str, user: str, temp: float) -> Optional[str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temp,
            "max_tokens": 4000,
        }
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
            except Exception as e:
                return None
    
    async def _call_anthropic(self, system: str, user: str, temp: float) -> Optional[str]:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "max_tokens": 4000,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": temp,
        }
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/messages",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()["content"][0]["text"]
            except Exception as e:
                return None

    async def _call_google(self, system: str, user: str, temp: float) -> Optional[str]:
        """Call Google Gemini API (native format)."""
        url = (
            f"{self.base_url}/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": 4000,
            },
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                return None
