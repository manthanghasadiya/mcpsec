"""LLM client supporting multiple providers."""

import os
import json
import httpx
from typing import Optional

class LLMClient:
    """Calls LLM APIs. Supports DeepSeek, OpenAI, Anthropic, Ollama."""
    
    def __init__(self):
        self.provider = None
        self.api_key = None
        self.base_url = None
        self.model = None
        
        # Priority: DeepSeek (cheapest) > OpenAI > Anthropic > Ollama (free)
        if os.environ.get("DEEPSEEK_API_KEY"):
            self.provider = "deepseek"
            self.api_key = os.environ["DEEPSEEK_API_KEY"]
            self.base_url = "https://api.deepseek.com/v1"
            self.model = "deepseek-chat"
        elif os.environ.get("OPENAI_API_KEY"):
            self.provider = "openai"
            self.api_key = os.environ["OPENAI_API_KEY"]
            self.base_url = "https://api.openai.com/v1"
            self.model = "gpt-4o-mini"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            self.provider = "anthropic"
            self.api_key = os.environ["ANTHROPIC_API_KEY"]
            self.base_url = "https://api.anthropic.com/v1"
            self.model = "claude-3-haiku-20240307"
        elif self._check_ollama():
            self.provider = "ollama"
            self.base_url = "http://localhost:11434/v1"
            self.model = "deepseek-coder-v2"
        else:
            self.provider = None
    
    def _check_ollama(self) -> bool:
        try:
            resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
            return resp.status_code == 200
        except Exception:
            return False
    
    @property
    def available(self) -> bool:
        return self.provider is not None
    
    async def chat(self, system: str, user: str, temperature: float = 0.1) -> Optional[str]:
        """Send a chat completion request."""
        if not self.available:
            return None
        
        if self.provider == "anthropic":
            return await self._call_anthropic(system, user, temperature)
        else:
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
