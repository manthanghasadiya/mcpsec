"""LLM client supporting multiple providers."""

from typing import Optional

import httpx

from mcpsec.config import get_api_key


class LLMError(Exception):
    """A configured LLM provider could not complete a request."""


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

    async def complete(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.1,
        max_tokens: int = 4000,
    ) -> Optional[str]:
        """Simplified completion method."""
        return await self.chat(system or "You are a helpful assistant.", prompt, temperature)

    async def chat(self, system: str, user: str, temperature: float = 0.1) -> Optional[str]:
        """Send a chat completion request."""
        if not self.available:
            return None

        try:
            if self.provider == "anthropic":
                result = await self._call_anthropic(system, user, temperature)
            elif self.provider == "google":
                result = await self._call_google(system, user, temperature)
            else:
                result = await self._call_openai_compat(system, user, temperature)
            if not isinstance(result, str) or not result.strip():
                raise LLMError(f"{self.provider} model {self.model}: empty response")
            return result
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            if self.api_key:
                body = body.replace(self.api_key, "[redacted]")
            raise LLMError(
                f"{self.provider} model {self.model}: HTTP {exc.response.status_code}: {body}"
            ) from None
        except httpx.RequestError as exc:
            # Do not include the URL: some providers put credentials in the query string.
            raise LLMError(f"{self.provider} model {self.model}: {type(exc).__name__}") from None
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError(
                f"{self.provider} model {self.model}: invalid response ({exc})"
            ) from None

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
            resp = await client.post(
                f"{self.base_url}/chat/completions", headers=headers, json=payload
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

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
            resp = await client.post(f"{self.base_url}/messages", headers=headers, json=payload)
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

    async def _call_google(self, system: str, user: str, temp: float) -> Optional[str]:
        """Call Google Gemini API (native format)."""
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
            "generationConfig": {
                "temperature": temp,
                "maxOutputTokens": 4000,
            },
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

