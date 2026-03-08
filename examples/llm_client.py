"""
Ollama LLM client with hardened system prompt.
"""

import httpx


class LLMClient:
    def __init__(self, base_url: str, model: str, system_prompt: str):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.system_prompt = system_prompt
        self.client = httpx.AsyncClient(timeout=120.0)

    async def generate(self, user_message: str) -> str:
        """Send a message to Ollama and return the response."""
        response = await self.client.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "stream": False,
            },
        )
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "")

    async def is_available(self) -> bool:
        """Check if Ollama is reachable."""
        try:
            resp = await self.client.get(f"{self.base_url}/api/tags")
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self):
        await self.client.aclose()
