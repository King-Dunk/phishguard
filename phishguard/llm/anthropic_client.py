"""Real Anthropic client. Key comes from Settings (ANTHROPIC_API_KEY env var) only."""
from __future__ import annotations

from ..config import Settings
from .base import LLMClient, LLMResponse, MissingAPIKeyError, ToolCall


class AnthropicLLM(LLMClient):
    def __init__(self, settings: Settings):
        if not settings.api_key:
            raise MissingAPIKeyError("ANTHROPIC_API_KEY is not set in the environment")
        import anthropic  # lazy: mock mode never imports the SDK

        self._client = anthropic.Anthropic(api_key=settings.api_key)
        self._model = settings.model

    def complete(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        resp = self._client.messages.create(
            model=self._model,
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
        )
        out = LLMResponse(input_tokens=resp.usage.input_tokens, output_tokens=resp.usage.output_tokens)
        for block in resp.content:
            if block.type == "text":
                out.text += block.text
            elif block.type == "tool_use":
                out.tool_calls.append(ToolCall(id=block.id, name=block.name, input=dict(block.input)))
        return out
