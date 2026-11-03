"""Offline rule-based LLM stand-in. Never touches the network."""
from __future__ import annotations

import json
from typing import Any

from .base import LLMClient, LLMResponse, ToolCall


def _est(obj: Any) -> int:
    return max(1, len(json.dumps(obj, ensure_ascii=False, default=str)) // 4)


class MockLLM(LLMClient):
    """Step 1: ask for extract_features. Step 2: score features (noisy-or) and answer."""

    def complete(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        tool_names = {t["name"] for t in tools}
        feats = self._find_features(messages)
        if feats is None and "extract_features" in tool_names:
            resp = LLMResponse(
                text="Extracting features.",
                tool_calls=[ToolCall(id="mock_1", name="extract_features", input={})],
            )
        else:
            miss = 1.0
            names = []
            for f in feats or []:
                miss *= 1.0 - float(f["weight"])
                names.append(f["name"])
            risk = round(100 * (1 - miss), 1)
            resp = LLMResponse(
                text=json.dumps(
                    {"risk": risk, "features": names, "rationale": f"rule-based score from {len(names)} features"}
                )
            )
        resp.input_tokens = _est(messages) + _est(system)
        resp.output_tokens = _est(resp.text) + 10 * len(resp.tool_calls)
        return resp

    @staticmethod
    def _find_features(messages) -> list[dict] | None:
        names: dict[str, str] = {}
        for m in messages:
            if m["role"] == "assistant" and isinstance(m["content"], list):
                for b in m["content"]:
                    if b.get("type") == "tool_use":
                        names[b["id"]] = b["name"]
        for m in reversed(messages):
            if m["role"] == "user" and isinstance(m["content"], list):
                for b in m["content"]:
                    if b.get("type") == "tool_result" and names.get(b["tool_use_id"]) == "extract_features":
                        try:
                            return json.loads(b["content"])["features"]
                        except (ValueError, KeyError, TypeError):
                            return []
        return None
