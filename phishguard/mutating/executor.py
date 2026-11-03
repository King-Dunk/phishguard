"""Performs (simulated) state changes. Only callable with a gateway-issued grant.

Honest limit: the grant is an in-process guard against accidental/LLM-driven calls,
not a defence against arbitrary code running in the same process. For a real
boundary, run this package as a separate service with its own credentials.
"""
from __future__ import annotations

from typing import Any

from .policy import ActionType

_SECRET = object()


class ExecutionGrant:
    def __init__(self, token: object, digest: str):
        if token is not _SECRET:
            raise PermissionError("execution grants can only be issued by the MFA gateway")
        self.digest = digest


def _issue_grant(digest: str) -> ExecutionGrant:  # used by gateway.py only
    return ExecutionGrant(_SECRET, digest)


class Executor:
    """Simulated backend: records effects in `ledger` instead of touching real systems."""

    def __init__(self) -> None:
        self.ledger: list[dict[str, Any]] = []

    def run(self, grant: ExecutionGrant, action: ActionType, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(grant, ExecutionGrant):
            raise PermissionError("missing execution grant")
        effect = {"action": action.value, "params": params, "digest": grant.digest}
        self.ledger.append(effect)
        return {"ok": True, "effect_index": len(self.ledger) - 1}
