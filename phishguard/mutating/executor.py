"""Performs (simulated) state changes. Only callable with a gateway-issued grant.

Honest limit: the grant is an in-process guard against accidental/LLM-driven calls,
not a defence against arbitrary code running in the same process. For a real
boundary, run this package as a separate service with its own credentials.
"""

from __future__ import annotations

from collections.abc import Callable
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


Handler = Callable[[dict[str, Any]], dict[str, Any]]


class Executor:
    """Records every effect in `ledger`. Actions without a handler are simulated (money moves, account
    changes). Actions with a handler (mailbox remediation, see remediation.py) call the provider; a
    failing handler is reported as {"ok": False, "error": ...}, never as success."""

    def __init__(self, handlers: dict[ActionType, Handler] | None = None) -> None:
        self.ledger: list[dict[str, Any]] = []
        self.handlers = dict(handlers or {})

    def run(self, grant: ExecutionGrant, action: ActionType, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(grant, ExecutionGrant):
            raise PermissionError("missing execution grant")
        result: dict[str, Any] = {"ok": True}
        handler = self.handlers.get(action)
        if handler is not None:
            try:
                result = {"ok": True, **(handler(params) or {})}
            except Exception as e:  # noqa: BLE001 - provider failures must not look like success
                from ..connectors.secrets import redact

                result = {"ok": False, "error": redact(f"{type(e).__name__}: {e}")[:300]}
        effect = {"action": action.value, "params": params, "digest": grant.digest, "result": result}
        self.ledger.append(effect)
        return {**result, "effect_index": len(self.ledger) - 1}
