"""Performs (simulated) state changes. Only callable with a gateway-issued grant.

Honest limit: the grant is an in-process guard against accidental/LLM-driven calls,
not a defence against arbitrary code running in the same process. For a real
boundary, run this package as a separate service with its own credentials.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
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
    """Records every effect in `ledger`. Without handlers that is all it does (simulated backend).

    `handlers` maps an action type to a real backend call, e.g. the mailbox remediation handlers
    from `mailbox.remediation_handlers()`. A handler only ever runs behind a gateway-issued grant.
    """

    def __init__(self, handlers: Mapping[ActionType, Handler] | None = None) -> None:
        self.ledger: list[dict[str, Any]] = []
        self.handlers: dict[ActionType, Handler] = dict(handlers or {})

    def run(self, grant: ExecutionGrant, action: ActionType, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(grant, ExecutionGrant):
            raise PermissionError("missing execution grant")
        effect: dict[str, Any] = {"action": action.value, "params": params, "digest": grant.digest}
        ok, outcome = True, None
        handler = self.handlers.get(action)
        if handler is not None:
            try:
                outcome = handler(params)
                ok = bool(outcome.get("ok", True))
            except Exception as e:  # noqa: BLE001 - report the failure; never leak secrets in it
                from ..connectors.secrets import redact

                ok, outcome = False, {"ok": False, "error": redact(f"{type(e).__name__}: {e}")[:300]}
            effect["outcome"] = outcome
        self.ledger.append(effect)
        result: dict[str, Any] = {"ok": ok, "effect_index": len(self.ledger) - 1}
        if outcome is not None:
            result["outcome"] = outcome
        return result
