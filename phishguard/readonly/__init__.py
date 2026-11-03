"""READ-ONLY package. It must never import phishguard.mutating (enforced by tests)."""

from ..models import EmailMessage
from .eml import EmlTooLarge, parse_eml
from .features import DetectionContext, Feature, explain, extract_features, risk_percent
from .tools import READ_ONLY_TOOL_NAMES, ReadOnlyToolbox


def analyze_email(email: EmailMessage, ctx: DetectionContext | None = None) -> tuple[float, list[Feature]]:
    """Return (risk 0-100, features sorted by contribution; contributions sum to the risk)."""
    feats = extract_features(email, ctx)
    return risk_percent(feats), explain(feats)


__all__ = [
    "DetectionContext",
    "EmlTooLarge",
    "Feature",
    "READ_ONLY_TOOL_NAMES",
    "ReadOnlyToolbox",
    "analyze_email",
    "explain",
    "extract_features",
    "parse_eml",
    "risk_percent",
]
