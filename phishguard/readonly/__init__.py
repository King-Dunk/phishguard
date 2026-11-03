"""READ-ONLY package. It must never import phishguard.mutating (enforced by tests)."""
from ..models import EmailMessage
from .features import DetectionContext, Feature, extract_features, risk_percent
from .tools import READ_ONLY_TOOL_NAMES, ReadOnlyToolbox


def analyze_email(email: EmailMessage, ctx: DetectionContext | None = None) -> tuple[float, list[Feature]]:
    feats = extract_features(email, ctx)
    return risk_percent(feats), feats


__all__ = [
    "DetectionContext",
    "Feature",
    "READ_ONLY_TOOL_NAMES",
    "ReadOnlyToolbox",
    "analyze_email",
    "extract_features",
    "risk_percent",
]
