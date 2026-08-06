"""M5 risk score — deterministic severity-weighted 0-100 aggregate.

Single source of truth for the Overview gauge (and any future report
surface): the dashboard, the API, and the scan job all read the same
weights. v1 heuristic, documented in docs/progress/M5.md:

- weights: critical=10, high=7, medium=4, low=1, info=0
- ``n`` = findings with severity > info
- score = min(100, round(100 * raw / (10 * n))) — the weighted mean relative
  to the maximum possible mean (10); 0 when there is nothing to score.

Sanity check (mockup's illustrative 2C/4H/5M/1L): raw = 69, n = 12 →
round(100*69/120) = 58/100. The mockup's 67 was decorative.
"""
from __future__ import annotations

# Order also drives findings-list sort (critical first).
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

# Display order by weight for the findings list.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def compute_risk_score(findings) -> int:
    """0-100 risk score for a collection of findings.

    ``findings`` is any iterable of objects exposing ``.severity`` — the
    analysis layer's ``FindingOut`` dataclass and the persisted ``Finding``
    ORM both qualify. Unknown severities are ignored rather than crashing
    the scan or the dashboard.
    """
    weights = [SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings]
    scored = [w for w in weights if w > 0]
    if not scored:
        return 0
    raw = sum(weights)
    n = len(scored)
    return min(100, round(100 * raw / (10 * n)))
