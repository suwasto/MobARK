"""M5 risk/security scores — CVSS 4.0-based 0-100 aggregates.

Single source of truth for the Overview gauge (and any future report
surface): the dashboard, the API, and the scan job all read the same
mapping. Owner decision (Aug 7, 2026): the scoring system is **CVSS 4.0**.

- Every severity band maps to a representative CVSS 4.0 base score — the
  midpoint of the qualitative band per the CVSS 4.0 specification
  (high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9, none 0): high 8.0, medium
  5.5, low 2.0, info 0. Owner decision (Aug 8, 2026): the critical band
  was removed from the findings vocabulary — high is the top severity.
- **risk = round(10 × max_cvss)** — the overall score is driven by the
  single worst finding (owner decision: max, not mean). 0 when there is
  nothing to score.
- **security = 100 - risk** — the public-facing score (owner decision, Aug
  7: higher is better). An empty scan scores 100; risk 80 → security 20.
- **Suppressed findings are excluded** (Aug 8, 2026): a false positive that
  was suppressed must not drive the posture — ``compute_risk_score`` skips
  any finding with ``suppressed=True`` (persisted ``Finding`` rows carry
  the flag; analysis-layer ``FindingOut`` objects don't, so ``getattr``
  keeps both call sites working).

The DB column stays ``risk_score`` (internal); ``security_score`` is derived
on read so the two can never drift.
"""
from __future__ import annotations

# CVSS 4.0 representative base score per severity band. Order also drives
# the findings-list sort (highest first).
SEVERITY_CVSS = {
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
    "info": 0.0,
}

# Display order by severity for the findings list.
SEVERITY_ORDER: tuple[str, ...] = ("high", "medium", "low", "info")


def cvss_base_score(severity: str) -> float:
    """Representative CVSS 4.0 base score for a severity band (0.0-8.0)."""
    return SEVERITY_CVSS.get(severity, 0.0)


def compute_risk_score(findings) -> int:
    """0-100 risk score for a collection of findings.

    Driven by the single worst finding: ``round(10 * max(cvss))`` over the
    scored findings (severity != info). ``findings`` is any iterable of
    objects exposing ``.severity`` — the analysis layer's ``FindingOut``
    dataclass and the persisted ``Finding`` ORM both qualify. Unknown
    severities are ignored rather than crashing the scan or the dashboard.
    Suppressed findings (``suppressed=True`` on persisted rows) are skipped
    so a suppressed false positive never drives the posture.
    """
    scored = [
        cvss_base_score(f.severity)
        for f in findings
        if not getattr(f, "suppressed", False)
        and cvss_base_score(f.severity) > 0
    ]
    if not scored:
        return 0
    return min(100, round(10 * max(scored)))


def compute_security_score(findings) -> int:
    """0-100 security score — the public-facing complement of the risk score.

    Higher is better: ``security = 100 - risk``. An empty finding set has no
    risk, so it scores 100.
    """
    return 100 - compute_risk_score(findings)


def security_from_risk(risk_score: int | None) -> int | None:
    """Derive the security score from a persisted risk score (None in, None
    out) — used by the Scan API read path so stored and derived values never
    drift."""
    if risk_score is None:
        return None
    return 100 - risk_score
