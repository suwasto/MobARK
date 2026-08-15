"""M5 risk/security scores - banded risk index (0-100 aggregates).

Single source of truth for the Overview gauge (and any future report
surface): the dashboard, the API, and the scan job all read the same
mapping. Owner decision (Aug 15, 2026): the CVSS 4.0 model was REPLACED
by a plain **banded risk index**. CVSS qualitative scoring is designed
for disclosed vulnerabilities (CVEs) where a human analyst has assessed
attack requirements, user interaction, and the other metric inputs - a
static scanner sees candidate flaws in uncompiled/compiled code and
cannot honestly claim that context (the MobSF pattern: a simple severity
heuristic). The old implementation's "CVSS 4.0 · risk n/100 · band"
caption overclaimed CVSS provenance for a midpoint heuristic; the new
caption is the honest "risk n/100 · band".

- **Severity vocabulary:** ``high | warning | info`` (no critical band -
  owner decision Aug 8, 2026; the low band was dropped and former low
  findings became informational Aug 15, 2026; ``medium`` was renamed
  ``warning`` the same day).
- **risk = worst-first, banded**: the worst finding picks the band - any
  high sets the High band (base 70), otherwise warnings set the Warning
  band (base 40) - and each additional finding at that band adds ~1 point,
  capped at the band ceiling (high 99 · warning 69). Info findings never
  score. Bands never overlap (any high ≥ 70 > any warning ≤ 69 > info-only
  0), so worst-first ordering is preserved and remediating/suppressing
  findings visibly moves the gauge within each band (11 highs = 80 · 2 =
  71 · 1 = 70; 30 warnings = 69 · 10 = 49 · 1 = 40). 0 when there is
  nothing to score.
- **security = 100 - risk** - the public-facing score (owner decision, Aug
  7: higher is better). An empty scan scores 100; risk 70 → security 30.
- **Suppressed findings are excluded** (Aug 8, 2026): a false positive that
  was suppressed must not drive the posture - ``compute_risk_score`` skips
  any finding with ``suppressed=True`` (persisted ``Finding`` rows carry
  the flag; analysis-layer ``FindingOut`` objects don't, so ``getattr``
  keeps both call sites working).

The DB column stays ``risk_score`` (internal); ``security_score`` is derived
on read so the two can never drift.
"""
from __future__ import annotations

# Per-severity ordinal weight (ordering only - not the score itself).
# info is 0: informational notes never drive the posture.
SEVERITY_WEIGHT = {
    "high": 3,
    "warning": 2,
    "info": 0,
}

# Worst + breadth, banded (owner decision, Aug 15 2026): (base risk,
# ceiling, bonus slope). The worst finding picks the band; each extra
# finding at that band adds ~1 point (rounded), capped at the ceiling.
# Bands never overlap: any high ≥ 70 > any warning ≤ 69 > info-only 0.
_BAND_RISK = {
    "high": (70, 99, 1.0),
    "warning": (40, 69, 1.0),
}

# Display order by severity for the findings list.
SEVERITY_ORDER: tuple[str, ...] = ("high", "warning", "info")


def severity_weight(severity: str) -> float:
    """Ordinal severity weight (0.0-3.0) - drives ordering, not the score."""
    return SEVERITY_WEIGHT.get(severity, 0.0)


def compute_risk_score(findings) -> int:
    """0-100 risk score for a collection of findings.

    Worst-first, banded, over the scored findings (severity in high |
    warning): the worst finding picks the band - any high sets the High
    band (base 70), otherwise warnings set the Warning band (base 40) -
    and each extra finding at that band adds ~1 point capped at the band
    ceiling (high 99 · warning 69). So suppressing/fixing findings visibly
    moves the gauge within each band (11 highs = 80 · 2 = 71 · 1 = 70;
    30 warnings = 69 · 10 = 49 · 1 = 40), worst-first order is preserved
    with no band overlap (any high ≥ 70 > any warning ≤ 69 > info-only 0),
    and the honest "risk n/100 · band" caption stays literally true.
    ``findings`` is any iterable of objects exposing ``.severity`` - the
    analysis layer's ``FindingOut`` dataclass and the persisted ``Finding``
    ORM both qualify. Unknown severities are ignored rather than crashing
    the scan or the dashboard. Suppressed findings (``suppressed=True`` on
    persisted rows) are skipped so a suppressed false positive never drives
    the posture.
    """
    scored = []
    for f in findings:
        if getattr(f, "suppressed", False):
            continue
        if f.severity in _BAND_RISK:
            scored.append(f.severity)
    if not scored:
        return 0
    worst_sev = "high" if "high" in scored else "warning"
    base, ceiling, per_extra = _BAND_RISK[worst_sev]
    extra = scored.count(worst_sev) - 1
    bonus = min(
        ceiling - base,
        int(per_extra * max(0, extra) + 0.5),
    )
    return base + bonus


def compute_security_score(findings) -> int:
    """0-100 security score - the public-facing complement of the risk score.

    Higher is better: ``security = 100 - risk``. An empty finding set has no
    risk, so it scores 100.
    """
    return 100 - compute_risk_score(findings)


def security_from_risk(risk_score: int | None) -> int | None:
    """Derive the security score from a persisted risk score (None in, None
    out) - used by the Scan API read path so stored and derived values never
    drift."""
    if risk_score is None:
        return None
    return 100 - risk_score
