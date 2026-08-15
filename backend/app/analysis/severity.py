"""Per-tool severity normalization - single source of truth.

The findings table stores one of: high | warning | info (no critical band -
owner decision, Aug 8, 2026; the low band was dropped and medium renamed
warning Aug 15, 2026). Each tool's native severity
vocabulary is mapped here so the rest of the codebase never sees
 tool-specific severity strings.
"""
from __future__ import annotations

# Semgrep JSON reports ERROR / WARNING / INFO - the native WARNING maps
# straight onto the warning severity (the medium band was renamed warning
# Aug 15, 2026).
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "warning", "INFO": "info"}

# Per-rule severity overrides for the curated MobARK rules (the vendored MASTG
# rules keep their as-shipped severity - their calibration is a separate
# decision). Semgrep's ERROR already maps to high (the top severity since
# the critical band was removed), so these entries document which rules are
# treated as the worst class rather than changing the mapped value.
SEMGREP_OVERRIDES = {
    # Complete TLS verification bypass - direct MITM compromise.
    "mobark-android-all-hostname-verifier": "high",
    "mobark-android-insecure-trust-manager": "high",
}

# Gitleaks has no severity concept; secrets default to ``high`` with a
# per-rule override table for rules we treat as direct compromise. All map
# to ``high`` - the top severity in the post-critical vocabulary.
GITLEAKS_DEFAULT = "high"
GITLEAKS_OVERRIDES = {
    "aws-access-token": "high",
    "aws-secret-access-key": "high",
    "gcp-api-key": "high",
    "google-api-key": "high",
    "azure-active-directory-client-secret": "high",
    "stripe-access-token": "high",
    "github-pat": "high",
    "gitlab-pat": "high",
    "slack-webhook-url": "high",
    "sendgrid-api-key": "high",
    "twilio-api-key": "high",
    "private-key": "high",
    "asymmetric-private-key": "high",
    "ssh-private-key": "high",
    "pkcs8-private-key": "high",
}


def semgrep_severity(check_id: str, native_severity: str) -> str:
    """Map a semgrep JSON severity to a finding severity, honoring the
    per-rule override table first (owner calibration, Aug 7)."""
    return SEMGREP_OVERRIDES.get(
        check_id, SEMGREP_SEVERITY.get(native_severity, "info")
    )


def gitleaks_severity(rule_id: str) -> str:
    return GITLEAKS_OVERRIDES.get(rule_id, GITLEAKS_DEFAULT)
