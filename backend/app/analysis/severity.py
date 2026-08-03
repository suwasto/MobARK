"""Per-tool severity normalization — single source of truth.

The findings table stores one of: critical | high | medium | low | info.
Each tool's native severity vocabulary is mapped here so the rest of the
codebase never sees tool-specific severity strings.
"""
from __future__ import annotations

# Semgrep JSON reports ERROR / WARNING / INFO.
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}

# Gitleaks has no severity concept; secrets default to ``high`` with a
# per-rule override table for rules we treat as direct compromise.
GITLEAKS_DEFAULT = "high"
GITLEAKS_OVERRIDES = {
    "aws-access-token": "critical",
    "aws-secret-access-key": "critical",
    "gcp-api-key": "critical",
    "google-api-key": "critical",
    "azure-active-directory-client-secret": "critical",
    "stripe-access-token": "critical",
    "github-pat": "critical",
    "gitlab-pat": "critical",
    "slack-webhook-url": "critical",
    "sendgrid-api-key": "critical",
    "twilio-api-key": "critical",
    "private-key": "critical",
    "asymmetric-private-key": "critical",
    "ssh-private-key": "critical",
    "pkcs8-private-key": "critical",
}


def gitleaks_severity(rule_id: str) -> str:
    return GITLEAKS_OVERRIDES.get(rule_id, GITLEAKS_DEFAULT)
