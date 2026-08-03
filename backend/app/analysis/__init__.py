"""M1 — Android analysis core.

Stages: jadx (decompile), androguard (manifest/cert), semgrep (code
patterns), gitleaks (secrets). All external CLIs are invoked strictly as
subprocesses, never imported, per the project's license posture.
"""
