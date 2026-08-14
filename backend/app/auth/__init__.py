"""M9.1 user authentication: local password + sessions (Phase A), OAuth in
Phase B. Zero new runtime deps (owner decision): stdlib scrypt/hmac/secrets
for passwords and tokens, httpx (already pinned) for the OAuth flows.
"""
