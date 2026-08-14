"""M9.1 Origin-check middleware (owner decision 8 - CSRF posture with zero
new dependencies).

The SPA is same-origin, mutating bodies are JSON-only, and the session
cookie is SameSite=Lax - the remaining CSRF gap is a cross-site form/JSON
POST, which a browser always sends with an ``Origin`` header. This
middleware rejects mutating ``/api/v1`` requests whose Origin netloc does
not match the Host. Non-browser clients (curl, tests, the CLI, native
tooling) send no Origin and pass through untouched.

Pure-ASGI (no BaseHTTPMiddleware) so streaming responses (the chat SSE
endpoint) are never buffered. Only enforced while auth is on: the
auth-off parity mode must stay byte-for-byte open.

Full CSRF tokens / login rate limiting are v1.1 items (see the M9.1 plan's
Out of scope).
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from app.config import settings

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class OriginCheckMiddleware:
    """Reject cross-origin mutating /api/v1 requests (Origin != Host)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "GET")
        path = scope.get("path", "")
        if (
            settings.auth_enabled
            and method in _MUTATING_METHODS
            and path.startswith("/api/v1")
        ):
            headers = {name: value for name, value in scope.get("headers", [])}
            origin = headers.get(b"origin")
            host = headers.get(b"host")
            if origin is not None and host is not None:
                origin_netloc = urlsplit(origin.decode("latin-1")).netloc.lower()
                if origin_netloc and origin_netloc != host.decode("latin-1").lower():
                    await _reject(scope, receive, send)
                    return
        await self.app(scope, receive, send)


async def _reject(scope, receive, send) -> None:
    """A minimal 403 JSON response (no framework dependency - pure ASGI)."""
    body = json.dumps({"detail": "cross-origin request rejected"}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
