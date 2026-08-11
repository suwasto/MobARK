"""Shared chat-model selection for every LLM-backed surface.

M4 agent chat, M5 per-finding explain, and M5 overview summary all resolve
the chat model the same way: the first enabled backend with a configured
model, else ``NoModelConfigured`` (the API maps it to HTTP 400). One rule,
one message - no drift between surfaces.
"""
from __future__ import annotations

from app.model.backends import get_store


class NoModelConfigured(RuntimeError):
    """No enabled backend has a configured chat model."""


def pick_chat_backend():
    """First enabled backend with a configured model (M3 store, no default).

    Raises :class:`NoModelConfigured` when Settings has no usable model -
    callers decide how to surface it (the API returns 400).
    """
    backends = [b for b in get_store().read() if b.enabled and b.model]
    if not backends:
        raise NoModelConfigured(
            "no chat model configured - pick a backend + model in Settings "
            "(API: PUT /api/v1/model/backends/{id})"
        )
    return backends[0]
