"""M9.1 per-user store resolution + vault context (Phase C + vault).

``current_user_id`` is how the STORE factories resolve the owning user
without threading a store through every call site:

- ``get_current_user`` (the router guard) sets it at the start of every
  guarded request, so the API routes (model/search backends) and the
  request-thread agent reads (``pick_chat_backend``, ``web_tools_allowed``)
  all resolve the CALLER's store.
- ``answer_question`` re-sets it from its explicit ``user_id`` argument at
  the top of the worker thread the chat/stream route runs in (a new thread
  does NOT inherit the request thread's contextvars, so the streaming loop
  must set it itself).
- The CLI never sets it -> the system store (root files), by design (the
  CLI is the host-operator surface).

AUTH-OFF mode: ``get_current_user`` sets it to None -> every store read
falls back to the system store, byte-for-byte the pre-M9.1 behavior.

``current_master_key`` is the session's UNWRAPPED vault master key (or
None when the vault is locked). ``get_current_user`` unwraps it from the
session row (``sessions.vault_wrap``) using the cookie-held token;
``answer_question`` re-sets it from its explicit ``master_key`` argument in
the worker thread, exactly like ``current_user_id``. The store layer reads
it to encrypt keys at rest and to decrypt them at use
(``resolved_api_key``) - never persisted, never logged, request-scoped.
"""
from __future__ import annotations

from contextvars import ContextVar

current_user_id: ContextVar[int | None] = ContextVar(
    "mobark_current_user_id", default=None
)

current_master_key: ContextVar[bytes | None] = ContextVar(
    "mobark_current_master_key", default=None
)
