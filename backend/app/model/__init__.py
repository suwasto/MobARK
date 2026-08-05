"""M3 — model backend abstraction: LiteLLM client + config store + health checks.

Phase 1-3 of the M3 plan (see docs/progress/M3.md). Embeddings / ChromaDB
were deferred to M4 by owner decision, so no vector code lives here yet.
"""
import litellm

# Quiet, consistent behavior across all backends: never raise on params a
# backend doesn't support, and don't print litellm's debug/feedback noise
# into the API/CLI output on errors.
litellm.drop_params = True
litellm.suppress_debug_info = True
litellm.verbose = False
