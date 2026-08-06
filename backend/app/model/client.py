"""Thin wrappers over LiteLLM (M3 model client: ``chat()`` + ``model_string()``).

The M4 embedding path (``embed_texts``) was removed from v1 by owner
decision — RAG was replaced with non-embedding agent layers; no vector
store exists anymore.
"""
from __future__ import annotations

import litellm

from app.model.backends import ModelBackend

# Ignore parameters the backend doesn't support instead of erroring (e.g.
# ``max_tokens`` vs ``max_completion_tokens`` differences across providers).
litellm.drop_params = True


def model_string(backend: ModelBackend) -> str:
    """LiteLLM model string for a backend: provider prefix + configured model.

    Examples: ``ollama/qwen2.5``, ``openai/gpt-4o-mini``, ``my-model`` (custom).

    Raises ValueError when no model is configured — callers decide how to
    surface that (the health check treats it as "nothing to probe").
    """
    if not backend.model:
        raise ValueError(f"backend '{backend.id}' has no model configured")
    return f"{backend.provider.model_prefix}{backend.model}"


def chat(
    backend: ModelBackend,
    messages: list[dict],
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
    timeout: float = 60.0,
    **kwargs,
):
    """Run a chat completion against ``backend``.

    ``messages`` uses the standard OpenAI format. Returns the raw litellm
    response object — callers read ``response.choices[0].message.content``.
    Raises ValueError if no model is configured, or the underlying litellm
    error otherwise (M5's callers decide how to surface it).
    """
    return litellm.completion(
        model=model_string(backend),
        messages=messages,
        api_base=backend.base_url or None,
        api_key=backend.api_key or None,  # local backends carry a dummy key
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
        **kwargs,
    )
