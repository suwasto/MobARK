"""Thin wrappers over LiteLLM (M3 model client: ``chat()`` + ``model_string()``).

The M4 embedding path (``embed_texts``) was removed from v1 by owner
decision - RAG was replaced with non-embedding agent layers; no vector
store exists anymore.
"""
from __future__ import annotations

import litellm

from app.model.backends import ModelBackend

# Ignore parameters the backend doesn't support instead of erroring (e.g.
# ``max_tokens`` vs ``max_completion_tokens`` differences across providers).
litellm.drop_params = True


def model_arch_hint(message: str) -> str:
    """Append an actionable hint when the upstream LLM server rejects the
    model: it cannot load the model's architecture (classic old-Ollama-vs-
    newer-model case), or the provider no longer serves the model (Google's
    ``no longer available to new users`` deprecation 404, Aug 2026).

    Shared by the Settings probe, agent chat, and the explain/summary
    insights so every surface gives the same actionable guidance.
    """
    if "unknown model architecture" in message:
        return message + (
            " - the model server cannot load this model's architecture; "
            "update the server (e.g. upgrade Ollama) or pick a model it supports"
        )
    if "no longer available to new users" in message:
        return message + (
            " - this model is no longer served to this account; pick a model "
            "the provider currently serves (Settings → model chip) or update "
            "the configured model"
        )
    return message


def model_string(backend: ModelBackend) -> str:
    """LiteLLM model string for a backend: provider prefix + configured model.

    Examples: ``ollama/qwen2.5``, ``openai/gpt-4o-mini``, ``my-model`` (custom).

    Raises ValueError when no model is configured - callers decide how to
    surface that (the health check treats it as "nothing to probe").
    """
    if not backend.model:
        raise ValueError(f"backend '{backend.id}' has no model configured")
    return f"{backend.provider.model_prefix}{backend.model}"


def _completion_kwargs(
    backend: ModelBackend,
    messages: list[dict],
    *,
    max_tokens: int | None,
    temperature: float | None,
    timeout: float,
    **kwargs,
) -> dict:
    """The litellm.completion kwargs shared by the buffered + streaming paths.

    Ollama backends additionally send ``think: false`` - local thinking
    models (e.g. Nanbeige4.2) would otherwise spend the whole agent budget
    inside ``<think>`` blocks and return near-empty content. Non-thinking
    models ignore the flag.
    """
    extra = dict(kwargs)
    if backend.provider_id == "ollama":
        body = dict(extra.get("extra_body") or {})
        body["think"] = False
        extra["extra_body"] = body
    return dict(
        model=model_string(backend),
        messages=messages,
        api_base=backend.base_url or None,
        # M9.1 vault: decrypts the at-rest blob with the session's master
        # key; local backends carry a dummy key that passes through.
        api_key=backend.resolved_api_key() or None,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
        **extra,
    )


def chat(
    backend: ModelBackend,
    messages: list[dict],
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
    timeout: float = 60.0,
    **kwargs,
):
    """Run a (buffered) chat completion against ``backend``.

    ``messages`` uses the standard OpenAI format. Returns the raw litellm
    response object - callers read ``response.choices[0].message.content``.
    Raises ValueError if no model is configured, or the underlying litellm
    error otherwise (M5's callers decide how to surface it).

    The dev-only ``fake`` backend (M6 follow-up) is short-circuited here -
    its completions never touch litellm.
    """
    from app.model.fake import fake_chat_response, is_fake

    if is_fake(backend):
        return fake_chat_response(messages, tools=kwargs.get("tools"))
    return litellm.completion(
        **_completion_kwargs(
            backend,
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
            **kwargs,
        )
    )


def chat_stream(
    backend: ModelBackend,
    messages: list[dict],
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
    timeout: float = 60.0,
    **kwargs,
):
    """Run a streaming chat completion; yields raw litellm chunks.

    Every chunk has the OpenAI ``ChatCompletionChunk`` shape litellm
    normalizes all providers to: ``chunk.choices[0].delta.content`` (text
    token or None) and ``delta.tool_calls`` (a list accumulating per
    ``index`` - ``arguments`` must be concatenated per index until the
    stream ends, then parsed as JSON). Content and tool calls can arrive in
    the same stream (a model that "thinks aloud" before calling a tool).

    Raises ValueError if no model is configured; a provider that ignores
    streaming still yields a single chunk with the full delta. The dev-only
    ``fake`` backend (M6 follow-up) short-circuits to a deterministic script.
    """
    from app.model.fake import fake_stream_chunks, is_fake

    if is_fake(backend):
        yield from fake_stream_chunks(messages, tools=kwargs.get("tools"))
        return
    response = litellm.completion(
        stream=True,
        **_completion_kwargs(
            backend,
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
            **kwargs,
        ),
    )
    yield from response
