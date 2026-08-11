"""Graphify code-graph wrapper (M4 Layer 3).

``graphify.py`` wraps the graphify CLI as a subprocess: deterministic
code-only AST extraction into a per-scan call/import/inheritance graph
(zero LLM, zero network), plus query/path/explain traversal for structural
questions. Android only - iOS has no decompiled source tree (M4 Decision 5),
and no graph tool is exposed for iOS scans.

The RAG/embedding pipeline that once lived in a ``vector`` package was
removed from v1 by owner decision - this package is the sole survivor of M4
Phase 4, renamed ``vector`` -> ``graph`` to match what it actually is.
"""
