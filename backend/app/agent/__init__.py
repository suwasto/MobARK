"""M4 agent layer - Layers 1-3, zero embeddings.

- context.py: Layer 1 - the full static-findings set normalized into one
  agent-facing schema with per-finding precision tags.
- tools.py: Layer 2 (search_code / read_file over the decompiled/extracted
  tree) + Layer 3 (Graphify graph_query / graph_path / graph_explain).
- chat.py: bounded tool-calling orchestration over Layers 1-3.

The RAG/embedding pipeline was removed from v1 by owner decision - nothing
here imports a vector store, an embedding model, or a chunker.
"""
