import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


def _utc_aware(value: datetime) -> datetime:
    """Attach UTC to a naive datetime before JSON serialization.

    SQLite drops tzinfo on round-trip, so persisted timestamps (scans /
    findings created_at) arrive naive; without this the API would serialize
    them with no offset and browsers would parse them as local time — the
    scan date then reads hours off on non-UTC machines (owner report, Aug
    7). Already-aware values pass through untouched.
    """
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class HealthResponse(BaseModel):
    status: str  # "ok" | "degraded"
    version: str
    redis_ok: bool
    db_ok: bool


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    platform: str | None
    status: str
    # Internal severity-weighted risk (higher = worse); kept for the scan
    # job and tests. The Overview reads ``security_score``.
    risk_score: int | None
    # Public-facing score, higher = better (100 - risk). Derived on the ORM
    # via Scan.security_score; None until the scan is analyzed.
    security_score: int | None = None
    error: str | None = None
    stage: str | None = None
    created_at: datetime

    @field_serializer("created_at")
    def _ser_created_at(self, value: datetime) -> datetime:
        return _utc_aware(value)


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    title: str
    severity: str
    file_path: str | None
    line_number: int | None
    category: str | None
    mastg_test_id: str | None
    tool: str
    detail: dict | None = None
    static_only: bool = True
    # M5 (Aug 8): per-finding false-positive suppression + review toggle.
    # Suppressed findings are hidden from the default list and excluded from
    # risk/summary/agent context; the review toggle lists them for restore.
    suppressed: bool = False
    suppressed_at: datetime | None = None
    created_at: datetime

    @field_serializer("created_at")
    def _ser_created_at(self, value: datetime) -> datetime:
        return _utc_aware(value)

    @field_serializer("suppressed_at")
    def _ser_suppressed_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None

    @field_validator("detail", mode="before")
    @classmethod
    def _parse_detail(cls, value):
        """The detail column stores tool payloads as JSON text."""
        if isinstance(value, str) and value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {"raw": value}
        return value


# ---- M3 model backends (consumed by M5's Settings modal) ----


class ModelBackendHealth(BaseModel):
    reachable: bool
    status: str  # "ok" | "unreachable" | "unknown"
    latency_ms: int | None = None
    models: list[str] = []
    model_source: str = "none"  # "live" | "suggested" | "unavailable" | "none"
    probe_model: str | None = None
    probe_ok: bool | None = None
    error: str | None = None
    checked_at: datetime | None = None

    @field_serializer("checked_at")
    def _ser_checked_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None


class ModelBackendRead(BaseModel):
    id: str
    provider_id: str
    name: str
    kind: str  # "local" | "byok" | "custom"
    base_url: str
    model: str = ""
    enabled: bool = True
    local: bool
    has_api_key: bool  # never the key itself
    # Provider's curated model list (``Provider.suggested_models``) — the
    # Settings UI shows these by default with a "see all" reveal for the
    # full served list (owner UX request, Aug 8).
    suggested_models: list[str] = []
    health: ModelBackendHealth | None = None


class ModelBackendUpsert(BaseModel):
    """Runtime edits to a backend's config. Empty ``api_key`` clears the stored
    key; None leaves the field unchanged."""

    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    enabled: bool | None = None


class ModelBackendModels(BaseModel):
    models: list[str] = []
    source: str = "none"  # "live" | "suggested" | "unavailable"
    error: str | None = None


# ---- M4 agent layer (Layers 1-3: findings context + grep/read + graph tools) ----
# The RAG/embedding schemas (ChatRequest.top_k, ScanIndexState) were removed
# with the pipeline — grounding is now the full findings set + tools.


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    # Optional hard deadline (seconds) for the whole agent loop; falls back to
    # settings.chat_timeout_seconds when omitted. A hung LLM call can never
    # block the API worker beyond this.
    timeout_seconds: int | None = Field(default=None, ge=1)


class Citation(BaseModel):
    file: str
    line: int | None = None
    snippet: str


class ChatResponse(BaseModel):
    answer: str
    citations: list[Citation]
    sources: list[str]


class ScanGraphState(BaseModel):
    built: bool
    nodes: int | None = None
    edges: int | None = None
    graph_path: str | None = None
    reason: str | None = None


class GraphNodeRow(BaseModel):
    """One searchable graph node (Code maps tab, Android only)."""

    id: str
    label: str
    file_type: str | None = None
    file: str | None = None
    line: int | None = None


class GraphSearchResponse(BaseModel):
    """Code maps search: substring matches over node labels/ids.

    ``total`` is the pre-limit match count — the UI can show "n of m".
    """

    query: str
    total: int
    nodes: list[GraphNodeRow]


class GraphNeighbor(BaseModel):
    """A node linked to/from the inspected node."""

    node: GraphNodeRow
    relation: str | None = None
    direction: str  # "in" | "out"


class GraphNodeDetail(BaseModel):
    """One node + its neighbors (relation/direction tagged)."""

    node: GraphNodeRow
    degree: int = 0
    neighbors: list[GraphNeighbor] = []


class GraphHubRow(BaseModel):
    """A most-connected node for the explorer's initial view."""

    node: GraphNodeRow
    degree: int = 0


class GraphHubsResponse(BaseModel):
    hubs: list[GraphHubRow] = []


# ---- M5 dashboard: LLM insights, decompiler tree, model lifecycle ----


class ExplainResponse(BaseModel):
    """Per-finding AI explanation (FR-8), cached on the finding row."""

    explanation: str
    cached: bool
    model: str | None = None
    generated_at: datetime | None = None

    @field_serializer("generated_at")
    def _ser_generated_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None


class SummaryResponse(BaseModel):
    """AI overview summary, cached on the scan row."""

    summary: str
    cached: bool
    model: str | None = None
    generated_at: datetime | None = None

    @field_serializer("generated_at")
    def _ser_generated_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None


class FileNode(BaseModel):
    """One node of the bounded decompiler tree."""

    name: str
    path: str  # relative to the tree root
    type: str  # "dir" | "file"
    # True for iOS hidden binary blobs listed under the synthetic
    # "Binary (Mach-O)" folder — rendered as inert, non-viewable rows.
    binary: bool = False
    children: list["FileNode"] = []


FileNode.model_rebuild()


class FileTreeRoot(BaseModel):
    """A bounded tree for one root (sources / resources / Payload/*.app).

    ``filtered_binaries`` (iOS) counts raw binary files hidden from the
    curated bundle walk — the UI shows the count so hiding never looks like
    data loss.
    """

    name: str
    total_nodes: int
    truncated: bool
    filtered_binaries: int = 0
    tree: list[FileNode]


class FileTreeResponse(BaseModel):
    platform: str
    roots: list[FileTreeRoot]


class FileContentResponse(BaseModel):
    """File content for the code viewer, with highlight.js language."""

    path: str
    content: str
    language: str
    truncated: bool
    size: int


class ModelBackendCreate(BaseModel):
    """Create/activate a BYOK or custom backend (Settings -> BYOK tab)."""

    provider_id: str
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
