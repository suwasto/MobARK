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
    # M7: per-scan web research opt-in (privacy gate) — the agent's web
    # tools are offered only when this is on AND an Active search engine
    # exists. Default off; controlled by the dock 🌐 toggle + Settings.
    web_research_enabled: bool = False
    # M8: on-demand apktool decode state (Android only). not_started |
    # queued | decoding | ready | failed. The dedicated smali-status
    # endpoint derives ``ready`` from the filesystem; these columns carry
    # the in-flight states + the specific failure reason.
    apktool_status: str = "not_started"
    apktool_error: str | None = None
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
    # M6 Phase C: max tool-calling rounds before the context-only fallback;
    # falls back to settings.max_tool_rounds when omitted.
    max_tool_rounds: int | None = Field(default=None, ge=1, le=10)
    # M8 follow-up (dock @-mentions): tree paths the user explicitly attached
    # to the question (``@sources/com/foo/A.java`` etc.). The chat layer loads
    # their content into the agent context so the model answers / proposes
    # edits about them directly — no search round needed. Capped small (the
    # validator trims blanks + caps the count; the list Field max is a loose
    # transport bound only).
    mentioned_files: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("mentioned_files")
    @classmethod
    def _clean_mentions(cls, value):
        out = []
        for p in value:
            p = (p or "").strip()
            if p and len(p) <= 512:
                out.append(p)
            if len(out) >= 10:
                break
        return out


class Citation(BaseModel):
    file: str
    line: int | None = None
    snippet: str


class ToolRunRead(BaseModel):
    """One executed tool call — the persistent trace on a chat response, so
    the dock can render a collapsible per-tool record (args, status,
    duration, capped result preview)."""

    id: str
    name: str
    args: dict
    status: str  # "ok" | "error"
    duration_ms: int
    result_preview: str = ""
    error: str | None = None
    count: int | None = None


class ChatResponse(BaseModel):
    answer: str
    citations: list[Citation]
    sources: list[str]
    # M6 Phase B: "tools" when the agent ran tool calls this turn,
    # "context-only" when it answered from the findings context alone.
    tool_mode: str = "context-only"
    tools_used: list[str] = []
    # M6 follow-up: the persistent per-tool trace (the live SSE events are
    # the same records, streamed as they happen).
    tool_runs: list[ToolRunRead] = []


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


# ---- M7 search backends (web research engines) ----


class SearchBackendHealth(BaseModel):
    """Reachability of one search engine (Settings -> Search & research)."""

    reachable: bool
    status: str = "unknown"  # "ok" | "unreachable" | "unknown"
    latency_ms: int | None = None
    error: str | None = None
    checked_at: datetime | None = None
    # Full-probe extras: how many normalized results a real query returned.
    result_count: int | None = None
    sample_title: str | None = None

    @field_serializer("checked_at")
    def _ser_checked_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None


class SearchBackendRead(BaseModel):
    """One configured search engine (the Active/Inactive radio list). The key
    is never returned — only ``has_api_key`` (same honesty rule as model
    backends)."""

    id: str
    provider_id: str
    name: str
    kind: str  # "bundled" | "custom" | "keyed"
    base_url: str
    enabled: bool
    order: int = 0
    has_api_key: bool = False
    health: SearchBackendHealth | None = None


class SearchBackendUpsert(BaseModel):
    """Runtime edits to a search backend. ``enabled: true`` triggers the
    one-Active radio semantics server-side (``SearchStore.enable_only``); an
    empty ``api_key`` clears the stored key."""

    base_url: str | None = None
    api_key: str | None = None
    enabled: bool | None = None


class SearchBackendCreate(BaseModel):
    """Add a search engine: a custom SearXNG-compatible instance (base URL
    required, no key) or a keyed provider (Brave/Serper/Mojeek — API key
    required, base URL optional with a per-provider default)."""

    provider_id: str
    base_url: str | None = None
    api_key: str | None = None


class SearchProviderRead(BaseModel):
    """One addable search engine — drives the Settings add-form picker."""

    id: str
    name: str
    kind: str  # "custom" | "keyed"
    base_url_required: bool
    key_required: bool
    default_base_url: str


class WebResearchUpdate(BaseModel):
    """Per-scan web research opt-in (the dock 🌐 toggle / Settings)."""

    enabled: bool


# ---- Dependencies tab (local-first inventory) ----


class DependencyApp(BaseModel):
    """Identity metadata for the scanned app (Android package + SDK levels /
    iOS bundle id + version). Fields are best-effort — missing when the scan
    output doesn't carry them."""

    package: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    bundle_id: str | None = None
    version: str | None = None


class DependencyItem(BaseModel):
    """One entry in the Dependencies tab inventory.

    ``kind``: ``package`` (Android Java/Kotlin group) · ``native`` (Android
    ``lib/*.so``) · ``dylib`` (iOS Mach-O link) · ``framework`` (iOS
    embedded ``Frameworks/*.framework``). ``label`` is a human name for
    well-known libraries (else None — the raw package/name stands).
    Finding tallies are the non-suppressed semgrep findings inside the
    dependency's package (Android packages only; the other kinds are
    inventory without findings).
    """

    name: str
    label: str | None = None
    kind: str  # package | native | dylib | framework
    evidence: str
    file_count: int | None = None
    finding_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    abis: list[str] = []
    # iOS dylibs only: True for Apple's own runtime libs (system), False for
    # third-party @rpath/embedded links, None elsewhere.
    system: bool | None = None


class DependenciesResponse(BaseModel):
    """The Dependencies tab payload — derived on demand from scan output,
    nothing new persisted. Known-CVE research is NOT a column here: it is
    the agent's web-research use case (M7) — the UI pre-fills the dock
    question and the agent decides when to search.
    """

    platform: str
    app: DependencyApp = DependencyApp()
    runtime_markers: list[str] = []
    dependencies: list[DependencyItem] = []
    total: int = 0
    truncated: bool = False
    generated_at: datetime

    @field_serializer("generated_at")
    def _ser_generated_at(self, value: datetime) -> datetime:
        return _utc_aware(value)


# ---- M8 Phase A: on-demand apktool decode (Smali view) ----


class SmaliStatusResponse(BaseModel):
    """Decode state for the Smali chip: ``ready`` is filesystem-derived
    (apktool/AndroidManifest.xml exists), the rest comes from the status
    column. ``error`` carries the specific decode failure."""

    status: str  # not_started | queued | decoding | ready | failed
    error: str | None = None


class EditRead(BaseModel):
    """One M8 file edit (the edits table). Full file contents are NOT in the
    list — the unified diff (``GET .../edits/{eid}/diff``) is the review
    surface; the viewer reads effective content via ``files/content``."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    file_path: str
    source: str  # manual | agent
    instruction: str | None = None
    status: str  # proposed | applied | rejected | reverted
    build_id: int | None = None
    created_at: datetime
    applied_at: datetime | None = None

    @field_serializer("created_at")
    def _ser_created_at(self, value: datetime) -> datetime:
        return _utc_aware(value)

    @field_serializer("applied_at")
    def _ser_applied_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None


class EditCreate(BaseModel):
    """Manual edit: apktool-root-relative ``file_path`` + the full edited
    content. Created as ``applied`` (the human authored it in the editor)."""

    file_path: str = Field(min_length=1, max_length=1024)
    content: str = Field(min_length=1)


class EditDiffResponse(BaseModel):
    """The generated unified diff for one edit (the review surface)."""

    file_path: str
    diff: str


class SmaliSiblingResponse(BaseModel):
    """Java⇄Smali sibling mapping for the Decompiler view toggle.

    ``path`` echoes the input; ``sibling`` is the counterpart's tree path
    (multidex-aware, first-found) or null when there is none (e.g. res files,
    jadx-fallback smali, or the class has no decoded smali)."""

    path: str
    sibling: str | None = None


class SmaliMappingResponse(BaseModel):
    """Finding→apktool tree-path mapping for a scan's findings — powers the
    Smali-mode tree dots + annotation rail (findings live on jadx
    ``sources/...`` paths; their apktool siblings get the same dots/notes
    once the decode is ready).

    Scoped to finding-bearing paths: the payload stays bounded and the dots
    only exist where findings exist. Keys/values are full tree paths:
    ``sources/...`` → multidex-aware smali siblings; ``res/...`` → itself
    (the apktool ``res`` root serves the same relative path);
    ``AndroidManifest.xml`` → ``AndroidManifest.xml/AndroidManifest.xml``
    (the synthetic manifest root's single file).

    ``anchors`` (M8 follow-up, Aug 11) are the smali-mode LINE anchors for
    line-bearing findings: ``{smali_tree_path: {str(jadx_line): smali_line}}``
    — each finding's jadx line mapped to its containing method's ``.method``
    line in the smali sibling (jadx renumbers source lines, so only METHOD
    granularity is honest; the rail pins notes there so they align with the
    smali editor's own line numbers). Findings without a resolvable anchor
    simply have no entry — those notes stack from the top."""

    mapping: dict[str, str]
    anchors: dict[str, dict[str, int]] = {}
    total: int


# ---- M8 Phase C: rebuild pipeline (recompile + resign) ----


class BuildRead(BaseModel):
    """One recompile attempt (the builds table — full rebuild history, D8).

    ``edit_ids`` is the snapshot of applied edits taken at job start (parsed
    from ``edits_json``), so history shows exactly what each build consumed.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    # queued | running | done | failed
    status: str
    # queued | applying | rebuilding | zipping | signing | done — the failing
    # stage is kept on a failed build so the error reads in context.
    stage: str
    error: str | None = None
    # Applied edit ids snapshot at job start — read from the stored
    # ``edits_json`` column (from_attributes maps by the alias, not the
    # field name).
    edit_ids: list[int] = Field(default=[], validation_alias="edits_json")
    artifact_name: str | None = None
    artifact_sha256: str | None = None
    created_at: datetime
    finished_at: datetime | None = None

    @field_validator("edit_ids", mode="before")
    @classmethod
    def _parse_edits_json(cls, value):
        """The column stores a JSON array of edit ids as text (None until a
        build snapshots its edits)."""
        if value is None:
            return []
        if isinstance(value, str) and value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return []
        return value

    @field_serializer("created_at")
    def _ser_created_at(self, value: datetime) -> datetime:
        return _utc_aware(value)

    @field_serializer("finished_at")
    def _ser_finished_at(self, value: datetime | None) -> datetime | None:
        return _utc_aware(value) if value is not None else None
