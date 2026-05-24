# VOD-001: Video Metadata Model and DynamoDB Table

**Ticket**: VOD-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-24

---

## 1. Overview & Motivation

The platform already supports live broadcasting (`BroadcastSessions`), file storage (`file_manager`), and playback entitlements (`entitlements`), but there is no first-class model that captures the metadata of a discrete video asset throughout its lifecycle: from initial upload or recording, through encoding and processing, to a published state ready for on-demand playback.

Today, video files land in the file manager as opaque blobs. A file node in the `file_manager` table knows a file's name, MIME type, size, and S3 key, but nothing about resolution, duration, codec, bitrate, encoding status, DRM packaging state, thumbnail locations, or the relationship between a source file and its transcoded renditions. Broadcast archive recordings similarly produce raw HLS segments in S3 with no queryable metadata record that links the archive to its encoding outputs.

A dedicated **video metadata model** is needed to:

1. **Track encoding lifecycle** -- Record when a video enters the processing pipeline, what encoding profile is applied, and whether it completed, failed, or was cancelled. Without this, operators have no visibility into the transcoding queue.
2. **Store technical properties** -- Duration, resolution, frame rate, codec, bitrate, audio channels, container format. These are required for ABR ladder selection, thumbnail generation, and client-side adaptive player configuration.
3. **Support content moderation** -- Videos must carry a review status (`pending_review`, `approved`, `rejected`) so the moderation system can gate playback.
4. **Enable per-user queries** -- Creators need to list their own videos sorted by creation date. Admins need to query videos by status (e.g., all videos stuck in `processing_failed`).
5. **Link to related entities** -- A video may originate from a file manager upload (`source_file_node_id`), a broadcast archive (`source_broadcast_session_id`), or a direct API upload. The metadata record provides the join point.
6. **Gate playback entitlements** -- The existing `entitlements` table gates access by SKU. The video metadata table provides the mapping from `video_id` to the SKU and the actual playback manifest URL.

---

## 2. Current State Analysis

### 2.1 DynamoDB Table Definition Pattern

All DynamoDB tables are declared in `scripts/local-ddb-init.py` as `TableDef` dataclass instances inside the `_table_defs()` function. Each `TableDef` specifies:

- `name` -- resolved via `_resolve_table_name(S.<setting>, "<fallback>")` or `os.getenv("<ENV_VAR>", "<fallback>")`
- `partition_key` and optional `sort_key` -- always strings by default (type `"S"`)
- `gsi` -- list of dicts with `index_name`, `partition_key`, and optional `sort_key`
- `attr_types` -- overrides for numeric sort keys (e.g., `{"created_at": "N"}`)

The `_ensure_table` function creates the table if absent or adds missing GSIs to existing tables. All tables use `BillingMode=PAY_PER_REQUEST`.

**Comparable table: `BroadcastSessions`** (lines 477-488 of `local-ddb-init.py`):

```python
TableDef(
    _resolve_table_name(S.broadcast_sessions_table_name, "BroadcastSessions"),
    "session_id",
    gsi=[
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByCreatorCreatedAt", "partition_key": "created_by", "sort_key": "created_at"},
    ],
)
```

This table uses a single primary key (`session_id`) with two GSIs for querying by status and by creator, both sorted by `created_at`. Note that `created_at` here is stored as a string (ISO 8601), so no `attr_types` override is needed. However, for the video metadata table we will use integer Unix timestamps (consistent with `now_ts()` from `app/core/time.py` and the messaging tables), which **requires** `attr_types={"created_at": "N"}`.

**Comparable table: `file_manager`** (lines 152-160):

```python
TableDef(
    _resolve_table_name(S.filemgr_table_name, "file_manager"),
    "PK",
    "SK",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
)
```

The file manager uses a generic single-table design with composite PK/SK keys (`USER#{sub}` / `NODE#{path}`). For video metadata, a dedicated table with descriptive key names is preferred (matching the `BroadcastSessions` pattern), since videos are a distinct entity with their own access patterns rather than a sub-entity of a user's file tree.

### 2.2 Settings Configuration Pattern

Table names are configured in `app/core/settings.py` as fields on the `Settings` frozen dataclass, reading from environment variables with sensible defaults:

```python
broadcast_sessions_table_name: str = os.environ.get("DDB_BROADCAST_SESSIONS", "BroadcastSessions")
```

GSI index names for tables with configurable indexes (like `tickets`) also appear as settings fields. For simpler tables (like `BroadcastSessions`), index names are hardcoded strings in the store module.

### 2.3 Table Handle Pattern

`app/core/tables.py` defines a frozen `Tables` dataclass with one field per table handle, instantiated as the module-level singleton `T`:

```python
@dataclass(frozen=True)
class Tables:
    broadcast_sessions: Any
    # ...

T = Tables(
    broadcast_sessions=ddb.Table(S.broadcast_sessions_table_name),
    # ...
)
```

Service code accesses tables exclusively through `T.<table_name>`.

### 2.4 Pydantic Model Pattern

The broadcast domain defines its models in a separate `app/models_broadcast.py` file (not in the main `app/models.py`). This is the pattern for domain-specific model files:

```python
BroadcastSessionStatus = Literal["draft", "provisioning", "ready", "live", "stopping", "stopped", "error"]

class BroadcastSessionModel(BaseModel):
    id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    status: BroadcastSessionStatus = "draft"
    # ... fields with Optional types, defaults, and constraints
    created_at: str = ""
    updated_at: str = ""
```

### 2.5 Service/Store Layer Pattern

`app/services/broadcast_store.py` implements the full CRUD pattern:

- **`*_to_item(model) -> Dict`** -- Serializes a Pydantic model to a DynamoDB item dict.
- **`*_from_item(item: Dict) -> Model`** -- Deserializes a DynamoDB item back to a Pydantic model, with safe `.get()` calls and fallback defaults.
- **`create_*(...)` -> Model** -- Generates a UUID, sets timestamps via `now_iso()`, constructs the model, calls `T.<table>.put_item(Item=..., ConditionExpression="attribute_not_exists(<pk>)")`.
- **`get_*(id: str)` -> Model** -- Calls `T.<table>.get_item(Key={...}, ConsistentRead=True)`, raises `HTTPException(404)` if missing.
- **`delete_*(id: str)` -> Dict** -- Fetches first (to confirm existence / raise 404), then calls `T.<table>.delete_item(Key={...})`.
- **`list_*_by_<dimension>(...)`** -- Queries a GSI using `boto3.dynamodb.conditions.Key`, supports `Limit` and `ExclusiveStartKey` cursor-based pagination, returns `{"items": [...], "cursor": ...}`.
- **`transition_*_status(...)`** -- Validates state transition legality, writes updated item, writes an audit record to a separate transitions table.

### 2.6 Unit Test Pattern

`tests/test_broadcast_store.py` uses a `_FakeTable` class that implements `put_item`, `get_item`, and `query` in memory. The real `T` singleton is replaced via `unittest.mock.patch.object(broadcast_store, "T", SimpleNamespace(...))`. Tests cover:

- Create + get roundtrip
- 404 on missing item
- List by GSI
- Legal and illegal state transitions
- Input validation rejections

---

## 3. Technical Design

### 3.1 DynamoDB Table Schema

**Table name**: `VideoMetadata` (env var: `DDB_VIDEO_METADATA`, setting: `video_metadata_table_name`)

| Attribute | Type | Role |
|-----------|------|------|
| `video_id` | S | Partition key (HASH) |

No sort key -- each video is uniquely identified by its `video_id` (UUID).

#### Global Secondary Indexes

| Index Name | PK | SK | Purpose |
|-----------|-----|-----|---------|
| `ByOwnerCreatedAt` | `owner_user_id` (S) | `created_at` (N) | List videos by creator, newest first |
| `ByStatusCreatedAt` | `status` (S) | `created_at` (N) | Query by processing/review status for admin dashboards and worker queues |
| `BySourceBroadcast` | `source_broadcast_session_id` (S) | -- | Look up the video record derived from a specific broadcast archive |

The `attr_types` override is required for the numeric sort key:

```python
attr_types={"created_at": "N"}
```

#### Access Patterns

| Access Pattern | Method | Index |
|---------------|--------|-------|
| Get video by ID | `get_item(Key={"video_id": id})` | Table (primary key) |
| List user's videos (newest first) | Query `ByOwnerCreatedAt` with `ScanIndexForward=False` | GSI |
| List videos by status | Query `ByStatusCreatedAt` | GSI |
| Find video from broadcast session | Query `BySourceBroadcast` | GSI |
| Update video status | `update_item` on primary key | Table |
| Delete video | `delete_item` on primary key | Table |

### 3.2 Item Schema (Field Definitions)

```
{
  "video_id":                       "v_<uuid4_hex>",        // PK
  "owner_user_id":                  "<user_sub>",           // GSI1 PK - who uploaded/created
  "title":                          "My Video Title",       // user-facing title, max 256 chars
  "description":                    "Optional description", // max 2000 chars
  "status":                         "<VideoStatus>",        // GSI2 PK - lifecycle state
  "created_at":                     1716566400,             // integer Unix timestamp (now_ts())
  "updated_at":                     1716566400,             // integer Unix timestamp

  // Source provenance (exactly one should be set)
  "source_type":                    "upload|broadcast_archive|api",
  "source_file_node_id":            "<file_manager PK/SK>", // if source_type=upload
  "source_broadcast_session_id":    "<session_id>",          // if source_type=broadcast_archive, GSI3 PK
  "source_s3_key":                  "uploads/raw/<key>",     // S3 location of source file

  // Technical properties (populated after probe/analysis)
  "duration_seconds":               123.45,
  "width":                          1920,
  "height":                         1080,
  "frame_rate":                     30.0,
  "video_codec":                    "h264",
  "audio_codec":                    "aac",
  "audio_channels":                 2,
  "bitrate_kbps":                   5000,
  "container_format":               "mp4",
  "file_size_bytes":                104857600,

  // Encoding/processing
  "encoding_profile_id":            "<profile_id>",         // links to encoding profile config
  "encoding_job_id":                "<job_uuid>",           // external encoder job reference
  "encoding_started_at":            1716566500,
  "encoding_completed_at":          1716567000,
  "encoding_error_message":         null,                   // set on processing_failed

  // Outputs
  "thumbnail_s3_key":               "thumbnails/<video_id>/poster.jpg",
  "thumbnail_url":                  "/mock/s3/...",          // populated in dev mode
  "hls_manifest_s3_key":            "output/<video_id>/master.m3u8",
  "hls_manifest_url":               "/mock/s3/...",
  "dash_manifest_s3_key":           "output/<video_id>/manifest.mpd",
  "renditions":                     [                        // list of ABR ladder outputs
    {"label": "1080p", "width": 1920, "height": 1080, "bitrate_kbps": 5000},
    {"label": "720p",  "width": 1280, "height": 720,  "bitrate_kbps": 2500},
    {"label": "480p",  "width": 854,  "height": 480,  "bitrate_kbps": 1200}
  ],

  // Content moderation
  "review_status":                  "pending_review|approved|rejected",
  "reviewed_by":                    "<admin_user_sub>",
  "reviewed_at":                    1716568000,
  "review_notes":                   "Approved for publication",

  // DRM
  "drm_policy_id":                  "<policy_id>",
  "drm_key_id":                     "<key_id>",

  // Entitlement linkage
  "entitlement_sku":                "<sku>",                 // links to entitlements table

  // Visibility
  "visibility":                     "private|unlisted|public",
  "published_at":                   1716569000,

  // Soft delete
  "deleted_at":                     null,                    // set on soft-delete

  // TTL
  "ttl_epoch":                      null                     // optional TTL for auto-expiry
}
```

### 3.3 Status Enum and State Machine

```
VideoStatus = Literal[
    "created",            # Initial record created, source file referenced
    "probing",            # ffprobe/mediainfo analysis in progress
    "probe_failed",       # Analysis failed (corrupt file, unsupported format)
    "pending_encoding",   # Queued for transcoding
    "encoding",           # Transcoding in progress
    "encoding_failed",    # Transcoding failed
    "pending_review",     # Encoded successfully, awaiting moderation review
    "approved",           # Approved by moderator, ready for playback
    "rejected",           # Rejected by moderator
    "published",          # Approved and made visible per visibility setting
    "archived",           # Soft-archived by owner (not deleted, not playable)
    "deleted",            # Soft-deleted
]
```

**Allowed transitions**:

```python
_ALLOWED_TRANSITIONS: Dict[VideoStatus, Set[VideoStatus]] = {
    "created":          {"probing", "deleted"},
    "probing":          {"pending_encoding", "probe_failed", "deleted"},
    "probe_failed":     {"probing", "deleted"},          # retry after fix
    "pending_encoding": {"encoding", "deleted"},
    "encoding":         {"pending_review", "encoding_failed", "deleted"},
    "encoding_failed":  {"pending_encoding", "deleted"}, # retry
    "pending_review":   {"approved", "rejected", "deleted"},
    "approved":         {"published", "archived", "deleted"},
    "rejected":         {"pending_review", "deleted"},   # re-submit for review
    "published":        {"archived", "approved", "deleted"},
    "archived":         {"published", "deleted"},
    "deleted":          set(),                           # terminal
}
```

### 3.4 Pydantic Models

File: `app/models_video.py`

```python
from __future__ import annotations
from typing import List, Literal, Optional
from pydantic import BaseModel, Field

VideoStatus = Literal[
    "created", "probing", "probe_failed", "pending_encoding",
    "encoding", "encoding_failed", "pending_review",
    "approved", "rejected", "published", "archived", "deleted",
]

VideoSourceType = Literal["upload", "broadcast_archive", "api"]
VideoVisibility = Literal["private", "unlisted", "public"]
VideoReviewStatus = Literal["pending_review", "approved", "rejected"]


class VideoRendition(BaseModel):
    """Per-rendition output metadata stored on completed videos.
    
    NOTE: This is distinct from `VideoRenditionProfile` in
    `app/contracts/video_rendition_profiles.py` which defines the
    encoding PARAMETERS (target bitrate, fps, GOP). This model
    records the ACTUAL output characteristics after transcoding.
    The `label` field here corresponds to `VideoRenditionProfile.name`.
    """
    label: str = Field(min_length=1, max_length=32)
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    bitrate_kbps: int = Field(ge=1)


class VideoMetadataModel(BaseModel):
    id: str = Field(min_length=1)
    owner_user_id: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: VideoStatus = "created"
    created_at: int = 0
    updated_at: int = 0

    # Source
    source_type: VideoSourceType = "upload"
    source_file_node_id: Optional[str] = None
    source_broadcast_session_id: Optional[str] = None
    source_s3_key: Optional[str] = None

    # Technical properties
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    video_codec: Optional[str] = None
    audio_codec: Optional[str] = None
    audio_channels: Optional[int] = None
    bitrate_kbps: Optional[int] = None
    container_format: Optional[str] = None
    file_size_bytes: Optional[int] = None

    # Encoding
    encoding_profile_id: Optional[str] = None
    encoding_job_id: Optional[str] = None
    encoding_started_at: Optional[int] = None
    encoding_completed_at: Optional[int] = None
    encoding_error_message: Optional[str] = None

    # Outputs
    thumbnail_s3_key: Optional[str] = None
    thumbnail_url: Optional[str] = None
    hls_manifest_s3_key: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    dash_manifest_s3_key: Optional[str] = None
    renditions: List[VideoRendition] = Field(default_factory=list)

    # Review
    review_status: Optional[VideoReviewStatus] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[int] = None
    review_notes: Optional[str] = None

    # DRM
    drm_policy_id: Optional[str] = None
    drm_key_id: Optional[str] = None

    # Entitlement
    entitlement_sku: Optional[str] = None

    # Visibility
    visibility: VideoVisibility = "private"
    published_at: Optional[int] = None
    deleted_at: Optional[int] = None


class CreateVideoIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    source_type: VideoSourceType = "upload"
    source_file_node_id: Optional[str] = None
    source_broadcast_session_id: Optional[str] = None
    source_s3_key: Optional[str] = None
    encoding_profile_id: Optional[str] = None
    visibility: VideoVisibility = "private"
    drm_policy_id: Optional[str] = None
    entitlement_sku: Optional[str] = None


class UpdateVideoIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[VideoVisibility] = None
    encoding_profile_id: Optional[str] = None
    drm_policy_id: Optional[str] = None
    entitlement_sku: Optional[str] = None


class VideoOut(BaseModel):
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: VideoStatus
    created_at: int
    updated_at: int
    source_type: VideoSourceType
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    renditions: List[VideoRendition] = Field(default_factory=list)
    review_status: Optional[VideoReviewStatus] = None
    visibility: VideoVisibility = "private"
    published_at: Optional[int] = None
    file_size_bytes: Optional[int] = None
```

---

## 4. Implementation Plan

### 4.1 Changes to `app/core/settings.py`

Add the table name setting to the `Settings` dataclass (in the video/broadcast settings section, after the existing `broadcast_*` fields around line 466):

```python
# Video metadata (VOD-001)
video_metadata_table_name: str = os.environ.get("DDB_VIDEO_METADATA", "VideoMetadata")
```

### 4.2 Changes to `scripts/local-ddb-init.py`

Add a new `TableDef` entry to the `_table_defs()` list, placed after the broadcast table definitions (after line 506):

```python
# Video metadata (VOD-001)
TableDef(
    _resolve_table_name(S.video_metadata_table_name, "VideoMetadata"),
    "video_id",
    gsi=[
        {
            "index_name": "ByOwnerCreatedAt",
            "partition_key": "owner_user_id",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByStatusCreatedAt",
            "partition_key": "status",
            "sort_key": "created_at",
        },
        {
            "index_name": "BySourceBroadcast",
            "partition_key": "source_broadcast_session_id",
        },
    ],
    attr_types={"created_at": "N"},
),
```

The `attr_types={"created_at": "N"}` declaration is critical. Without it, the `_attribute_definitions` helper defaults all attributes to type `"S"` (string), and DynamoDB will reject queries that pass integer `created_at` values against string-typed sort keys with a `ValidationException`. This is the same gotcha documented in `CLAUDE.md` under "DynamoDB numeric GSI sort keys."

### 4.3 Changes to `app/core/tables.py`

Add a new field to the `Tables` dataclass and its instantiation:

In the dataclass (after `broadcast_action_audit: Any`):

```python
video_metadata: Any
```

In the `T = Tables(...)` constructor (after `broadcast_action_audit=...`):

```python
video_metadata=ddb.Table(S.video_metadata_table_name),
```

### 4.4 New File: `app/models_video.py`

Create the Pydantic models as specified in Section 3.4. This follows the same pattern as `app/models_broadcast.py` -- a domain-specific model file separate from the monolithic `app/models.py`.

### 4.5 New File: `app/services/video_state_machine.py`

Implements the state transition validation logic, following the `broadcast_state_machine.py` pattern:

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Set
from app.models_video import VideoStatus

INVALID_TRANSITION_ERROR_CODE = "VIDEO_INVALID_STATE_TRANSITION"

_ALLOWED_TRANSITIONS: Dict[VideoStatus, Set[VideoStatus]] = {
    "created":          {"probing", "deleted"},
    "probing":          {"pending_encoding", "probe_failed", "deleted"},
    "probe_failed":     {"probing", "deleted"},
    "pending_encoding": {"encoding", "deleted"},
    "encoding":         {"pending_review", "encoding_failed", "deleted"},
    "encoding_failed":  {"pending_encoding", "deleted"},
    "pending_review":   {"approved", "rejected", "deleted"},
    "approved":         {"published", "archived", "deleted"},
    "rejected":         {"pending_review", "deleted"},
    "published":        {"archived", "approved", "deleted"},
    "archived":         {"published", "deleted"},
    "deleted":          set(),
}

@dataclass(frozen=True)
class TransitionValidationResult:
    legal: bool
    error_code: str | None = None

def validate_transition(
    from_status: VideoStatus, to_status: VideoStatus
) -> TransitionValidationResult:
    if to_status in _ALLOWED_TRANSITIONS.get(from_status, set()):
        return TransitionValidationResult(legal=True)
    return TransitionValidationResult(
        legal=False, error_code=INVALID_TRANSITION_ERROR_CODE
    )
```

### 4.6 New File: `app/services/video_metadata_store.py`

Implements the CRUD operations, following the `broadcast_store.py` pattern exactly:

**Key functions to implement:**

| Function | Signature | Description |
|----------|-----------|-------------|
| `video_to_item` | `(video: VideoMetadataModel) -> Dict[str, Any]` | Serialize model to DynamoDB item. Must filter `None` values from GSI key attributes (e.g., `source_broadcast_session_id`) to avoid DynamoDB storing NULL in GSI keys. |
| `video_from_item` | `(item: Dict[str, Any]) -> VideoMetadataModel` | Deserialize DynamoDB item to model with safe `.get()` and `int()` coercion for Decimal values. |
| `create_video` | `(*, owner_user_id, title, ...) -> VideoMetadataModel` | Generate `v_<uuid4().hex>` ID, set `created_at` and `updated_at` via `now_ts()`, put with `ConditionExpression="attribute_not_exists(video_id)"`. |
| `get_video` | `(video_id: str) -> VideoMetadataModel` | `get_item` with `ConsistentRead=True`, raise 404 if missing. |
| `update_video` | `(video_id: str, updates: UpdateVideoIn) -> VideoMetadataModel` | Fetch existing, apply non-None fields, set `updated_at`, put item. |
| `delete_video` | `(video_id: str) -> Dict[str, bool]` | Soft delete: set `status="deleted"`, `deleted_at=now_ts()`. |
| `transition_video_status` | `(*, video_id, to_status, reason, actor) -> VideoMetadataModel` | Validate transition via state machine, update status + `updated_at`, return updated model. |
| `list_videos_by_owner` | `(owner_user_id, *, limit=50, cursor=None) -> Dict` | Query `ByOwnerCreatedAt` GSI, `ScanIndexForward=False`. |
| `list_videos_by_status` | `(status, *, limit=50, cursor=None) -> Dict` | Query `ByStatusCreatedAt` GSI. |
| `get_video_by_broadcast_session` | `(session_id: str) -> VideoMetadataModel | None` | Query `BySourceBroadcast` GSI, return first result or None. |

**Critical implementation details:**

1. **Decimal coercion**: DynamoDB returns numbers as `Decimal`. The `video_from_item` function must call `int()` on numeric fields (`created_at`, `updated_at`, `width`, `height`, etc.) to avoid Pydantic validation errors. This is the same pattern used in `MessageEncryptionEnvelope`'s `@model_validator(mode="before")`.

2. **GSI key attribute filtering in `video_to_item`**: The `source_broadcast_session_id` is a GSI partition key. If its value is `None`, it must be omitted from the item dict entirely (not stored as DynamoDB NULL), because DynamoDB cannot use NULL values in GSI key attributes and will raise a `ValidationException`. This matches the pattern in `app/services/tickets.py` `create_ticket` where None GSI keys are filtered.

3. **Timestamp convention**: Use `now_ts()` from `app/core/time.py` (integer Unix seconds), not `now_iso()` (ISO 8601 string). This is consistent with the messaging tables and newer tables in the codebase. The `attr_types={"created_at": "N"}` declaration in the table definition enables integer sort key queries.

4. **Pagination**: Return `{"items": [...], "cursor": resp.get("LastEvaluatedKey")}` matching the broadcast store convention. Callers pass the cursor dict back as `ExclusiveStartKey`.

### 4.7 New File: `app/routers/video_metadata.py`

Register in `app/main.py` with prefix `/ui/videos` (for session-auth UI endpoints) and optionally `/api/videos` (for Bearer-auth API clients). Endpoints:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/videos` | `require_ui_session` | Create video metadata record |
| GET | `/ui/videos` | `require_ui_session` | List caller's videos (paginated) |
| GET | `/ui/videos/{video_id}` | `require_ui_session` | Get single video |
| PATCH | `/ui/videos/{video_id}` | `require_ui_session` | Update title/description/visibility |
| DELETE | `/ui/videos/{video_id}` | `require_ui_session` | Soft-delete |
| POST | `/ui/videos/{video_id}/transition` | `require_admin_session` | Transition status (admin) |
| GET | `/ui/videos/admin/by-status/{status}` | `require_admin_session` | List by status (admin) |

### 4.8 Environment Variable

Add to `.env.local.example`:

```bash
DDB_VIDEO_METADATA=VideoMetadata
```

---

## 5. Testing Strategy

### 5.1 Unit Tests: `tests/test_video_metadata_store.py`

Follow the `tests/test_broadcast_store.py` pattern: use a `_FakeTable` in-memory stub, patch `T` via `SimpleNamespace`.

**Test cases:**

| Test | What it validates |
|------|-------------------|
| `test_create_and_get_roundtrip` | Create a video, get it back, assert all fields match. |
| `test_get_missing_raises_404` | `get_video("nonexistent")` raises `HTTPException(404)`. |
| `test_create_generates_uuid_and_timestamps` | Assert `video_id` starts with `v_`, `created_at` and `updated_at` are non-zero integers. |
| `test_list_by_owner_returns_items` | Insert 3 videos for user A and 1 for user B, list for A, assert 3 returned. |
| `test_list_by_owner_pagination` | Insert 5 videos, list with `limit=2`, assert cursor is returned, second page returns remaining. |
| `test_list_by_status` | Insert videos with mixed statuses, query one status, assert correct filtering. |
| `test_update_video_partial` | Update only `title`, assert `description` unchanged, `updated_at` advanced. |
| `test_delete_soft_deletes` | Delete a video, assert `status="deleted"` and `deleted_at` is set. |
| `test_transition_legal` | `created -> probing`, assert status updated. |
| `test_transition_illegal_raises_409` | `created -> published` raises `HTTPException(409)` with error code `VIDEO_INVALID_STATE_TRANSITION`. |
| `test_transition_deleted_is_terminal` | `deleted -> *` always raises 409. |
| `test_source_broadcast_gsi_none_omitted` | Create video with `source_broadcast_session_id=None`, assert key is absent from DynamoDB item. |
| `test_decimal_coercion` | Construct a raw DynamoDB item with `Decimal` values, call `video_from_item`, assert fields are `int`. |

### 5.2 Unit Tests: `tests/test_video_state_machine.py`

Follow the `tests/test_broadcast_state_machine.py` pattern:

| Test | What it validates |
|------|-------------------|
| `test_all_valid_transitions` | Iterate `_ALLOWED_TRANSITIONS`, assert `validate_transition` returns `legal=True` for each. |
| `test_invalid_transitions` | Test representative illegal transitions (e.g., `created -> published`, `deleted -> created`), assert `legal=False`. |
| `test_deleted_is_terminal` | Assert `_ALLOWED_TRANSITIONS["deleted"]` is empty set. |
| `test_every_status_reachable` | Graph traversal from `created`, assert all non-terminal states are reachable. |
| `test_error_code_on_invalid` | Assert `error_code == "VIDEO_INVALID_STATE_TRANSITION"` on failed validation. |

### 5.3 Integration Tests (pytest with moto)

Using the `conftest.py` test client and moto-mocked DynamoDB:

| Test | What it validates |
|------|-------------------|
| `test_create_video_endpoint_201` | POST `/ui/videos` with valid body, assert 201 and response contains `video_id`. |
| `test_create_video_missing_title_422` | POST without `title`, assert 422 validation error. |
| `test_get_video_endpoint_200` | Create then GET, assert fields match. |
| `test_get_video_404` | GET nonexistent ID, assert 404. |
| `test_list_videos_empty` | GET `/ui/videos` for user with no videos, assert empty list. |
| `test_update_video_endpoint` | PATCH title, assert 200 and title updated. |
| `test_delete_video_soft_delete` | DELETE, then GET, assert `status=deleted`. |
| `test_admin_transition_endpoint` | POST transition from `pending_review` to `approved`, assert 200. |
| `test_admin_list_by_status` | Admin queries `pending_review` videos, assert filtered results. |
| `test_non_admin_cannot_transition` | Regular user POST to transition endpoint, assert 403. |
| `test_csrf_required_for_post` | POST without `x-csrf-token` header, assert 403. |

### 5.4 E2E Tests: `frontend/e2e/video-metadata.spec.ts`

Once frontend pages are built (out of scope for VOD-001), add Playwright E2E tests following the project's `injectAuth` + `page.request` pattern:

- Section: Video CRUD API (create, get, list, update, delete via `page.request`)
- Section: Video status transitions (admin transitions via root session)
- Section: Video metadata UI (list page, detail page, upload flow)

### 5.5 Test Data Considerations

- Use unique per-run titles (e.g., `f"Test Video {uuid4().hex[:8]}"`) to avoid conflicts from accumulated test data across runs.
- The `_FakeTable` stub must handle the `BySourceBroadcast` GSI query pattern (filter by `source_broadcast_session_id`).
- Numeric timestamp fields in fake items should use `int`, not `Decimal`, since `_FakeTable` does not emulate DynamoDB's Decimal serialization. The `test_decimal_coercion` test should construct a raw dict with `Decimal` values explicitly to verify the coercion logic.

---

## Appendix: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/core/settings.py` | Modify | Add `video_metadata_table_name` field |
| `app/core/tables.py` | Modify | Add `video_metadata` field to `Tables` dataclass and `T` constructor |
| `scripts/local-ddb-init.py` | Modify | Add `VideoMetadata` `TableDef` with 3 GSIs |
| `app/models_video.py` | New | Pydantic models: `VideoMetadataModel`, `CreateVideoIn`, `UpdateVideoIn`, `VideoOut`, `VideoRendition`, type aliases |
| `app/services/video_state_machine.py` | New | `_ALLOWED_TRANSITIONS` dict, `validate_transition()` function |
| `app/services/video_metadata_store.py` | New | Full CRUD: `create_video`, `get_video`, `update_video`, `delete_video`, `transition_video_status`, `list_videos_by_owner`, `list_videos_by_status`, `get_video_by_broadcast_session` |
| `app/routers/video_metadata.py` | New | FastAPI router with 7 endpoints |
| `app/main.py` | Modify | Register `video_metadata_router` |
| `tests/test_video_state_machine.py` | New | 5 unit tests for state machine |
| `tests/test_video_metadata_store.py` | New | 13 unit tests for CRUD store |
| `.env.local.example` | Modify | Add `DDB_VIDEO_METADATA=VideoMetadata` |
