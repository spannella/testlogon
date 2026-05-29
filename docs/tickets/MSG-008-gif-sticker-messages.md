# MSG-008: GIF & Sticker Messages

**Ticket**: MSG-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-008 adds GIF search-and-send and sticker collections to the messaging system. GIFs are sourced from a mock GIF API in dev mode (returning deterministic placeholder results), while stickers are platform-hosted image collections that users can browse, favorite, and send. Both GIFs and stickers are sent as new message kinds (`gif` and `sticker`) with dedicated fields, rendering in `MessageBubble` as properly-sized media with alt text for accessibility.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Sender | As a sender, I want to search for GIFs by keyword and send one to a conversation. | GIF picker opens from ComposeBar; type "happy" → see GIF results; click to send. |
| Sender | As a sender, I want to browse sticker collections and send a sticker. | Sticker picker shows favorited collections; click a sticker to send. |
| Sender | As a sender, I want to favorite sticker collections so they appear in my picker. | "Add to Favorites" button on collection; favorited collections persist. |
| Recipient | As a recipient, I want GIFs and stickers to render with proper sizing and alt text. | GIFs animate in message bubble; stickers display at fixed size; both have alt text. |
| Admin | As an admin, I want to upload sticker collections for all users. | Admin endpoint creates collection with name, description, and sticker images. |
| User | As a user, I want to search stickers by alt text keyword. | Search input in sticker picker filters across all favorited collections. |

### 1.3 Why This Is Needed Now

GIFs and stickers are a core communication medium for modern messaging. They enable emotional expression beyond text and emoji, increase engagement, and are expected by users from any messaging platform. The mock GIF API ensures development and testing work offline without external dependencies.

---

## 2. Current State Analysis

### 2.1 Message Kinds

Current message kinds in `app/routers/messaging.py`: `text`, `image`, `file_share`, `calendar_share`, `calendar_event`, `meeting_poll`. The `kind` field on messages determines how `MessageBubble.tsx` renders the content. Adding `gif` and `sticker` kinds follows the same pattern.

### 2.2 Message Send Flow

`send_text_message()` in `app/services/messaging.py` stores a message item in the `Messages` DDB table with fields including `kind`, `text`, and various media fields. Image messages use `create_image_message()` with `image_url`, `image_width`, `image_height`. GIF and sticker messages will follow the same pattern with their own dedicated fields.

### 2.3 ComposeBar

`ComposeBar.tsx` has a toolbar row with buttons for emoji, image, file, tip, lock, encryption, view-once, and schedule. GIF and sticker buttons will be added to this toolbar, opening picker panels similar to the EmojiPicker (MSG-006).

### 2.4 S3 Storage

Sticker images are static assets uploaded by admins. They will be stored in S3 under `stickers/{collection_id}/{sticker_id}.{ext}`. GIF URLs come from the mock provider (no S3 storage needed for GIFs).

### 2.5 Gaps

1. **No GIF search/send** — no GIF provider integration, no GIF message kind.
2. **No sticker collections** — no DDB table, no upload endpoint, no collection browsing.
3. **No `gif` or `sticker` message kind** — MessageBubble doesn't render these types.
4. **No GIF/Sticker picker UI** — no panels in ComposeBar.
5. **No mock GIF API** — dev mode needs deterministic GIF results.

---

## 3. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React)                                │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐   │
│  │  ComposeBar   │    │  GifPicker   │    │  StickerPicker           │   │
│  │  ┌──────────┐ │    │  ┌────────┐  │    │  ┌──────────────────┐   │   │
│  │  │ GIF btn  │─┼───>│  │ Search │  │    │  │ Collection Tabs  │   │   │
│  │  │ Stk btn  │─┼─┐  │  │  Input │  │    │  │ ┌──────────┐    │   │   │
│  │  └──────────┘ │ │  │  └───┬────┘  │    │  │ │ Stickers │    │   │   │
│  └──────────────┘ │ │  │      │       │    │  │ │   Grid   │    │   │   │
│                    │ │  │  ┌───▼────┐  │    │  │ └──────────┘    │   │   │
│                    │ │  │  │ Result │  │    │  └──────────────────┘   │   │
│                    │ │  │  │  Grid  │  │    │  ┌──────────────────┐   │   │
│                    │ │  │  └───┬────┘  │    │  │ Browse All Tab   │   │   │
│                    │ │  │      │click  │    │  │  + Add Favorite  │   │   │
│                    │ └─>│  └───┘       │    │  └──────────────────┘   │   │
│                    │    └──────┬───────┘    └──────────┬──────────────┘   │
│                    │           │                        │                  │
│  ┌─────────────────▼───────────▼────────────────────────▼──────────────┐  │
│  │                   MessageBubble                                     │  │
│  │   kind=gif  → <img src={gif_url} />  (animated, max-w-xs)          │  │
│  │   kind=sticker → <img src={sticker_url} />  (128x128, contain)     │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTP
┌───────────────────────────────────▼──────────────────────────────────────┐
│                         BACKEND (FastAPI)                                 │
│                                                                          │
│  ┌──────────────────────────┐    ┌─────────────────────────────────────┐ │
│  │  sticker_collections     │    │  messaging router                   │ │
│  │  router                  │    │                                     │ │
│  │                          │    │  POST /conversations/{id}/          │ │
│  │  GET /collections        │    │       messages/gif                  │ │
│  │  GET /collections/{id}/  │    │  POST /conversations/{id}/          │ │
│  │       stickers           │    │       messages/sticker              │ │
│  │  POST /favorites/{id}    │    │                                     │ │
│  │  DELETE /favorites/{id}  │    │  → send_gif_message()               │ │
│  │  GET /favorites          │    │  → send_sticker_message()           │ │
│  │  GET /search             │    └──────────┬──────────────────────────┘ │
│  │  GET /gifs/search        │               │                            │
│  │  GET /gifs/trending      │               │                            │
│  │                          │    ┌──────────▼──────────────────────────┐ │
│  │  Admin:                  │    │  Messages DDB Table                 │ │
│  │  POST /collections       │    │  PK: conversation_id               │ │
│  │  DELETE /collections/{id}│    │  SK: message_id                    │ │
│  └───────────┬──────────────┘    │  kind: "gif" | "sticker"           │ │
│              │                   │  gif_url, gif_alt_text, gif_width,  │ │
│   ┌──────────▼───────────┐       │  gif_height, sticker_id,           │ │
│   │  sticker_collections │       │  sticker_collection_id,            │ │
│   │  DDB Table           │       │  sticker_url, sticker_alt_text     │ │
│   │  PK: collection_id  │       └─────────────────────────────────────┘ │
│   │  SK: META | STICKER# │                                              │
│   └──────────┬───────────┘       ┌─────────────────────────────────────┐ │
│              │                   │  gif_provider.py (mock)             │ │
│   ┌──────────▼───────────┐       │  search_gifs() → deterministic     │ │
│   │  S3 (moto mock)     │       │  trending_gifs() → full list       │ │
│   │  stickers/{coll_id}/│       └─────────────────────────────────────┘ │
│   │    {sticker_id}.png │                                               │
│   └──────────────────────┘       ┌─────────────────────────────────────┐ │
│                                  │  billing DDB Table (favorites)      │ │
│                                  │  PK: USER#{user_sub}                │ │
│                                  │  SK: FAV_STICKER#{collection_id}    │ │
│                                  └─────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

**Data Flow — Sending a GIF**:
1. User opens GifPicker from ComposeBar
2. GifPicker calls `GET /ui/stickers/gifs/search?q=happy`
3. Mock provider returns deterministic results based on query hash
4. User clicks a GIF result
5. ComposeBar calls `POST /conversations/{id}/messages/gif` with `gif_url`, `gif_alt_text`, `gif_width`, `gif_height`
6. Backend stores message item with `kind=gif` + GIF fields
7. SSE broadcasts new message to conversation participants
8. MessageBubble renders `<img>` with GIF URL

**Data Flow — Sending a Sticker**:
1. User opens StickerPicker from ComposeBar
2. StickerPicker loads `GET /ui/stickers/favorites` (favorited collections with stickers)
3. User browses collections, clicks a sticker
4. ComposeBar calls `POST /conversations/{id}/messages/sticker` with `sticker_id`, `sticker_collection_id`
5. Backend resolves sticker URL from DDB, stores message item with `kind=sticker`
6. SSE broadcasts new message
7. MessageBubble renders `<img>` with sticker URL at 128x128

---

## 4. Technical Design

### 4.1 DynamoDB Table: `sticker_collections`

Single-table design with collection metadata and individual sticker items:

| Attribute | Type | Description |
|-----------|------|-------------|
| `collection_id` (PK) | String | `sc_<uuid4_hex>` |
| `sk` (SK) | String | `META` for collection info, `STICKER#{sticker_id}` for stickers |
| `name` | String | Collection name (e.g., "Cute Cats") |
| `description` | String | Collection description |
| `thumbnail_url` | String | Cover image URL (first sticker or custom) |
| `sticker_count` | Number | Number of stickers in collection |
| `created_by` | String | Admin user sub who created it |
| `created_at` | Number | Unix timestamp |
| `is_active` | Boolean | Whether collection is visible to users |

Sticker items (SK = `STICKER#{sticker_id}`):

| Attribute | Type | Description |
|-----------|------|-------------|
| `sticker_id` | String | `stk_<uuid4_hex>` |
| `image_url` | String | S3 URL for sticker image |
| `alt_text` | String | Accessibility description |
| `sort_order` | Number | Display order within collection |
| `width` | Number | Image width in pixels |
| `height` | Number | Image height in pixels |

**User favorites** are stored in the user's preferences (billing table pattern):

| PK | SK | Fields |
|----|----|--------|
| `USER#{user_sub}` | `FAV_STICKER#{collection_id}` | `added_at: Number` |

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `GSI1` | `is_active` (String "1"/"0") | `created_at` | List active collections sorted by recency |

**File**: `scripts/local-ddb-init.py`

```python
TableDef(
    name=S.ddb_sticker_collections_table,
    pk="collection_id",
    sk="sk",
    gsis=[
        GsiDef(name="GSI1", pk="is_active", sk="created_at"),
    ],
    attr_types={"created_at": "N", "sticker_count": "N", "sort_order": "N"},
),
```

### 4.2 DynamoDB Access Patterns

| # | Access Pattern | Table/Index | PK | SK | Projection | Notes |
|---|---------------|-------------|----|----|------------|-------|
| 1 | Get collection metadata | `sticker_collections` | `collection_id = "sc_<hex>"` | `sk = "META"` | All | `GetItem` — single read |
| 2 | List stickers in collection | `sticker_collections` | `collection_id = "sc_<hex>"` | `sk BEGINS_WITH "STICKER#"` | All | `Query` — paginate by sort_order |
| 3 | List active collections | `sticker_collections / GSI1` | `is_active = "1"` | `created_at DESC` | All | `Query ScanIndexForward=False` |
| 4 | Get user's favorites | `billing` | `USER#{user_sub}` | `sk BEGINS_WITH "FAV_STICKER#"` | collection_id, added_at | `Query` — returns all favorited collection IDs |
| 5 | Add favorite | `billing` | `USER#{user_sub}` | `FAV_STICKER#{collection_id}` | — | `PutItem` — idempotent |
| 6 | Remove favorite | `billing` | `USER#{user_sub}` | `FAV_STICKER#{collection_id}` | — | `DeleteItem` — idempotent |
| 7 | Soft-delete collection | `sticker_collections` | `collection_id = "sc_<hex>"` | `sk = "META"` | — | `UpdateItem SET is_active = "0"` |
| 8 | Get GIF message | `messages` | `conversation_id` | `message_id` | gif_url, gif_alt_text, gif_width, gif_height | Standard message fetch |
| 9 | Get sticker message | `messages` | `conversation_id` | `message_id` | sticker_id, sticker_collection_id, sticker_url, sticker_alt_text | Standard message fetch |

**Example DynamoDB Items**:

```json
// Collection META item
{
  "collection_id": {"S": "sc_a1b2c3d4e5f6"},
  "sk": {"S": "META"},
  "name": {"S": "Cute Cats"},
  "description": {"S": "Adorable cat stickers for every occasion"},
  "thumbnail_url": {"S": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_001.png"},
  "sticker_count": {"N": "12"},
  "created_by": {"S": "admin-user-sub-001"},
  "created_at": {"N": "1748500000"},
  "is_active": {"S": "1"}
}

// Sticker item
{
  "collection_id": {"S": "sc_a1b2c3d4e5f6"},
  "sk": {"S": "STICKER#stk_f1e2d3c4b5a6"},
  "sticker_id": {"S": "stk_f1e2d3c4b5a6"},
  "image_url": {"S": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_f1e2d3c4b5a6.png"},
  "alt_text": {"S": "Cat waving hello"},
  "sort_order": {"N": "1"},
  "width": {"N": "256"},
  "height": {"N": "256"}
}

// User favorite
{
  "pk": {"S": "USER#alice-sub-001"},
  "sk": {"S": "FAV_STICKER#sc_a1b2c3d4e5f6"},
  "added_at": {"N": "1748500500"}
}

// GIF message
{
  "conversation_id": {"S": "conv_abc123"},
  "message_id": {"S": "m_def456"},
  "kind": {"S": "gif"},
  "sender_id": {"S": "alice-sub-001"},
  "gif_url": {"S": "/mock/gifs/placeholder_3.gif"},
  "gif_alt_text": {"S": "Happy dance animation"},
  "gif_width": {"N": "320"},
  "gif_height": {"N": "240"},
  "gif_provider": {"S": "mock"},
  "created_at": {"N": "1748501000"}
}

// Sticker message
{
  "conversation_id": {"S": "conv_abc123"},
  "message_id": {"S": "m_ghi789"},
  "kind": {"S": "sticker"},
  "sender_id": {"S": "alice-sub-001"},
  "sticker_id": {"S": "stk_f1e2d3c4b5a6"},
  "sticker_collection_id": {"S": "sc_a1b2c3d4e5f6"},
  "sticker_url": {"S": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_f1e2d3c4b5a6.png"},
  "sticker_alt_text": {"S": "Cat waving hello"},
  "created_at": {"N": "1748501100"}
}
```

### 4.3 Message Schema Extension

**File**: `app/models.py`

```python
class GifMessageFields(BaseModel):
    gif_url: str = Field(..., max_length=2048)
    gif_alt_text: str = Field(default="", max_length=256)
    gif_width: int = Field(default=0, ge=0, le=4096)
    gif_height: int = Field(default=0, ge=0, le=4096)
    gif_provider: str = Field(default="mock", max_length=32)  # "mock", "tenor", "giphy"

class StickerMessageFields(BaseModel):
    sticker_id: str = Field(..., max_length=64)
    sticker_collection_id: str = Field(..., max_length=64)
    sticker_url: str = Field(..., max_length=2048)
    sticker_alt_text: str = Field(default="", max_length=256)
```

Add to `MessageOut`:

```python
gif_url: Optional[str] = None
gif_alt_text: Optional[str] = None
gif_width: Optional[int] = None
gif_height: Optional[int] = None
sticker_id: Optional[str] = None
sticker_collection_id: Optional[str] = None
sticker_url: Optional[str] = None
sticker_alt_text: Optional[str] = None
```

### 4.4 Mock GIF Provider

**File**: `app/services/gif_provider.py`

```python
MOCK_GIFS = [
    {
        "id": "mock_gif_001",
        "url": "/mock/gifs/placeholder_1.gif",
        "alt_text": "Happy dance animation",
        "width": 320,
        "height": 240,
    },
    # ... 20 deterministic mock entries
]

def search_gifs(query: str, limit: int = 20, offset: int = 0) -> list[dict]:
    """Search mock GIF provider. Returns deterministic results based on query hash."""
    if not query.strip():
        return MOCK_GIFS[:limit]
    # Deterministic: hash query → select subset of MOCK_GIFS
    h = hash(query.lower().strip()) % len(MOCK_GIFS)
    results = (MOCK_GIFS[h:] + MOCK_GIFS[:h])[:limit]
    return results

def trending_gifs(limit: int = 20) -> list[dict]:
    """Return trending GIFs (mock: returns full list)."""
    return MOCK_GIFS[:limit]
```

### 4.5 Backend Service

**File**: `app/services/sticker_collections.py`

```python
def create_collection(*, name, description, created_by, stickers: list[UploadFile]) -> dict:
    """Create a sticker collection with uploaded images."""

def list_collections(active_only: bool = True) -> list[dict]:
    """List sticker collections."""

def get_collection_stickers(collection_id: str) -> list[dict]:
    """List all stickers in a collection."""

def add_favorite(user_sub: str, collection_id: str) -> None:
    """Add a collection to user's favorites."""

def remove_favorite(user_sub: str, collection_id: str) -> None:
    """Remove a collection from user's favorites."""

def list_favorites(user_sub: str) -> list[str]:
    """List user's favorited collection IDs."""

def delete_collection(collection_id: str) -> bool:
    """Soft-delete a collection (set is_active=False)."""
```

### 4.6 Backend Router

**File**: `app/routers/sticker_collections.py`

```python
router = APIRouter(prefix="/ui/stickers", tags=["stickers"])

@router.get("/collections")
def list_sticker_collections(ctx=Depends(require_ui_session)):
    """List all active sticker collections."""

@router.get("/collections/{collection_id}/stickers")
def get_stickers(collection_id: str, ctx=Depends(require_ui_session)):
    """List stickers in a collection."""

@router.post("/favorites/{collection_id}")
def add_to_favorites(collection_id: str, ctx=Depends(require_ui_session)):
    """Add a sticker collection to favorites."""

@router.delete("/favorites/{collection_id}")
def remove_from_favorites(collection_id: str, ctx=Depends(require_ui_session)):
    """Remove a sticker collection from favorites."""

@router.get("/favorites")
def list_my_favorites(ctx=Depends(require_ui_session)):
    """List user's favorited sticker collections with stickers."""

@router.get("/search")
def search_stickers(q: str = Query(...), ctx=Depends(require_ui_session)):
    """Search stickers by alt_text across favorited collections."""

# GIF search
@router.get("/gifs/search")
def search_gifs_endpoint(q: str = Query(default=""), limit: int = Query(default=20, le=50), ctx=Depends(require_ui_session)):
    """Search GIFs via mock provider."""

@router.get("/gifs/trending")
def trending_gifs_endpoint(limit: int = Query(default=20, le=50), ctx=Depends(require_ui_session)):
    """Get trending GIFs."""

# Admin
admin_router = APIRouter(prefix="/v1/admin/stickers", tags=["admin-stickers"])

@admin_router.post("/collections", status_code=201)
async def create_sticker_collection(
    name: str = Form(...),
    description: str = Form(default=""),
    files: list[UploadFile] = File(...),
    alt_texts: str = Form(default=""),  # comma-separated, one per file
    ctx=Depends(require_admin_session),
):
    """Create a sticker collection with uploaded images (admin only)."""

@admin_router.delete("/collections/{collection_id}")
def delete_sticker_collection(collection_id: str, ctx=Depends(require_admin_session)):
    """Delete a sticker collection (admin only)."""
```

### 4.7 Messaging Endpoints for GIF/Sticker Send

**File**: `app/routers/messaging.py`

Add to existing message send infrastructure:

```python
class SendGifMessageIn(BaseModel):
    gif_url: str = Field(..., max_length=2048)
    gif_alt_text: str = Field(default="", max_length=256)
    gif_width: int = Field(default=0, ge=0)
    gif_height: int = Field(default=0, ge=0)
    reply_to_message_id: Optional[str] = None

class SendStickerMessageIn(BaseModel):
    sticker_id: str = Field(..., max_length=64)
    sticker_collection_id: str = Field(..., max_length=64)
    reply_to_message_id: Optional[str] = None

@router.post("/conversations/{conv_id}/messages/gif", status_code=201)
def send_gif_message(conv_id: str, body: SendGifMessageIn, ctx=Depends(require_ui_session)):
    """Send a GIF message to a conversation."""

@router.post("/conversations/{conv_id}/messages/sticker", status_code=201)
def send_sticker_message(conv_id: str, body: SendStickerMessageIn, ctx=Depends(require_ui_session)):
    """Send a sticker message to a conversation."""
```

### 4.8 API Request/Response Examples

#### 4.8.1 Search GIFs

```bash
curl -s -X GET "http://localhost:8000/ui/stickers/gifs/search?q=happy&limit=5" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  | jq .
```

**Response** (200):
```json
[
  {
    "id": "mock_gif_007",
    "url": "/mock/gifs/placeholder_7.gif",
    "alt_text": "Happy dance animation",
    "width": 320,
    "height": 240
  },
  {
    "id": "mock_gif_008",
    "url": "/mock/gifs/placeholder_8.gif",
    "alt_text": "Celebration confetti",
    "width": 400,
    "height": 300
  },
  {
    "id": "mock_gif_009",
    "url": "/mock/gifs/placeholder_9.gif",
    "alt_text": "Jumping for joy",
    "width": 320,
    "height": 320
  }
]
```

#### 4.8.2 Get Trending GIFs

```bash
curl -s -X GET "http://localhost:8000/ui/stickers/gifs/trending?limit=3" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  | jq .
```

**Response** (200):
```json
[
  {
    "id": "mock_gif_001",
    "url": "/mock/gifs/placeholder_1.gif",
    "alt_text": "Happy dance animation",
    "width": 320,
    "height": 240
  },
  {
    "id": "mock_gif_002",
    "url": "/mock/gifs/placeholder_2.gif",
    "alt_text": "Laughing out loud",
    "width": 280,
    "height": 210
  },
  {
    "id": "mock_gif_003",
    "url": "/mock/gifs/placeholder_3.gif",
    "alt_text": "Thumbs up approval",
    "width": 320,
    "height": 240
  }
]
```

#### 4.8.3 List Sticker Collections

```bash
curl -s -X GET "http://localhost:8000/ui/stickers/collections" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  | jq .
```

**Response** (200):
```json
{
  "collections": [
    {
      "collection_id": "sc_a1b2c3d4e5f6",
      "name": "Cute Cats",
      "description": "Adorable cat stickers for every occasion",
      "thumbnail_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_001.png",
      "sticker_count": 12,
      "is_active": true,
      "created_at": 1748500000
    },
    {
      "collection_id": "sc_b2c3d4e5f607",
      "name": "Party Time",
      "description": "Celebration and party stickers",
      "thumbnail_url": "/mock/s3/stickers/sc_b2c3d4e5f607/stk_001.png",
      "sticker_count": 8,
      "is_active": true,
      "created_at": 1748499000
    }
  ]
}
```

#### 4.8.4 Get Stickers in Collection

```bash
curl -s -X GET "http://localhost:8000/ui/stickers/collections/sc_a1b2c3d4e5f6/stickers" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  | jq .
```

**Response** (200):
```json
{
  "stickers": [
    {
      "sticker_id": "stk_f1e2d3c4b5a6",
      "image_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_f1e2d3c4b5a6.png",
      "alt_text": "Cat waving hello",
      "sort_order": 1,
      "width": 256,
      "height": 256
    },
    {
      "sticker_id": "stk_a2b3c4d5e6f7",
      "image_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_a2b3c4d5e6f7.png",
      "alt_text": "Cat sleeping",
      "sort_order": 2,
      "width": 256,
      "height": 256
    }
  ]
}
```

#### 4.8.5 Add Collection to Favorites

```bash
curl -s -X POST "http://localhost:8000/ui/stickers/favorites/sc_a1b2c3d4e5f6" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  | jq .
```

**Response** (200):
```json
{
  "ok": true,
  "collection_id": "sc_a1b2c3d4e5f6"
}
```

#### 4.8.6 Send GIF Message

```bash
curl -s -X POST "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/gif" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "gif_url": "/mock/gifs/placeholder_7.gif",
    "gif_alt_text": "Happy dance animation",
    "gif_width": 320,
    "gif_height": 240
  }' | jq .
```

**Response** (201):
```json
{
  "message_id": "m_abc123def456",
  "conversation_id": "conv_abc123",
  "sender_id": "alice-sub-001",
  "kind": "gif",
  "gif_url": "/mock/gifs/placeholder_7.gif",
  "gif_alt_text": "Happy dance animation",
  "gif_width": 320,
  "gif_height": 240,
  "gif_provider": "mock",
  "created_at": 1748501000,
  "text": null,
  "reactions": {}
}
```

#### 4.8.7 Send Sticker Message

```bash
curl -s -X POST "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/sticker" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "sticker_id": "stk_f1e2d3c4b5a6",
    "sticker_collection_id": "sc_a1b2c3d4e5f6"
  }' | jq .
```

**Response** (201):
```json
{
  "message_id": "m_ghi789jkl012",
  "conversation_id": "conv_abc123",
  "sender_id": "alice-sub-001",
  "kind": "sticker",
  "sticker_id": "stk_f1e2d3c4b5a6",
  "sticker_collection_id": "sc_a1b2c3d4e5f6",
  "sticker_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_f1e2d3c4b5a6.png",
  "sticker_alt_text": "Cat waving hello",
  "created_at": 1748501100,
  "text": null,
  "reactions": {}
}
```

#### 4.8.8 Admin Create Sticker Collection

```bash
curl -s -X POST "http://localhost:8000/v1/admin/stickers/collections" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=jwt_root" \
  -H "x-csrf-token: csrf_root" \
  -F "name=Cute Cats" \
  -F "description=Adorable cat stickers for every occasion" \
  -F "alt_texts=Cat waving hello,Cat sleeping,Cat laughing" \
  -F "files=@/path/to/cat1.png" \
  -F "files=@/path/to/cat2.png" \
  -F "files=@/path/to/cat3.png" \
  | jq .
```

**Response** (201):
```json
{
  "collection_id": "sc_a1b2c3d4e5f6",
  "name": "Cute Cats",
  "description": "Adorable cat stickers for every occasion",
  "sticker_count": 3,
  "thumbnail_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_001.png",
  "is_active": true,
  "created_at": 1748500000,
  "stickers": [
    {
      "sticker_id": "stk_f1e2d3c4b5a6",
      "image_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_f1e2d3c4b5a6.png",
      "alt_text": "Cat waving hello",
      "sort_order": 1
    },
    {
      "sticker_id": "stk_a2b3c4d5e6f7",
      "image_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_a2b3c4d5e6f7.png",
      "alt_text": "Cat sleeping",
      "sort_order": 2
    },
    {
      "sticker_id": "stk_c3d4e5f6a7b8",
      "image_url": "/mock/s3/stickers/sc_a1b2c3d4e5f6/stk_c3d4e5f6a7b8.png",
      "alt_text": "Cat laughing",
      "sort_order": 3
    }
  ]
}
```

### 4.9 Pydantic Models

```python
# ---------- GIF Provider ----------

class GifSearchResult(BaseModel):
    """Single GIF result from the provider."""
    id: str = Field(..., description="Provider-specific GIF ID")
    url: str = Field(..., max_length=2048, description="GIF URL (direct link)")
    alt_text: str = Field(default="", max_length=256, description="GIF alt text")
    width: int = Field(default=0, ge=0, le=4096, description="Width in pixels")
    height: int = Field(default=0, ge=0, le=4096, description="Height in pixels")

    model_config = {"json_schema_extra": {"examples": [
        {"id": "mock_gif_001", "url": "/mock/gifs/placeholder_1.gif",
         "alt_text": "Happy dance animation", "width": 320, "height": 240}
    ]}}

class GifSearchResponse(BaseModel):
    """Response from GIF search/trending endpoints."""
    results: list[GifSearchResult]

# ---------- Sticker Collections ----------

class StickerOut(BaseModel):
    """Single sticker within a collection."""
    sticker_id: str = Field(..., max_length=64)
    image_url: str = Field(..., max_length=2048)
    alt_text: str = Field(default="", max_length=256)
    sort_order: int = Field(default=0, ge=0)
    width: int = Field(default=256, ge=0, le=4096)
    height: int = Field(default=256, ge=0, le=4096)

class StickerCollectionOut(BaseModel):
    """Sticker collection metadata."""
    collection_id: str
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    thumbnail_url: Optional[str] = None
    sticker_count: int = Field(default=0, ge=0)
    is_active: bool = True
    created_at: int
    stickers: list[StickerOut] = Field(default_factory=list)

class StickerCollectionListOut(BaseModel):
    """Response for listing sticker collections."""
    collections: list[StickerCollectionOut]

class StickerFavoriteOut(BaseModel):
    """Response when adding/removing a favorite."""
    ok: bool
    collection_id: str

class StickerSearchResult(BaseModel):
    """A sticker matching a search query."""
    sticker_id: str
    collection_id: str
    image_url: str
    alt_text: str
    collection_name: str

class StickerSearchResponse(BaseModel):
    """Response for sticker search."""
    results: list[StickerSearchResult]

# ---------- Message Send Models ----------

class SendGifMessageIn(BaseModel):
    """Request body for sending a GIF message."""
    gif_url: str = Field(..., max_length=2048,
        description="Direct URL of the GIF to send")
    gif_alt_text: str = Field(default="", max_length=256,
        description="Accessibility alt text for the GIF")
    gif_width: int = Field(default=0, ge=0, le=4096,
        description="GIF width in pixels")
    gif_height: int = Field(default=0, ge=0, le=4096,
        description="GIF height in pixels")
    reply_to_message_id: Optional[str] = Field(default=None,
        description="Message ID this GIF is replying to")

    model_config = {"json_schema_extra": {"examples": [
        {"gif_url": "/mock/gifs/placeholder_7.gif",
         "gif_alt_text": "Happy dance animation",
         "gif_width": 320, "gif_height": 240}
    ]}}

class SendStickerMessageIn(BaseModel):
    """Request body for sending a sticker message."""
    sticker_id: str = Field(..., max_length=64,
        description="ID of the sticker to send")
    sticker_collection_id: str = Field(..., max_length=64,
        description="Collection ID the sticker belongs to")
    reply_to_message_id: Optional[str] = Field(default=None,
        description="Message ID this sticker is replying to")

    model_config = {"json_schema_extra": {"examples": [
        {"sticker_id": "stk_f1e2d3c4b5a6",
         "sticker_collection_id": "sc_a1b2c3d4e5f6"}
    ]}}

# ---------- Admin Models ----------

class CreateStickerCollectionOut(BaseModel):
    """Response after creating a sticker collection (admin)."""
    collection_id: str
    name: str
    description: str
    sticker_count: int
    thumbnail_url: Optional[str] = None
    is_active: bool = True
    created_at: int
    stickers: list[StickerOut]
```

### 4.10 Frontend Components

**GifPicker** (`frontend/src/components/shared/GifPicker.tsx`):

```typescript
interface GifPickerProps {
  onSelect: (gif: { url: string; alt_text: string; width: number; height: number }) => void;
  onClose?: () => void;
}
```

- Search input with debounced API call (300ms)
- Grid layout (2 columns, masonry-style based on aspect ratio)
- Trending GIFs shown on initial open (no search term)
- Click GIF → calls `onSelect`
- `data-testid="gif-picker"`

**StickerPicker** (`frontend/src/components/shared/StickerPicker.tsx`):

```typescript
interface StickerPickerProps {
  onSelect: (sticker: { id: string; collection_id: string; url: string; alt_text: string }) => void;
  onClose?: () => void;
}
```

- Tab bar of favorited collections
- "Browse All" tab to discover new collections
- Grid of stickers (4 columns)
- Search input filters by alt_text
- "Add to Favorites" button on non-favorited collections
- Click sticker → calls `onSelect`
- `data-testid="sticker-picker"`

**MessageBubble** enhancement for GIF and sticker rendering:

```tsx
// GIF rendering
{message.kind === "gif" && message.gif_url && (
  <div className="max-w-xs">
    <img
      src={message.gif_url}
      alt={message.gif_alt_text || "GIF"}
      className="rounded-lg w-full"
      style={{ aspectRatio: `${message.gif_width || 320} / ${message.gif_height || 240}` }}
      loading="lazy"
    />
  </div>
)}

// Sticker rendering
{message.kind === "sticker" && message.sticker_url && (
  <div className="w-32 h-32">
    <img
      src={message.sticker_url}
      alt={message.sticker_alt_text || "Sticker"}
      className="w-full h-full object-contain"
    />
  </div>
)}
```

### 4.11 Frontend Component Tree

```
ComposeBar
├── ToolbarRow
│   ├── EmojiPickerButton (existing)
│   ├── GifButton (new)
│   │   └── Popover
│   │       └── GifPicker
│   │           ├── SearchInput (debounced 300ms)
│   │           ├── GifGrid (2-col masonry)
│   │           │   └── GifCard[] (img + alt overlay)
│   │           └── LoadingSkeleton (during fetch)
│   ├── StickerButton (new)
│   │   └── Popover
│   │       └── StickerPicker
│   │           ├── TabBar (favorited collections)
│   │           │   └── CollectionTab[] (thumbnail + name)
│   │           ├── StickerGrid (4-col)
│   │           │   └── StickerCard[] (img + alt tooltip)
│   │           ├── SearchInput (filters alt_text)
│   │           ├── BrowseAllTab
│   │           │   ├── CollectionCard[] (thumbnail + name + "Add to Favorites")
│   │           │   └── EmptyState
│   │           └── LoadingSkeleton (during fetch)
│   ├── ImageButton (existing)
│   ├── FileButton (existing)
│   └── ... (other existing buttons)
├── TextArea (existing)
└── SendButton (existing)

MessageBubble (enhanced)
├── SenderHeader (existing)
├── ContentArea
│   ├── TextContent (existing, kind=text)
│   ├── ImageContent (existing, kind=image)
│   ├── GifContent (new, kind=gif)            ← <img> animated, max-w-xs, aspect-ratio
│   │   └── img[src=gif_url, alt=gif_alt_text]
│   ├── StickerContent (new, kind=sticker)    ← <img> 128x128, object-contain
│   │   └── img[src=sticker_url, alt=sticker_alt_text]
│   └── ... (other kinds)
├── ReactionBar (existing)
└── MessageMeta (existing: timestamp, read status)
```

**State Management (ComposeBar)**:
```typescript
const [gifPickerOpen, setGifPickerOpen] = useState(false);
const [stickerPickerOpen, setStickerPickerOpen] = useState(false);

// Mutations
const sendGifMut = useMutation({
  mutationFn: (data: SendGifMessageIn) =>
    sendGifMessage(conversationId, data),
  onSuccess: () => queryClient.invalidateQueries(["messages", conversationId]),
});

const sendStickerMut = useMutation({
  mutationFn: (data: SendStickerMessageIn) =>
    sendStickerMessage(conversationId, data),
  onSuccess: () => queryClient.invalidateQueries(["messages", conversationId]),
});
```

### 4.12 Settings

```python
# GIF & Sticker messages (MSG-008)
ddb_sticker_collections_table: str = os.environ.get("DDB_STICKER_COLLECTIONS_TABLE", "sticker_collections")
gif_provider: str = os.environ.get("GIF_PROVIDER", "mock")  # "mock", "tenor", "giphy"
sticker_max_file_size_bytes: int = int(os.environ.get("STICKER_MAX_FILE_SIZE", "524288"))  # 512KB
sticker_max_per_collection: int = int(os.environ.get("STICKER_MAX_PER_COLLECTION", "100"))
```

---

## 5. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|-----------------|
| 1 | GIF URL exceeds 2048 chars | 422 | `validation_error` | "GIF URL is too long" | Truncate URL or use a shorter GIF link |
| 2 | GIF URL not from allowed domain | 400 | `gif_url_not_allowed` | "GIF URL is not from an allowed provider" | Select a GIF from the built-in GIF picker |
| 3 | Sticker not found in collection | 404 | `sticker_not_found` | "Sticker not found" | Refresh sticker list and try again |
| 4 | Sticker collection not found | 404 | `collection_not_found` | "Sticker collection not found" | Refresh collections list |
| 5 | Collection soft-deleted (inactive) | 404 | `collection_not_found` | "Sticker collection not found" | Remove from favorites and refresh |
| 6 | Non-admin creating collection | 403 | `forbidden` | "Forbidden" | Contact an admin to create collections |
| 7 | Sticker file exceeds 512KB | 400 | `file_too_large` | "File too large (max 512KB)" | Compress image or reduce dimensions |
| 8 | Sticker file not PNG/WebP/SVG | 400 | `invalid_file_type` | "Only PNG, WebP, and SVG sticker images are supported" | Convert to a supported format |
| 9 | Collection at max stickers (100) | 400 | `collection_full` | "Collection has reached maximum sticker count" | Create a new collection or remove existing stickers |
| 10 | Favorite already exists | 200 | — | (Idempotent, no error) | No action needed |
| 11 | Favorite not found on remove | 200 | — | (Idempotent, no error) | No action needed |
| 12 | User not conversation participant | 403 | `not_participant` | "You are not a participant in this conversation" | Join the conversation first |
| 13 | GIF search rate limit exceeded | 429 | `rate_limit_exceeded` | "Too many requests. Try again in a moment." | Wait 60s and retry |
| 14 | Empty sticker collection upload | 400 | `no_stickers` | "At least one sticker image is required" | Attach at least one image file |
| 15 | Duplicate collection name (same admin) | 409 | `collection_name_conflict` | "A collection with this name already exists" | Choose a different collection name |

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/gif_provider.py` | Mock GIF search provider |
| `app/services/sticker_collections.py` | Sticker collection CRUD + S3 upload |
| `app/routers/sticker_collections.py` | Sticker + GIF REST endpoints |
| `frontend/src/components/shared/GifPicker.tsx` | GIF search and select component |
| `frontend/src/components/shared/StickerPicker.tsx` | Sticker browsing component |
| `frontend/src/api/endpoints/stickers.ts` | API client for stickers + GIFs |
| `app/static/mock/gifs/` | Directory with placeholder animated GIF files |

### 6.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `sticker_collections` TableDef |
| `app/core/settings.py` | Add sticker/GIF settings |
| `app/core/tables.py` | Add `T.sticker_collections` |
| `app/main.py` | Register sticker router |
| `app/models.py` | Add GIF/sticker fields to MessageOut |
| `app/routers/messaging.py` | Add GIF/sticker send endpoints |
| `frontend/src/api/types.ts` | Add GIF/sticker TypeScript types |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add GIF + Sticker buttons and pickers |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render GIF and sticker messages |

### 6.3 Step-by-Step Order

1. Add DDB table, settings, table handle
2. Implement mock GIF provider
3. Implement sticker collection service
4. Implement router (GIF search + sticker endpoints + admin)
5. Add GIF/sticker send endpoints to messaging router
6. Add frontend types and API client
7. Build GifPicker component
8. Build StickerPicker component
9. Integrate pickers into ComposeBar
10. Add GIF/sticker rendering in MessageBubble
11. Seed mock sticker collection for dev/test
12. Write E2E tests

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `msg008_gif_search_total` | Counter | `status` | GIF searches (success/error) |
| `msg008_gif_message_sent_total` | Counter | `provider` | GIF messages sent by provider |
| `msg008_sticker_message_sent_total` | Counter | — | Sticker messages sent |
| `msg008_collection_created_total` | Counter | — | Sticker collections created by admin |
| `msg008_favorite_added_total` | Counter | — | Sticker collections added to favorites |
| `msg008_favorite_removed_total` | Counter | — | Sticker collections removed from favorites |
| `msg008_sticker_search_total` | Counter | `status` | Sticker searches (success/empty/error) |
| `msg008_gif_search_latency_ms` | Histogram | — | GIF search response time |
| `msg008_sticker_upload_size_bytes` | Histogram | — | Size of uploaded sticker files |

### 7.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `gif.search` | INFO | `user_sub`, `query`, `result_count` | GIF search executed |
| `gif.message.sent` | INFO | `user_sub`, `conversation_id`, `gif_url` | GIF message sent |
| `sticker.message.sent` | INFO | `user_sub`, `conversation_id`, `sticker_id`, `collection_id` | Sticker message sent |
| `sticker.collection.created` | INFO | `admin_sub`, `collection_id`, `sticker_count` | Admin created collection |
| `sticker.collection.deleted` | INFO | `admin_sub`, `collection_id` | Admin soft-deleted collection |
| `sticker.favorite.added` | INFO | `user_sub`, `collection_id` | User favorited a collection |
| `sticker.upload.rejected` | WARN | `admin_sub`, `filename`, `size_bytes`, `reason` | Sticker upload rejected (too large / wrong type) |
| `gif.search.rate_limited` | WARN | `user_sub`, `count_last_minute` | User hit GIF search rate limit |

### 7.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| GIF search error rate > 5% | `rate(msg008_gif_search_total{status="error"}) / rate(msg008_gif_search_total) > 0.05` | Warning | Check mock provider; verify GIF URLs are valid |
| Sticker upload failure spike | `increase(sticker.upload.rejected) > 20 in 1h` | Warning | Review uploaded files; check if size limit is too restrictive |
| S3 sticker write failure | `sticker.collection.created` with S3 error | Critical | Check S3/moto status; verify bucket permissions |
| GIF search latency p95 > 500ms | `histogram_quantile(0.95, msg008_gif_search_latency_ms) > 500` | Warning | In mock mode, indicates DDB table scan; add index or cache |
| Sticker collection count > 500 | `count(sticker_collections where is_active=1) > 500` | Info | Consider pagination or archiving old collections |

### 7.4 Dashboard Queries

```promql
# GIF vs Sticker message volume (last 24h)
sum by (kind) (increase(msg008_gif_message_sent_total[24h]))
sum(increase(msg008_sticker_message_sent_total[24h]))

# Most popular GIF search queries (requires log aggregation)
# topk(10, count by (query) (log{event="gif.search"} | logfmt))

# Sticker collection favorites funnel
sum(increase(msg008_favorite_added_total[7d]))
sum(increase(msg008_favorite_removed_total[7d]))
```

---

## 8. Rollout Plan

### 8.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `MSG008_GIF_ENABLED` | `false` | Enable GIF search and send |
| `MSG008_STICKER_ENABLED` | `false` | Enable sticker collections and send |
| `MSG008_ADMIN_STICKER_UPLOAD` | `false` | Enable admin sticker collection upload |

### 8.2 Rollout Phases

| Phase | Duration | Actions |
|-------|----------|---------|
| 1. Backend deploy | Day 1 | Deploy backend with all endpoints. Feature flags OFF. DDB table created. Mock GIF data seeded. |
| 2. Admin sticker setup | Day 2-3 | Enable `MSG008_ADMIN_STICKER_UPLOAD`. Admins create 5-10 sticker collections. Verify S3 uploads, collection listing, sticker rendering. |
| 3. Internal alpha | Day 4-7 | Enable `MSG008_GIF_ENABLED` + `MSG008_STICKER_ENABLED` for internal users (5%). Monitor GIF search latency, sticker load times, message rendering. |
| 4. Gradual rollout | Day 8-14 | Ramp to 25% → 50% → 100%. Monitor engagement metrics, error rates, S3 bandwidth. |
| 5. GA | Day 15 | Remove feature flags. Update documentation. |

### 8.3 Rollback Procedure

1. Set all three feature flags to `false` (immediate, no deploy needed).
2. Frontend hides GIF/Sticker buttons in ComposeBar; existing GIF/sticker messages still render.
3. If backend issues: revert backend deploy. GIF/sticker messages remain in DDB but `kind` is unrecognized by old MessageBubble — falls through to a "Unsupported message type" placeholder.
4. If S3 issues: sticker URLs return 404 — MessageBubble shows broken image with alt text.
5. Sticker collections and favorites remain in DDB (no data loss on rollback).

---

## 9. Performance Considerations

| # | Concern | Impact | Mitigation |
|---|---------|--------|------------|
| 1 | GIF search debounce flooding | High search volume on fast typers | 300ms debounce on GifPicker search input; server-side rate limit 30/min |
| 2 | GIF image bandwidth | Large animated GIFs (2-5MB each) | Use `loading="lazy"` on `<img>`; limit GIF search results to 20 per request; thumbnail previews in picker (smaller resolution) |
| 3 | Sticker collection listing | Admin creates 100+ collections | GSI1 query with `Limit=50` and cursor pagination; client-side collection caching (staleTime: 5min) |
| 4 | Sticker image loading in picker | 4-col grid with 100 stickers per collection | Lazy loading with IntersectionObserver; 256x256 images are small (~20-50KB PNG) |
| 5 | S3 upload bandwidth for admin | Uploading 100 stickers at once | Limit batch upload to 20 files per request; resize/compress on upload (max 512KB per file) |
| 6 | DDB read cost for favorites | Each `list_favorites` query + N `get_collection_stickers` queries | Batch with `Promise.all` on frontend; cache sticker lists per collection (staleTime: 10min); denormalize top-4 stickers into favorites response |
| 7 | GIF URL validation | Checking GIF URLs against allowed domains on every send | Maintain in-memory allow-list; O(1) lookup; mock mode skips validation |
| 8 | Conversation message list with mixed media | Scroll performance with many GIF messages | `loading="lazy"` and `decoding="async"` on all media `<img>` tags; virtual scrolling for conversations with 500+ messages |
| 9 | Sticker search across collections | Full scan of all stickers in all favorited collections | Alt-text keyword stored in DDB; query with `contains` filter; limit to 50 results; client-side debounce |

---

## 10. E2E Test Plan

### 10.1 Test File

`frontend/e2e/gif-sticker-messages.spec.ts` — 30 tests across 6 sections.

### 10.2 Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let bobPage: Page;
let dmConvoId: string;
let testCollectionId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Create/get DM conversation
  // Admin: create a test sticker collection with 3 stickers
});
```

### 10.3 Section 291: GIF Search API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 291.1 | Trending GIFs returns results | GET `/ui/stickers/gifs/trending`; 200; array length > 0; each has `url`, `alt_text` |
| 291.2 | GIF search returns filtered results | GET `/ui/stickers/gifs/search?q=happy`; 200; results non-empty |
| 291.3 | GIF search with empty query returns trending | GET `/ui/stickers/gifs/search?q=`; 200; same as trending |
| 291.4 | GIF search respects limit parameter | GET `?q=test&limit=5`; 200; array length <= 5 |
| 291.5 | GIF search is deterministic for same query | GET `?q=happy` twice; results identical |

### 10.4 Section 292: Sticker Collection API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 292.1 | List sticker collections returns active collections | GET `/ui/stickers/collections`; 200; includes test collection |
| 292.2 | Get stickers in collection | GET `/ui/stickers/collections/{id}/stickers`; 200; array with sticker entries having `sticker_id`, `image_url`, `alt_text` |
| 292.3 | Add collection to favorites | POST `/ui/stickers/favorites/{id}`; 200 |
| 292.4 | List favorites includes added collection | GET `/ui/stickers/favorites`; 200; includes test collection |
| 292.5 | Remove from favorites | DELETE `/ui/stickers/favorites/{id}`; 200; re-list; not included |
| 292.6 | Add favorite is idempotent | POST `/ui/stickers/favorites/{id}` again; 200; no error |

### 10.5 Section 293: GIF Message Send/Receive API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 293.1 | Alice sends a GIF message | POST `/conversations/{id}/messages/gif`; 201; `kind=gif`, `gif_url` set |
| 293.2 | GIF message appears in conversation messages | GET messages; find message with `kind=gif`; has `gif_alt_text` |
| 293.3 | Bob receives GIF message with correct fields | Bob GET messages; GIF message visible with `gif_url`, `gif_width`, `gif_height` |
| 293.4 | GIF message supports reply_to | POST GIF with `reply_to_message_id`; 201; `reply_to_message_id` set |
| 293.5 | GIF message appears in conversation last_message | GET conversations; last message has `kind=gif` |
| 293.6 | GIF message with missing optional fields uses defaults | POST with only `gif_url`; 201; `gif_width=0`, `gif_height=0`, `gif_alt_text=""` |

### 10.6 Section 294: Sticker Message Send/Receive API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 294.1 | Alice sends a sticker message | POST `/conversations/{id}/messages/sticker`; 201; `kind=sticker`, `sticker_id` set |
| 294.2 | Sticker message has correct collection and URL | Response has `sticker_collection_id`, `sticker_url` populated from DDB |
| 294.3 | Bob receives sticker message | Bob GET messages; sticker message visible with `sticker_url`, `sticker_alt_text` |
| 294.4 | Invalid sticker_id returns 404 | POST with nonexistent sticker_id; 404 |
| 294.5 | Invalid collection_id returns 404 | POST with nonexistent collection_id; 404 |

### 10.7 Section 295: Admin Sticker Management API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 295.1 | Admin creates sticker collection | POST `/v1/admin/stickers/collections` with files; 201; collection_id + sticker_count returned |
| 295.2 | Non-admin cannot create collection | Alice POST; 403 |
| 295.3 | Admin soft-deletes collection | DELETE `/v1/admin/stickers/collections/{id}`; 200; collection not in active list |
| 295.4 | Deleted collection stickers no longer sendable | POST sticker message with deleted collection sticker; 404 |

### 10.8 Section 296: GIF & Sticker UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 296.1 | GIF picker opens from ComposeBar button | Click GIF button; `[data-testid="gif-picker"]` visible; search input present |
| 296.2 | Searching GIFs shows results in picker | Type "happy"; GIF images appear in grid |
| 296.3 | Sticker picker opens from ComposeBar button | Click sticker button; `[data-testid="sticker-picker"]` visible |
| 296.4 | GIF message renders as animated image in message bubble | Navigate to conversation; GIF message shows `<img>` with correct src |

---

## 11. Security Considerations

- GIF URLs are validated to be from allowed domains (mock provider in dev, configured domains in prod)
- Sticker images are uploaded to platform S3 — no external hotlinking
- Alt text is HTML-escaped by React JSX
- Admin endpoints require `require_admin_session` auth
- Rate limiting on GIF search: 30 requests/minute per user
- Sticker file uploads validated for MIME type (PNG, WebP, SVG only) and size (512KB max)
- GIF provider responses are sanitized — only `id`, `url`, `alt_text`, `width`, `height` fields passed through
- S3 sticker URLs served through `/mock/s3/` prefix in dev (no direct S3 bucket access)

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker patterns | MSG-006 | Required (ComposeBar integration pattern) |
| Admin session auth | Existing | Available |
| S3 mock (moto) | Existing | Available |
| Billing table (favorites) | Existing | Available |
