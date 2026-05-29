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

## 3. Technical Design

### 3.1 DynamoDB Table: `sticker_collections`

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

### 3.2 Message Schema Extension

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

### 3.3 Mock GIF Provider

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

### 3.4 Backend Service

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

### 3.5 Backend Router

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

### 3.6 Messaging Endpoints for GIF/Sticker Send

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

### 3.7 Frontend Components

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

### 3.8 Settings

```python
# GIF & Sticker messages (MSG-008)
ddb_sticker_collections_table: str = os.environ.get("DDB_STICKER_COLLECTIONS_TABLE", "sticker_collections")
gif_provider: str = os.environ.get("GIF_PROVIDER", "mock")  # "mock", "tenor", "giphy"
sticker_max_file_size_bytes: int = int(os.environ.get("STICKER_MAX_FILE_SIZE", "524288"))  # 512KB
sticker_max_per_collection: int = int(os.environ.get("STICKER_MAX_PER_COLLECTION", "100"))
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/gif_provider.py` | Mock GIF search provider |
| `app/services/sticker_collections.py` | Sticker collection CRUD + S3 upload |
| `app/routers/sticker_collections.py` | Sticker + GIF REST endpoints |
| `frontend/src/components/shared/GifPicker.tsx` | GIF search and select component |
| `frontend/src/components/shared/StickerPicker.tsx` | Sticker browsing component |
| `frontend/src/api/endpoints/stickers.ts` | API client for stickers + GIFs |
| `app/static/mock/gifs/` | Directory with placeholder animated GIF files |

### 4.2 Files to Modify

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

### 4.3 Step-by-Step Order

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

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/gif-sticker-messages.spec.ts` — 22 tests across 5 sections.

### 5.2 Test Setup

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

### 5.3 Section 291: GIF Search API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 291.1 | Trending GIFs returns results | GET `/ui/stickers/gifs/trending`; 200; array length > 0; each has `url`, `alt_text` |
| 291.2 | GIF search returns filtered results | GET `/ui/stickers/gifs/search?q=happy`; 200; results non-empty |
| 291.3 | GIF search with empty query returns trending | GET `/ui/stickers/gifs/search?q=`; 200; same as trending |
| 291.4 | GIF search respects limit parameter | GET `?q=test&limit=5`; 200; array length <= 5 |

### 5.4 Section 292: Sticker Collection API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 292.1 | List sticker collections returns active collections | GET `/ui/stickers/collections`; 200; includes test collection |
| 292.2 | Get stickers in collection | GET `/ui/stickers/collections/{id}/stickers`; 200; array with sticker entries |
| 292.3 | Add collection to favorites | POST `/ui/stickers/favorites/{id}`; 200 |
| 292.4 | List favorites includes added collection | GET `/ui/stickers/favorites`; 200; includes test collection |
| 292.5 | Remove from favorites | DELETE `/ui/stickers/favorites/{id}`; 200; re-list; not included |

### 5.5 Section 293: GIF Message Send/Receive API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 293.1 | Alice sends a GIF message | POST `/conversations/{id}/messages/gif`; 201; `kind=gif`, `gif_url` set |
| 293.2 | GIF message appears in conversation messages | GET messages; find message with `kind=gif`; has `gif_alt_text` |
| 293.3 | Bob receives GIF message with correct fields | Bob GET messages; GIF message visible with `gif_url`, `gif_width`, `gif_height` |
| 293.4 | GIF message supports reply_to | POST GIF with `reply_to_message_id`; 201; `reply_to_message_id` set |
| 293.5 | GIF message appears in conversation last_message | GET conversations; last message has `kind=gif` |

### 5.6 Section 294: Sticker Message Send/Receive API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 294.1 | Alice sends a sticker message | POST `/conversations/{id}/messages/sticker`; 201; `kind=sticker`, `sticker_id` set |
| 294.2 | Sticker message has correct collection and URL | Response has `sticker_collection_id`, `sticker_url` |
| 294.3 | Bob receives sticker message | Bob GET messages; sticker message visible with `sticker_url`, `sticker_alt_text` |
| 294.4 | Invalid sticker_id returns 404 | POST with nonexistent sticker_id; 404 |

### 5.7 Section 295: GIF & Sticker UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 295.1 | GIF picker opens from ComposeBar button | Click GIF button; `[data-testid="gif-picker"]` visible; search input present |
| 295.2 | Searching GIFs shows results in picker | Type "happy"; GIF images appear in grid |
| 295.3 | Sticker picker opens from ComposeBar button | Click sticker button; `[data-testid="sticker-picker"]` visible |
| 295.4 | GIF message renders as animated image in message bubble | Navigate to conversation; GIF message shows `<img>` with correct src |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| GIF URL exceeds max length | 422 | Pydantic validation error |
| Sticker not found in collection | 404 | "Sticker not found" |
| Collection not found | 404 | "Sticker collection not found" |
| Non-admin creating collection | 403 | "Forbidden" |
| Sticker file exceeds 512KB | 400 | "File too large" |
| Sticker collection at max capacity | 400 | "Collection has reached maximum sticker count" |

---

## 7. Security Considerations

- GIF URLs are validated to be from allowed domains (mock provider in dev, configured domains in prod)
- Sticker images are uploaded to platform S3 — no external hotlinking
- Alt text is HTML-escaped by React JSX
- Admin endpoints require `require_admin_session` auth
- Rate limiting on GIF search: 30 requests/minute per user

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker patterns | MSG-006 | Required (ComposeBar integration pattern) |
| Admin session auth | Existing | Available |
