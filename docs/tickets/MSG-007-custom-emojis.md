# MSG-007: Custom Emojis

**Ticket**: MSG-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Depends on**: MSG-006 (Emoji Messages — EmojiPicker component)

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-007 adds support for user-uploaded and admin-managed custom emoji images. Users can upload personal emojis visible only to themselves, and admins can upload global emoji sets available to all users on the platform. Custom emojis integrate into the existing EmojiPicker (MSG-006) under a "Custom" tab and work in both messages and reactions.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to upload a custom emoji image with a unique shortcode so I can express myself with personalized imagery. | Upload PNG/GIF (max 256KB, max 128x128px); assign shortcode; emoji appears in EmojiPicker "Custom" tab. |
| User | As a user, I want to use custom emojis in message text via shortcodes (`:my_cat:`) | Shortcode triggers custom emoji rendering inline. |
| User | As a user, I want to use custom emojis as message reactions. | Custom emoji appears in reaction picker; reaction displays custom image. |
| User | As a user, I want my personal emojis to be private — only I can see and use them. | Personal emojis scoped to `owner_scope = user_sub`; other users see fallback text. |
| Admin | As an admin, I want to upload global custom emojis available to all users. | Admin uploads via `/v1/admin/emojis`; emojis have `owner_scope = "GLOBAL"`. |
| Admin | As an admin, I want to organize global emojis into categories. | `category` field on emoji record; EmojiPicker groups by category. |
| Admin | As an admin, I want to delete inappropriate custom emojis. | DELETE endpoint removes emoji; existing usages show fallback text. |

### 1.3 Why This Is Needed Now

Custom emojis are a differentiating feature in messaging platforms. They drive engagement and community identity (see Discord, Slack, Twitch). With the EmojiPicker foundation from MSG-006 in place, adding custom emoji support is a natural extension that leverages the existing UI patterns and emoji infrastructure.

---

## 2. Current State Analysis

### 2.1 EmojiPicker (MSG-006)

The `EmojiPicker` component (`frontend/src/components/shared/EmojiPicker.tsx`) renders a categorized grid of Unicode emojis with search, recent history, and skin tone support. It accepts an `onSelect` callback. Custom emojis will be added as an additional "Custom" tab in the category sidebar.

### 2.2 S3 File Storage

The platform uses S3 (mocked via moto in dev) for file storage. Custom emoji images will be uploaded to a dedicated S3 prefix: `emojis/{scope}/{emoji_id}.{ext}`. The upload follows the same pattern as watermark uploads in `app/services/watermark_store.py` — direct file upload via multipart form data.

### 2.3 Image Processing

No server-side image resizing exists in the codebase. Custom emoji validation will enforce maximum dimensions (128x128px) and file size (256KB) at upload time. The frontend can use `<canvas>` for client-side validation of dimensions before uploading.

### 2.4 Reactions System

Reactions are stored as a map on the message record: `reactions: { "😀": { "user_sub_1": True } }`. For custom emojis, the reaction key will be the shortcode prefixed with `custom:` to distinguish from Unicode emojis: `reactions: { "custom:my_cat": { "user_sub_1": True } }`.

### 2.5 Gaps

1. **No `custom_emojis` DynamoDB table** — no storage for custom emoji metadata.
2. **No upload endpoint** — no way to upload emoji images.
3. **No custom emoji resolution** — message rendering doesn't know how to resolve custom shortcodes to images.
4. **No admin emoji management** — no bulk upload or global scope management.
5. **No custom emoji in EmojiPicker** — no "Custom" tab.
6. **No custom emoji in reactions** — reaction picker only shows Unicode emojis.

---

## 3. Technical Design

### 3.1 DynamoDB Table

**Table**: `custom_emojis`

| Attribute | Type | Description |
|-----------|------|-------------|
| `owner_scope` (PK) | String | `USER#{user_sub}` for personal, `"GLOBAL"` for admin-managed |
| `emoji_sk` (SK) | String | `EMOJI#{emoji_id}` |
| `emoji_id` | String | `ce_<uuid4_hex>` |
| `shortcode` | String | Unique per scope (e.g., `my_cat`), 2-32 chars, alphanumeric + underscores |
| `name` | String | Display name (e.g., "My Cat") |
| `image_url` | String | S3 URL for the emoji image |
| `alt_text` | String | Accessibility alt text |
| `category` | String | Optional grouping (e.g., "Pets", "Memes"); default "Uncategorized" |
| `created_by` | String | User sub of the uploader |
| `created_at` | Number | Unix timestamp |
| `content_type` | String | MIME type (`image/png` or `image/gif`) |
| `file_size_bytes` | Number | Original file size |

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `GSI1` | `owner_scope` | `shortcode` | Uniqueness check: lookup by scope + shortcode |
| `GSI2` | `created_by` | `created_at` | List all emojis created by a user (across scopes) |

**File**: `scripts/local-ddb-init.py` — Add `TableDef`:

```python
TableDef(
    name=S.ddb_custom_emojis_table,
    pk="owner_scope",
    sk="emoji_sk",
    gsis=[
        GsiDef(name="GSI1", pk="owner_scope", sk="shortcode"),
        GsiDef(name="GSI2", pk="created_by", sk="created_at"),
    ],
    attr_types={"created_at": "N", "file_size_bytes": "N"},
),
```

### 3.2 Settings

**File**: `app/core/settings.py`

```python
# Custom emojis (MSG-007)
ddb_custom_emojis_table: str = os.environ.get("DDB_CUSTOM_EMOJIS_TABLE", "custom_emojis")
custom_emoji_max_file_size_bytes: int = int(os.environ.get("CUSTOM_EMOJI_MAX_FILE_SIZE", "262144"))  # 256KB
custom_emoji_max_dimension_px: int = int(os.environ.get("CUSTOM_EMOJI_MAX_DIMENSION", "128"))
custom_emoji_max_per_user: int = int(os.environ.get("CUSTOM_EMOJI_MAX_PER_USER", "100"))
custom_emoji_s3_prefix: str = os.environ.get("CUSTOM_EMOJI_S3_PREFIX", "emojis")
```

### 3.3 Backend Service

**File**: `app/services/custom_emojis.py`

```python
def create_custom_emoji(
    *,
    owner_scope: str,
    shortcode: str,
    name: str,
    alt_text: str,
    category: str,
    created_by: str,
    image_file: UploadFile,
) -> dict:
    """Upload emoji image to S3 and create DDB record."""
    # 1. Validate file: size, content_type (PNG/GIF), dimensions (PIL.Image)
    # 2. Check shortcode uniqueness within scope (GSI1 query)
    # 3. Check per-user limit (GSI2 query count)
    # 4. Generate emoji_id = f"ce_{uuid4().hex}"
    # 5. Upload to S3: emojis/{scope}/{emoji_id}.{ext}
    # 6. Write DDB record
    # 7. Return emoji dict

def list_custom_emojis(owner_scope: str) -> list[dict]:
    """List all custom emojis for a scope."""
    # Query PK=owner_scope, return all items

def get_custom_emoji(owner_scope: str, emoji_id: str) -> dict | None:
    """Get a single custom emoji."""
    # GetItem PK=owner_scope, SK=EMOJI#{emoji_id}

def delete_custom_emoji(owner_scope: str, emoji_id: str) -> bool:
    """Delete a custom emoji and its S3 object."""
    # 1. GetItem to find image_url
    # 2. Delete S3 object
    # 3. Delete DDB record

def resolve_custom_shortcodes(user_sub: str, shortcodes: list[str]) -> dict[str, str]:
    """Resolve shortcodes to image URLs, checking personal then global scope."""
    # 1. Batch query USER#{user_sub} for all shortcodes
    # 2. For unresolved: batch query GLOBAL
    # 3. Return {shortcode: image_url} map
```

### 3.4 Backend Router

**File**: `app/routers/custom_emojis.py`

```python
router = APIRouter(prefix="/ui/emojis/custom", tags=["custom-emojis"])

@router.post("", status_code=201)
async def upload_custom_emoji(
    shortcode: str = Form(...),
    name: str = Form(...),
    alt_text: str = Form(default=""),
    category: str = Form(default="Uncategorized"),
    file: UploadFile = File(...),
    ctx=Depends(require_ui_session),
):
    """Upload a personal custom emoji."""

@router.get("")
def list_my_custom_emojis(ctx=Depends(require_ui_session)):
    """List all custom emojis visible to the caller (personal + global)."""

@router.delete("/{emoji_id}")
def delete_my_custom_emoji(emoji_id: str, ctx=Depends(require_ui_session)):
    """Delete a personal custom emoji."""

@router.get("/resolve")
def resolve_shortcodes(
    codes: str = Query(..., description="Comma-separated shortcodes"),
    ctx=Depends(require_ui_session),
):
    """Resolve custom shortcodes to image URLs."""
```

**Admin router** (`app/routers/custom_emojis.py`):

```python
admin_router = APIRouter(prefix="/v1/admin/emojis", tags=["admin-emojis"])

@admin_router.post("", status_code=201)
async def upload_global_emoji(
    shortcode: str = Form(...),
    name: str = Form(...),
    alt_text: str = Form(default=""),
    category: str = Form(default="Uncategorized"),
    file: UploadFile = File(...),
    ctx=Depends(require_admin_session),
):
    """Upload a global custom emoji (admin only)."""

@admin_router.get("")
def list_global_emojis(ctx=Depends(require_admin_session)):
    """List all global custom emojis."""

@admin_router.delete("/{emoji_id}")
def delete_global_emoji(emoji_id: str, ctx=Depends(require_admin_session)):
    """Delete a global custom emoji (admin only)."""
```

### 3.5 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface CustomEmoji {
  emoji_id: string;
  shortcode: string;
  name: string;
  image_url: string;
  alt_text: string;
  category: string;
  owner_scope: string;
  created_by: string;
  created_at: number;
}
```

### 3.6 Frontend API

**File**: `frontend/src/api/endpoints/emojis.ts`

```typescript
export const uploadCustomEmoji = (data: FormData) =>
  api.post<CustomEmoji>("/ui/emojis/custom", data);

export const listMyCustomEmojis = () =>
  api.get<CustomEmoji[]>("/ui/emojis/custom");

export const deleteCustomEmoji = (emojiId: string) =>
  api.delete(`/ui/emojis/custom/${emojiId}`);

export const resolveCustomShortcodes = (codes: string[]) =>
  api.get<Record<string, string>>("/ui/emojis/custom/resolve", {
    params: { codes: codes.join(",") },
  });
```

### 3.7 EmojiPicker Integration

Add a "Custom" tab to the EmojiPicker after the standard categories:

```tsx
// In EmojiPicker.tsx
const { data: customEmojis } = useQuery({
  queryKey: ["custom-emojis"],
  queryFn: listMyCustomEmojis,
  staleTime: 5 * 60 * 1000,
});

// Add "Custom" tab with upload button
// Render custom emojis as <img> elements instead of text
// Custom emoji selection calls onSelect(`:${shortcode}:`)
```

### 3.8 MessageBubble Custom Emoji Rendering

Custom shortcodes in message text (`:my_cat:`) are rendered as inline `<img>` elements:

```tsx
function renderMessageText(text: string, customEmojiMap: Record<string, string>) {
  // Split text on :shortcode: patterns
  // For each shortcode, check customEmojiMap for image_url
  // Render as <img src={url} alt={shortcode} className="inline h-5 w-5" />
  // Unresolved shortcodes stay as text
}
```

The `customEmojiMap` is fetched via `resolveCustomShortcodes` when a message contains `:...:` patterns.

### 3.9 Reactions with Custom Emojis

In the reaction picker (currently shows Unicode emojis), add a "Custom" section:

```tsx
// Reaction key format for custom emojis: "custom:shortcode"
// Rendering: check if reaction key starts with "custom:"
//   → fetch image_url via resolveCustomShortcodes
//   → render <img> instead of text
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/custom_emojis.py` | Custom emoji business logic + DDB access |
| `app/routers/custom_emojis.py` | REST endpoints (user + admin) |
| `frontend/src/api/endpoints/emojis.ts` | API client functions |
| `frontend/src/pages/settings/CustomEmojisPage.tsx` | Management page for personal emojis |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `custom_emojis` TableDef |
| `app/core/settings.py` | Add custom emoji settings |
| `app/core/tables.py` | Add `T.custom_emojis` table handle |
| `app/main.py` | Register custom emoji routers |
| `frontend/src/api/types.ts` | Add `CustomEmoji` interface |
| `frontend/src/components/shared/EmojiPicker.tsx` | Add "Custom" tab, upload button |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render custom emoji images inline |
| `frontend/src/App.tsx` | Add route for CustomEmojisPage |

### 4.3 Step-by-Step Order

1. Add DDB table definition and settings
2. Implement `custom_emojis.py` service (CRUD + S3 upload + shortcode resolution)
3. Implement `custom_emojis.py` router (user + admin endpoints)
4. Register routers in `main.py`
5. Add frontend types and API client
6. Extend EmojiPicker with "Custom" tab and upload flow
7. Implement custom emoji rendering in MessageBubble
8. Implement custom emoji in reaction picker
9. Build CustomEmojisPage for management
10. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/custom-emojis.spec.ts` — 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let adminPage: Page;
let aliceEmojiId: string;
let globalEmojiId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (USER) and Charlie (ADMIN) sessions
  // Prepare a 64x64 PNG test image buffer for upload
});
```

### 5.3 Section 287: Personal Custom Emoji CRUD API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 287.1 | Upload a personal custom emoji with valid PNG | POST `/ui/emojis/custom` multipart; 201; response has `emoji_id`, `shortcode`, `image_url` |
| 287.2 | Reject upload with duplicate shortcode in same scope | POST with same shortcode; 409; detail contains "shortcode already exists" |
| 287.3 | Reject upload with file > 256KB | POST with oversized file; 400; detail contains "file too large" |
| 287.4 | Reject upload with invalid content type (JPEG) | POST with JPEG; 400; detail contains "PNG or GIF" |
| 287.5 | List personal custom emojis | GET `/ui/emojis/custom`; 200; array includes uploaded emoji |
| 287.6 | Delete personal custom emoji | DELETE `/ui/emojis/custom/{id}`; 200; subsequent GET does not include deleted emoji |

### 5.4 Section 288: Global Custom Emoji Admin API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 288.1 | Admin uploads a global custom emoji | POST `/v1/admin/emojis` multipart; 201; `owner_scope` is "GLOBAL" |
| 288.2 | Non-admin cannot upload global emoji | POST as Alice; 403 |
| 288.3 | Global emoji appears in user's custom emoji list | Alice GET `/ui/emojis/custom`; response includes global emoji |
| 288.4 | Admin deletes global emoji | DELETE `/v1/admin/emojis/{id}`; 200; no longer in listings |

### 5.5 Section 289: Custom Emoji in Messages (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 289.1 | Custom emoji shortcode resolves to image URL | GET `/ui/emojis/custom/resolve?codes=my_test_emoji`; returns `{ shortcode: image_url }` |
| 289.2 | Message with custom emoji shortcode stores text as-is | POST message with `:my_test_emoji:`; message text contains `:my_test_emoji:` |
| 289.3 | Personal emoji not resolvable by other user | Bob resolves Alice's personal shortcode; returns empty map for that code |
| 289.4 | Global emoji resolvable by any user | Bob resolves global shortcode; returns image_url |
| 289.5 | Custom emoji in reaction is stored with `custom:` prefix | POST reaction with `custom:my_test_emoji`; reaction key stored correctly |

### 5.6 Section 290: Custom Emoji UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 290.1 | EmojiPicker shows "Custom" tab | Open picker; "Custom" tab visible |
| 290.2 | Custom tab displays uploaded emoji | Click "Custom" tab; emoji image visible with shortcode label |
| 290.3 | Clicking custom emoji inserts shortcode into compose | Click custom emoji; compose input contains `:shortcode:` |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| File exceeds 256KB | 400 | "File size exceeds maximum of 256KB" |
| Invalid MIME type | 400 | "Only PNG and GIF images are allowed" |
| Duplicate shortcode in scope | 409 | "Shortcode already exists in this scope" |
| User exceeds emoji limit (100) | 400 | "Maximum custom emoji limit reached" |
| Shortcode contains invalid characters | 422 | "Shortcode must be 2-32 alphanumeric characters or underscores" |
| Delete non-existent emoji | 404 | "Custom emoji not found" |
| Non-owner tries to delete personal emoji | 403 | "Forbidden" |

---

## 7. Security Considerations

### 7.1 File Upload Validation

- Server-side MIME type check via magic bytes (not just Content-Type header)
- Maximum file size enforced at both FastAPI `UploadFile` and service layer
- Image dimensions validated via PIL/Pillow `Image.open().size`
- S3 objects stored with `Content-Disposition: inline` to prevent download prompts

### 7.2 Shortcode Injection

- Shortcodes restricted to `[a-z0-9_]` pattern, 2-32 characters
- Rendered as `<img>` with `src` from trusted S3 URL — no XSS vector
- Alt text is HTML-escaped by React JSX
- Custom shortcodes cannot shadow built-in Unicode emoji shortcodes (validated at upload)

### 7.3 Access Control

- Personal emojis: only creator can upload, list, delete, and use
- Global emojis: only admin can upload/delete; all users can view and use
- Image URLs are S3 pre-signed or public (via mock in dev) — no additional auth needed for rendering

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker component | MSG-006 | Required (provides UI foundation) |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| MSG-011 (Emoji Reactions Enhancement) | Custom emoji in reaction picker |
| FEED-004 (Emoji/GIF/Sticker Comments) | Custom emoji in comment composer |
