# FEED-004: Emoji/GIF/Sticker Comments

**Ticket**: FEED-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 4-5 days
**Depends on**: MSG-006 (EmojiPicker), MSG-008 (GifPicker, StickerPicker)

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-004 extends newsfeed post comments to support emoji-only, GIF, and sticker content. Currently, comments on posts are text-only. This ticket adds a `kind` field to comments and enables the EmojiPicker, GifPicker, and StickerPicker components (built in MSG-006 and MSG-008) in the comment composer. Emoji-only comments render at 3x size, matching the message bubble behavior from MSG-006.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Commenter | As a user, I want to reply to a post with a GIF. | GIF picker in comment composer; GIF comment renders as animated image. |
| Commenter | As a user, I want to reply with a sticker. | Sticker picker in comment composer; sticker renders at fixed size. |
| Commenter | As a user, I want to use the emoji picker when writing a comment. | Emoji button in comment input; opens EmojiPicker; inserts emoji into text. |
| Commenter | As a user, I want single-emoji comments to render large. | Comment with just "..." renders at 3x size. |
| Viewer | As a viewer, I want to see GIF and sticker comments properly rendered in the comment thread. | GIF animates; sticker displays at standard size; alt text for accessibility. |
| Creator | As a post creator, I want to tip GIF/sticker comments the same way I tip text comments. | Tip button available on all comment kinds. |

### 1.3 Why This Is Needed Now

With EmojiPicker, GifPicker, and StickerPicker already built for messaging (MSG-006, MSG-008), extending them to comments is straightforward. GIF and sticker comments are standard in social platforms (Instagram, Facebook, Twitter/X) and significantly increase comment engagement.

---

## 2. Current State Analysis

### 2.1 Comment Model

Comments are created via `POST /posts/{post_id}/comments` in `app/routers/newsfeed.py` (line 4556). The current `CreateCommentRequest` model (line 1432) extends `ContentFieldsMixin`:
<!-- VERIFIED: app/routers/newsfeed.py:1432 — CreateCommentRequest(ContentFieldsMixin); :4556 — create_comment -->

```python
# NOTE: Actual model uses ContentFieldsMixin, not plain text field
class CreateCommentRequest(ContentFieldsMixin):
    parent_comment_id: Optional[str] = None
```

Comments are stored in DDB with fields: `comment_id`, `post_id`, `user_id`, `text`, `parent_comment_id`, `created_at`, `tip_total_cents`.

### 2.2 Comment Rendering

`frontend/src/pages/feed/CommentsThread.tsx` renders comments as plain text in `<p>` tags.
<!-- VERIFIED: frontend/src/pages/feed/CommentsThread.tsx exists -->
<!-- NOTE: frontend/src/pages/feed/CommentRow.tsx does NOT exist as a separate file — comment rendering is inline in CommentsThread.tsx -->

### 2.3 Available Picker Components

<!-- NOTE: ALL THREE picker components do NOT exist yet — MSG-006 and MSG-008 have not been implemented. These are blocking dependencies. -->
- `EmojiPicker` (MSG-006): `frontend/src/components/shared/EmojiPicker.tsx` — **does not exist yet**
- `GifPicker` (MSG-008): `frontend/src/components/shared/GifPicker.tsx` — **does not exist yet**
- `StickerPicker` (MSG-008): `frontend/src/components/shared/StickerPicker.tsx` — **does not exist yet**

### 2.4 Gaps

1. **No `kind` field on comments** — all comments are implicitly text.
2. **No GIF/sticker fields on comments** — no `gif_url`, `sticker_id` etc.
3. **No media pickers in comment composer** — only a text input exists.
4. **No emoji-only large rendering for comments** — no detection of emoji-only content.
5. **No GIF/sticker rendering in CommentRow** — only text displayed.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
                    Comment Creation Flow (GIF Example)
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ CommentComposer│────>│ POST /posts/{id}/  │────>│  DynamoDB     │
  │  (frontend)    │     │   comments         │     │  app_single   │
  │                │     │  (newsfeed.py)      │     │  _table       │
  │  kind="gif"    │     │                    │     │               │
  │  gif_url=...   │     │  validate kind +   │     │  PK=POST#id   │
  │  gif_alt=...   │     │  media fields      │     │  SK=CMT#cmt_id│
  └───────────────┘     └────────────────────┘     └──────────────┘
                                                          │
                                                          v
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │  CommentRow    │<────│ GET /posts/{id}/   │<────│  Query by     │
  │  (frontend)    │     │   comments         │     │  PK=POST#id   │
  │                │     │  (newsfeed.py)      │     │  SK begins    │
  │  renders GIF   │     │                    │     │  "CMT#"       │
  │  <img> tag     │     │  _comment_to_dict  │     │               │
  │  + alt text    │     │  includes media    │     │               │
  └───────────────┘     └────────────────────┘     └──────────────┘
```

### 3.2 Comment Model Extension

**File**: `app/routers/newsfeed.py`

Extend `CreateCommentRequest`:

```python
class CreateCommentRequest(BaseModel):
    kind: str = Field(default="text", pattern=r"^(text|gif|sticker)$")
    text: Optional[str] = Field(default=None, max_length=5000)
    parent_comment_id: Optional[str] = None
    # GIF fields (required when kind=gif)
    gif_url: Optional[str] = Field(default=None, max_length=2048)
    gif_alt_text: Optional[str] = Field(default=None, max_length=256)
    gif_width: Optional[int] = Field(default=None, ge=0)
    gif_height: Optional[int] = Field(default=None, ge=0)
    # Sticker fields (required when kind=sticker)
    sticker_id: Optional[str] = Field(default=None, max_length=64)
    sticker_collection_id: Optional[str] = Field(default=None, max_length=64)
    sticker_url: Optional[str] = Field(default=None, max_length=2048)
    sticker_alt_text: Optional[str] = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def validate_kind_fields(self):
        if self.kind == "text" and not self.text:
            raise ValueError("text is required for text comments")
        if self.kind == "gif" and not self.gif_url:
            raise ValueError("gif_url is required for gif comments")
        if self.kind == "sticker" and not self.sticker_id:
            raise ValueError("sticker_id is required for sticker comments")
        return self
```

### 3.3 Detailed DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Create comment (any kind) | `app_single_table` | PK=`POST#{post_id}`, SK=`CMT#{comment_id}` | -- | Write new comment with kind + media fields |
| List comments on post | `app_single_table` | PK=`POST#{post_id}`, SK `begins_with("CMT#")` | -- | Fetch all comments for rendering in thread |
| List threaded replies | `app_single_table` | PK=`POST#{post_id}`, SK `begins_with("CMT#")` | `parent_comment_id = :parent` | Fetch replies to a specific comment |
| Tip a comment | `app_single_table` | PK=`POST#{post_id}`, SK=`CMT#{comment_id}` | -- | Update `tip_total_cents` via atomic ADD |
| Count comments by kind | `app_single_table` | PK=`POST#{post_id}`, SK `begins_with("CMT#")` | `kind = :kind` | Analytics: count GIF vs text vs sticker comments |

### 3.4 Comment DDB Item Extension

Add fields to comment item:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | String | `"text"`, `"gif"`, `"sticker"` (default `"text"`) |
| `gif_url` | String | GIF image URL (for `kind=gif`) |
| `gif_alt_text` | String | GIF accessibility text |
| `gif_width` | Number | GIF width in pixels |
| `gif_height` | Number | GIF height in pixels |
| `sticker_id` | String | Sticker ID (for `kind=sticker`) |
| `sticker_collection_id` | String | Collection the sticker belongs to |
| `sticker_url` | String | Sticker image URL |
| `sticker_alt_text` | String | Sticker accessibility text |

### 3.5 Comment Response Extension

Add media fields to the comment response dict in `_comment_to_dict()`:

```python
def _comment_to_dict(item: dict) -> dict:
    return {
        # ... existing fields ...
        "kind": item.get("kind", "text"),
        "gif_url": item.get("gif_url"),
        "gif_alt_text": item.get("gif_alt_text"),
        "gif_width": item.get("gif_width"),
        "gif_height": item.get("gif_height"),
        "sticker_id": item.get("sticker_id"),
        "sticker_collection_id": item.get("sticker_collection_id"),
        "sticker_url": item.get("sticker_url"),
        "sticker_alt_text": item.get("sticker_alt_text"),
    }
```

### 3.6 API Request/Response Examples

**Create GIF comment**:

```
POST /ui/posts/p_abc123/comments
Content-Type: application/json
x-csrf-token: <csrf>

{
  "kind": "gif",
  "gif_url": "https://media.giphy.com/media/3o7TKU8RvQuomFfUUU/giphy.gif",
  "gif_alt_text": "Happy dance celebration",
  "gif_width": 480,
  "gif_height": 270,
  "parent_comment_id": null
}
```

**Response (201)**:
```json
{
  "comment_id": "cmt_7a8b9c0d1e2f",
  "post_id": "p_abc123",
  "user_id": "alice@test.local",
  "user_name": "Alice",
  "kind": "gif",
  "text": null,
  "gif_url": "https://media.giphy.com/media/3o7TKU8RvQuomFfUUU/giphy.gif",
  "gif_alt_text": "Happy dance celebration",
  "gif_width": 480,
  "gif_height": 270,
  "sticker_id": null,
  "sticker_collection_id": null,
  "sticker_url": null,
  "sticker_alt_text": null,
  "parent_comment_id": null,
  "created_at": 1748520100,
  "tip_total_cents": 0
}
```

**Create sticker comment**:

```
POST /ui/posts/p_abc123/comments
Content-Type: application/json
x-csrf-token: <csrf>

{
  "kind": "sticker",
  "sticker_id": "stk_love_heart_01",
  "sticker_collection_id": "coll_love_pack",
  "sticker_url": "/mock/s3/stickers/coll_love_pack/stk_love_heart_01.webp",
  "sticker_alt_text": "Love heart sticker"
}
```

**Response (201)**:
```json
{
  "comment_id": "cmt_d4e5f6a7b8c9",
  "post_id": "p_abc123",
  "user_id": "bob@test.local",
  "user_name": "Bob",
  "kind": "sticker",
  "text": null,
  "gif_url": null,
  "gif_alt_text": null,
  "gif_width": null,
  "gif_height": null,
  "sticker_id": "stk_love_heart_01",
  "sticker_collection_id": "coll_love_pack",
  "sticker_url": "/mock/s3/stickers/coll_love_pack/stk_love_heart_01.webp",
  "sticker_alt_text": "Love heart sticker",
  "parent_comment_id": null,
  "created_at": 1748520200,
  "tip_total_cents": 0
}
```

**Create emoji-only text comment**:

```
POST /ui/posts/p_abc123/comments
Content-Type: application/json
x-csrf-token: <csrf>

{
  "kind": "text",
  "text": "😀"
}
```

**Response (201)**:
```json
{
  "comment_id": "cmt_1a2b3c4d5e6f",
  "post_id": "p_abc123",
  "user_id": "alice@test.local",
  "user_name": "Alice",
  "kind": "text",
  "text": "😀",
  "gif_url": null,
  "sticker_id": null,
  "parent_comment_id": null,
  "created_at": 1748520300,
  "tip_total_cents": 0
}
```

**List comments with mixed kinds**:

```
GET /ui/posts/p_abc123/comments
```

**Response (200)**:
```json
{
  "comments": [
    {
      "comment_id": "cmt_1a2b3c4d5e6f",
      "kind": "text",
      "text": "😀",
      "created_at": 1748520300
    },
    {
      "comment_id": "cmt_d4e5f6a7b8c9",
      "kind": "sticker",
      "sticker_url": "/mock/s3/stickers/coll_love_pack/stk_love_heart_01.webp",
      "sticker_alt_text": "Love heart sticker",
      "created_at": 1748520200
    },
    {
      "comment_id": "cmt_7a8b9c0d1e2f",
      "kind": "gif",
      "gif_url": "https://media.giphy.com/media/3o7TKU8RvQuomFfUUU/giphy.gif",
      "gif_alt_text": "Happy dance celebration",
      "created_at": 1748520100
    }
  ]
}
```

### 3.7 Pydantic Model Definitions

```python
# In app/models.py

class CreateCommentIn(BaseModel):
    """Request model for creating a comment on a post."""
    kind: str = Field(
        default="text",
        pattern=r"^(text|gif|sticker)$",
        description="Comment content kind: text, gif, or sticker",
    )
    text: Optional[str] = Field(
        default=None,
        max_length=5000,
        description="Comment text (required for kind=text)",
    )
    parent_comment_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="ID of parent comment for threaded replies",
    )
    # GIF fields
    gif_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="GIF image URL (required for kind=gif)",
    )
    gif_alt_text: Optional[str] = Field(
        default=None,
        max_length=256,
        description="GIF accessibility text",
    )
    gif_width: Optional[int] = Field(default=None, ge=0, le=4096)
    gif_height: Optional[int] = Field(default=None, ge=0, le=4096)
    # Sticker fields
    sticker_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Sticker ID (required for kind=sticker)",
    )
    sticker_collection_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Collection the sticker belongs to",
    )
    sticker_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Sticker image URL",
    )
    sticker_alt_text: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Sticker accessibility text",
    )

    @model_validator(mode="after")
    def validate_kind_fields(self):
        if self.kind == "text" and not self.text:
            raise ValueError("text is required for text comments")
        if self.kind == "gif":
            if not self.gif_url:
                raise ValueError("gif_url is required for gif comments")
        if self.kind == "sticker":
            if not self.sticker_id:
                raise ValueError("sticker_id is required for sticker comments")
            if not self.sticker_url:
                raise ValueError("sticker_url is required for sticker comments")
        return self


class CommentOut(BaseModel):
    """Response model for a comment on a post."""
    comment_id: str
    post_id: str
    user_id: str
    user_name: Optional[str] = None
    kind: str = "text"
    text: Optional[str] = None
    parent_comment_id: Optional[str] = None
    created_at: int = 0
    tip_total_cents: int = 0
    # GIF fields
    gif_url: Optional[str] = None
    gif_alt_text: Optional[str] = None
    gif_width: Optional[int] = None
    gif_height: Optional[int] = None
    # Sticker fields
    sticker_id: Optional[str] = None
    sticker_collection_id: Optional[str] = None
    sticker_url: Optional[str] = None
    sticker_alt_text: Optional[str] = None
```

### 3.8 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface PostComment {
  comment_id: string;
  post_id: string;
  user_id: string;
  user_name?: string;
  text?: string | null;
  kind: "text" | "gif" | "sticker";
  parent_comment_id?: string | null;
  created_at: number;
  tip_total_cents?: number;
  // GIF fields
  gif_url?: string | null;
  gif_alt_text?: string | null;
  gif_width?: number | null;
  gif_height?: number | null;
  // Sticker fields
  sticker_id?: string | null;
  sticker_collection_id?: string | null;
  sticker_url?: string | null;
  sticker_alt_text?: string | null;
}
```

### 3.9 Frontend Component Tree

```
CommentsThread (modified)
├── CommentComposer (modified or extracted)
│   ├── TextInput (existing textarea)
│   ├── MediaToolbar (new)
│   │   ├── EmojiPickerButton
│   │   │   └── Popover → EmojiPicker (shared component)
│   │   ├── GifPickerButton
│   │   │   └── Dialog → GifPicker (shared component)
│   │   └── StickerPickerButton
│   │       └── Dialog → StickerPicker (shared component)
│   ├── MediaPreview (conditional, new)
│   │   ├── GifPreview (<img> with remove button)
│   │   └── StickerPreview (<img> with remove button)
│   └── SubmitButton
│
├── CommentRow (modified) — one per comment
│   ├── AuthorInfo (avatar, name, timestamp)
│   ├── CommentContent (modified, renders by kind)
│   │   ├── kind=text → <p> (3x size if emoji-only via isEmojiOnly())
│   │   ├── kind=gif → <img src={gif_url} alt={gif_alt_text}>
│   │   └── kind=sticker → <img src={sticker_url} alt={sticker_alt_text}>
│   ├── TipButton (unchanged — works for all kinds)
│   ├── ReplyButton (unchanged)
│   └── NestedReplies (recursive CommentRow for threaded replies)
```

### 3.10 Frontend Components

**CommentComposer enhancement** (in `CommentsThread.tsx` or extracted as `CommentComposer.tsx`):

```tsx
// Add toolbar buttons below comment text input:
<div className="flex items-center gap-1">
  <Popover>
    <PopoverTrigger asChild>
      <Button variant="ghost" size="icon" className="h-7 w-7">
        <Smile className="h-4 w-4" />
      </Button>
    </PopoverTrigger>
    <PopoverContent className="w-80 p-0">
      <EmojiPicker onSelect={handleEmojiInsert} />
    </PopoverContent>
  </Popover>
  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setGifPickerOpen(true)}>
    <span className="text-xs font-bold">GIF</span>
  </Button>
  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setStickerPickerOpen(true)}>
    <Sticker className="h-4 w-4" />
  </Button>
</div>
```

GIF/sticker selection replaces the comment text and submits immediately (one-click send).

**CommentRow enhancement** (`frontend/src/pages/feed/CommentRow.tsx`):

```tsx
// Text comment with emoji-only detection:
{comment.kind === "text" && comment.text && (
  <p className={cn(
    "text-sm",
    isEmojiOnly(comment.text) && "text-3xl leading-relaxed"
  )}>
    {comment.text}
  </p>
)}

// GIF comment:
{comment.kind === "gif" && comment.gif_url && (
  <img
    src={comment.gif_url}
    alt={comment.gif_alt_text || "GIF"}
    className="rounded max-w-[200px]"
    loading="lazy"
  />
)}

// Sticker comment:
{comment.kind === "sticker" && comment.sticker_url && (
  <img
    src={comment.sticker_url}
    alt={comment.sticker_alt_text || "Sticker"}
    className="w-20 h-20 object-contain"
  />
)}
```

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/newsfeed.py` | Extend `CreateCommentRequest` with `kind` and media fields; update `_comment_to_dict` |
| `app/models.py` | Add `CreateCommentIn`, `CommentOut` Pydantic models |
| `frontend/src/api/types.ts` | Extend `PostComment` interface |
| `frontend/src/pages/feed/CommentsThread.tsx` | Add emoji/GIF/sticker picker buttons to composer |
| `frontend/src/pages/feed/CommentRow.tsx` | Render GIF/sticker comments; emoji-only detection |
| `frontend/src/api/endpoints/newsfeed.ts` | Update `createComment` to accept media fields |

### 4.2 Step-by-Step Order

1. Extend `CreateCommentRequest` model with kind and media fields
2. Update comment creation logic to store new fields
3. Update `_comment_to_dict` to return media fields
4. Extend frontend `PostComment` type
5. Add picker buttons to comment composer
6. Add GIF/sticker/emoji rendering in CommentRow
7. Add emoji-only detection for large rendering
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-media-comments.spec.ts` — 24 tests across 6 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let alicePostId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Alice creates a text post for commenting
  // Admin seeds a sticker collection for sticker comments
});
```

### 5.3 Section 303: GIF/Sticker Comment API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 303.1 | Create GIF comment on post | POST `/posts/{id}/comments` with `kind=gif`, `gif_url`; 201; response has `kind=gif` |
| 303.2 | Create sticker comment on post | POST with `kind=sticker`, `sticker_id`, `sticker_url`; 201; `kind=sticker` |
| 303.3 | GIF comment appears in comment list | GET `/posts/{id}/comments`; find comment with `kind=gif`, `gif_url` set |
| 303.4 | Reject GIF comment without gif_url | POST `kind=gif` without `gif_url`; 422 |
| 303.5 | Reject sticker comment without sticker_id | POST `kind=sticker` without `sticker_id`; 422 |

### 5.4 Section 304: Text Comment with Emoji (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 304.1 | Create text comment with emoji shortcode | POST `kind=text`, `text=":fire:"`; 201 (shortcode stored as-is, rendered on frontend) |
| 304.2 | Text comment with emoji-only content stored correctly | POST `text="..."` ; 201; `text` is "..." |
| 304.3 | Comment tips work on GIF comments | POST tip on GIF comment; 200; `tip_total_cents` incremented |
| 304.4 | Reply to GIF comment with text | POST `parent_comment_id` of GIF comment, `kind=text`; 201 |

### 5.5 Section 305: Comment Rendering Validation (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 305.1 | GIF comment has gif_url and gif_alt_text in response | GET comments; GIF comment has both fields populated |
| 305.2 | Sticker comment has sticker_url and sticker_alt_text in response | GET comments; sticker comment has both fields |
| 305.3 | Default kind is "text" for plain comment | POST comment without `kind` field; 201; response `kind=text` |

### 5.6 Section 306: Comment Validation Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 306.1 | Invalid kind value rejected | POST with `kind=video`; 422; pattern validation error |
| 306.2 | GIF comment with text is accepted | POST `kind=gif` with both `gif_url` and `text`; 201; both fields stored |
| 306.3 | Sticker comment without sticker_url rejected | POST `kind=sticker` with `sticker_id` but no `sticker_url`; 422 |
| 306.4 | Empty text for text comment rejected | POST `kind=text` with `text=""`; 422 |
| 306.5 | GIF width/height stored correctly | POST `kind=gif` with `gif_width=480, gif_height=270`; 201; values in response |

### 5.7 Section 307: Comment Interactions Cross-Kind (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 307.1 | Reply to sticker comment with GIF | POST GIF comment as reply to sticker comment; 201; `parent_comment_id` set |
| 307.2 | Tip a sticker comment | POST tip on sticker comment; 200; `tip_total_cents` incremented |
| 307.3 | Thread with mixed comment kinds | Create text, GIF, sticker comments in thread; GET comments; all 3 kinds present |
| 307.4 | Comment count includes all kinds | Create one of each kind; GET post; `comment_count` = 3 |

### 5.8 Section 308: Comment Rendering UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 308.1 | GIF comment renders as image in thread | Navigate to post; GIF comment shows `<img>` with gif_url src |
| 308.2 | Sticker comment renders at fixed size | Sticker comment has `w-20 h-20` container class |
| 308.3 | Emoji picker button visible in comment composer | Expand comments; emoji button (Smile icon) visible in toolbar |

---

## 6. Error Handling

### 6.1 Error Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| GIF comment without gif_url | 422 | `validation_error` | "gif_url is required for gif comments" | Show inline form error; do not submit |
| Sticker comment without sticker_id | 422 | `validation_error` | "sticker_id is required for sticker comments" | Show inline form error |
| Sticker comment without sticker_url | 422 | `validation_error` | "sticker_url is required for sticker comments" | Show inline form error |
| Invalid kind value | 422 | `validation_error` | Pydantic pattern validation | Show generic validation error |
| Text comment without text | 422 | `validation_error` | "text is required for text comments" | Show inline form error |
| GIF URL from blocked domain | 400 | `gif_domain_blocked` | "GIF URL not from an allowed domain" | Show error toast; suggest using GIF picker |
| Post not found | 404 | `not_found` | "Post not found" | Redirect to feed |
| Parent comment not found | 404 | `parent_not_found` | "Parent comment not found" | Remove reply context; allow as top-level |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |
| Rate limited | 429 | `rate_limited` | "Too many comments, please wait" | Disable submit button; show countdown |

---

## 7. Security Considerations

- GIF URLs validated against allowed domains (same as MSG-008)
- Sticker URLs must reference platform S3 (no arbitrary external URLs)
- Alt text is HTML-escaped by React
- Comment rate limiting applies uniformly to all kinds
- GIF dimensions are validated server-side (max 4096x4096) to prevent layout abuse
- Sticker images are served from platform CDN; no user-uploaded sticker URLs accepted
- `gif_url` is sanitized to prevent XSS via data: or javascript: URI schemes

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| GIF loading in comment thread | < 1s per visible GIF | `loading="lazy"` on all GIF images; only load when scrolled into view |
| Large GIF file sizes | < 5MB per GIF | GIF picker enforces max file size; backend validates `Content-Length` if re-hosted |
| Sticker loading | < 200ms | Stickers served from CDN with aggressive cache headers; WebP format for smaller files |
| Comment list with many GIFs | Smooth scroll at 60fps | Virtualized comment list for threads > 50 comments; lazy load below fold |
| Emoji-only detection CPU | < 1ms per comment | `isEmojiOnly()` uses regex; cached per comment text in React.memo |
| Comment thread query latency | < 150ms p95 | Single DDB query on PK with begins_with; no additional queries for media fields |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `comment_created_total` | Counter | `kind` | Number of comments created, labeled by kind |
| `comment_media_load_time_ms` | Histogram | `kind`, `status` | Time to load GIF/sticker images in frontend |
| `comment_emoji_only_total` | Counter | -- | Number of emoji-only text comments |
| `comment_tip_on_media_total` | Counter | `kind` | Tips on non-text comments |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Media comment created | INFO | `comment_id`, `post_id`, `user_id`, `kind` |
| GIF URL blocked (domain) | WARN | `user_id`, `gif_url`, `reason` |
| Sticker URL invalid (not platform) | WARN | `user_id`, `sticker_url`, `reason` |

### 9.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| GIF comment creation failures spike | > 50 422s/hour on kind=gif | Medium |
| Sticker URL validation failures | > 20/hour blocked sticker URLs | Low |

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
media_comments_enabled: bool = os.environ.get("MEDIA_COMMENTS_ENABLED", "true").lower() == "true"
```

When disabled, the backend rejects `kind=gif` and `kind=sticker` comments with 400 "Media comments are not enabled". The frontend hides the GIF and Sticker buttons in the comment composer.

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend only | Deploy backend with kind field; feature flag ON in dev only | 1 day | All unit tests pass |
| Phase 2: Internal testing | Enable for internal test accounts; test GIF/sticker rendering | 2 days | E2E tests pass; manual QA sign-off |
| Phase 3: GA | Enable for all users; monitor GIF load performance | Permanent | No errors in Phase 2; GIF load time < 2s p95 |

---

## 11. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker component | MSG-006 | Required — **NOT YET IMPLEMENTED** |
| GifPicker component | MSG-008 | Required — **NOT YET IMPLEMENTED** |
| StickerPicker component | MSG-008 | Required — **NOT YET IMPLEMENTED** |
| `isEmojiOnly()` utility | MSG-006 | Required — **NOT YET IMPLEMENTED** |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/routers/newsfeed.py` | `CreateCommentRequest` (extends `ContentFieldsMixin`) | 1432 |
| `app/routers/newsfeed.py` | `create_comment` endpoint | 4556 |
| `app/routers/newsfeed.py` | `_comment_to_dict` serializer | 2018 |
| `app/routers/newsfeed.py` | `ContentFieldsMixin` | 1182 |
| `frontend/src/pages/feed/CommentsThread.tsx` | Comment thread rendering | - |
| `scripts/local-ddb-init.py` | `app_single_table` definition | 222 |

### Files That Do NOT Exist Yet (blocking dependencies)
| File | Dependency | Status |
|------|-----------|--------|
| `frontend/src/components/shared/EmojiPicker.tsx` | MSG-006 | Not implemented |
| `frontend/src/components/shared/GifPicker.tsx` | MSG-008 | Not implemented |
| `frontend/src/components/shared/StickerPicker.tsx` | MSG-008 | Not implemented |
| `frontend/src/pages/feed/CommentRow.tsx` | Referenced in ticket | Does not exist as separate file (comment rendering is inline in CommentsThread.tsx) |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_rich_comments.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_feed_004_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_feed_004_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_feed_004_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_feed_004_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_feed_004_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_feed_004_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_feed_004_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_feed_004_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/rich-comments.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 12

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `RICH_COMMENTS_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `RICH_COMMENTS_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| FEED-008 | Enhanced post composer uses emoji/gif/sticker pickers |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `RICH_COMMENTS_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
