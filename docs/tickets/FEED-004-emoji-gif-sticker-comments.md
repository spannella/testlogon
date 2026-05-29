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
| Commenter | As a user, I want single-emoji comments to render large. | Comment with just "😀" renders at 3x size. |
| Viewer | As a viewer, I want to see GIF and sticker comments properly rendered in the comment thread. | GIF animates; sticker displays at standard size; alt text for accessibility. |
| Creator | As a post creator, I want to tip GIF/sticker comments the same way I tip text comments. | Tip button available on all comment kinds. |

### 1.3 Why This Is Needed Now

With EmojiPicker, GifPicker, and StickerPicker already built for messaging (MSG-006, MSG-008), extending them to comments is straightforward. GIF and sticker comments are standard in social platforms (Instagram, Facebook, Twitter/X) and significantly increase comment engagement.

---

## 2. Current State Analysis

### 2.1 Comment Model

Comments are created via `POST /posts/{post_id}/comments` in `app/routers/newsfeed.py`. The current `CreateCommentRequest` model:

```python
class CreateCommentRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    parent_comment_id: Optional[str] = None
```

Comments are stored in DDB with fields: `comment_id`, `post_id`, `user_id`, `text`, `parent_comment_id`, `created_at`, `tip_total_cents`.

### 2.2 Comment Rendering

`frontend/src/pages/feed/CommentsThread.tsx` renders comments as plain text in `<p>` tags. `CommentRow.tsx` handles individual comment display with author info, tip button, and reply button.

### 2.3 Available Picker Components

- `EmojiPicker` (MSG-006): `frontend/src/components/shared/EmojiPicker.tsx`
- `GifPicker` (MSG-008): `frontend/src/components/shared/GifPicker.tsx`
- `StickerPicker` (MSG-008): `frontend/src/components/shared/StickerPicker.tsx`

### 2.4 Gaps

1. **No `kind` field on comments** — all comments are implicitly text.
2. **No GIF/sticker fields on comments** — no `gif_url`, `sticker_id` etc.
3. **No media pickers in comment composer** — only a text input exists.
4. **No emoji-only large rendering for comments** — no detection of emoji-only content.
5. **No GIF/sticker rendering in CommentRow** — only text displayed.

---

## 3. Technical Design

### 3.1 Comment Model Extension

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

### 3.2 Comment DDB Item Extension

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

### 3.3 Comment Response Extension

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

### 3.4 Frontend Types

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

### 3.5 Frontend Components

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

`frontend/e2e/feed-media-comments.spec.ts` — 12 tests across 3 sections.

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
| 304.2 | Text comment with emoji-only content stored correctly | POST `text="😀"`; 201; `text` is "😀" |
| 304.3 | Comment tips work on GIF comments | POST tip on GIF comment; 200; `tip_total_cents` incremented |
| 304.4 | Reply to GIF comment with text | POST `parent_comment_id` of GIF comment, `kind=text`; 201 |

### 5.5 Section 305: Comment Rendering Validation (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 305.1 | GIF comment has gif_url and gif_alt_text in response | GET comments; GIF comment has both fields populated |
| 305.2 | Sticker comment has sticker_url and sticker_alt_text in response | GET comments; sticker comment has both fields |
| 305.3 | Default kind is "text" for plain comment | POST comment without `kind` field; 201; response `kind=text` |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| GIF comment without gif_url | 422 | "gif_url is required for gif comments" |
| Sticker comment without sticker_id | 422 | "sticker_id is required for sticker comments" |
| Invalid kind value | 422 | Pydantic pattern validation |
| Text comment without text | 422 | "text is required for text comments" |

---

## 7. Security Considerations

- GIF URLs validated against allowed domains (same as MSG-008)
- Sticker URLs must reference platform S3 (no arbitrary external URLs)
- Alt text is HTML-escaped by React
- Comment rate limiting applies uniformly to all kinds

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker component | MSG-006 | Required |
| GifPicker component | MSG-008 | Required |
| StickerPicker component | MSG-008 | Required |
| `isEmojiOnly()` utility | MSG-006 | Required |
