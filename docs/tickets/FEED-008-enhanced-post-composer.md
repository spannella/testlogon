# FEED-008: Enhanced Post Composer

**Ticket**: FEED-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 5-6 days
**Depends on**: MSG-006 (EmojiPicker), MSG-008 (GifPicker, StickerPicker), MSG-009 (FindDateTimeComposer), MSG-010 (CountdownComposerDialog)

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-008 unifies the post composer (`CreatePost.tsx`) by integrating all new content types into a cohesive interface. The enhanced composer provides a content type selector (Text, Poll, Find-a-DateTime, Countdown, GIF, Sticker), emoji picker integration, draft auto-save via localStorage, character count with limit indicator, and a preview mode that shows how the post will look before publishing.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want a unified composer with buttons for all content types. | Content type buttons visible in toolbar; each opens appropriate sub-composer. |
| Creator | As a creator, I want my draft to be saved automatically so I don't lose work. | Draft text persisted to localStorage; restored on page reload. |
| Creator | As a creator, I want to see how many characters I've typed and the limit. | Character count indicator (e.g., "450 / 5000") below text input. |
| Creator | As a creator, I want to preview my post before publishing. | "Preview" button shows rendered post card; "Edit" returns to composer. |
| Creator | As a creator, I want the emoji picker available when writing posts. | Emoji button in toolbar; opens EmojiPicker; inserts emoji into text. |
| Creator | As a creator, I want to post a GIF directly from the composer. | GIF button opens GifPicker; selecting sends as post image. |
| Creator | As a creator, I want to schedule posts with the existing date picker. | Clock icon opens schedule picker (existing `publish_at` functionality). |

### 1.3 Why This Is Needed Now

As new post types are added (FEED-003 Find-a-DateTime, FEED-005 Countdown), the composer needs a unified interface that makes all content types discoverable. Draft auto-save prevents accidental data loss. Character count and preview mode improve the quality of published content. These are standard features in modern content creation tools.

---

## 2. Current State Analysis

### 2.1 Current CreatePost Component

`frontend/src/pages/feed/CreatePost.tsx` currently supports:
- Text input (textarea with auto-resize)
- Image upload (multiple images via `image_urls`)
- File attachment (from file manager via FilePickerDialog)
- Poll creation (via PollComposer)
- Video attachment (via VideoPickerDialog, FEED-001)
- Lock/paywall toggle
- Scheduling (publish_at date picker)

The toolbar has buttons for Image, File, Poll, Video, and Lock. There is no emoji picker, GIF picker, sticker option, Find-a-DateTime, countdown, draft saving, character count, or preview mode.

### 2.2 Available Components

From other tickets:
- `EmojiPicker` (MSG-006) — shared component
- `GifPicker` (MSG-008) — shared component
- `StickerPicker` (MSG-008) — shared component
- `FindDateTimeComposer` (MSG-009) — date range + time grid composer
- `CountdownComposerDialog` (MSG-010) — countdown target + event type form
- `PollComposer` (existing) — poll options + settings

### 2.3 Gaps

1. **No content type selector** — new types not discoverable.
2. **No emoji picker** — can't browse/insert emojis.
3. **No GIF/sticker posting** — can't post GIFs or stickers directly.
4. **No draft auto-save** — text lost on page navigation.
5. **No character count** — no indicator of remaining characters.
6. **No preview mode** — can't see post rendering before publishing.
7. **No FADT/countdown buttons** — new post types not accessible.

---

## 3. Technical Design

### 3.1 Content Type Architecture

The composer supports multiple content types, but only one can be active at a time:

```typescript
type PostContentType = "text" | "poll" | "find_datetime" | "countdown" | "gif" | "sticker";

const [contentType, setContentType] = useState<PostContentType>("text");
const [showContentMenu, setShowContentMenu] = useState(false);
```

Switching content type clears the previous sub-composer state:

```typescript
const handleContentTypeChange = (type: PostContentType) => {
  setContentType(type);
  // Clear sub-composer state
  setPollData(null);
  setFindDateTimeData(null);
  setCountdownData(null);
  setPendingGif(null);
  setPendingSticker(null);
  setShowContentMenu(false);
};
```

### 3.2 Toolbar Layout

```
┌──────────────────────────────────────────────────────────┐
│ [📷 Image] [📁 File] [📊 Poll] [🎥 Video]               │
│ [😀 Emoji] [GIF] [📌 Sticker] [📅 Find Time] [⏱ Count] │
│ [🔒 Lock] [🕐 Schedule] [👁 Preview]                     │
└──────────────────────────────────────────────────────────┘
```

Second row shows extended content types. The toolbar is responsive — on mobile, overflow items go into a "More" dropdown.

### 3.3 Draft Auto-Save

```typescript
const DRAFT_KEY = "feed_post_draft";

// Load draft on mount
useEffect(() => {
  const saved = localStorage.getItem(DRAFT_KEY);
  if (saved) {
    try {
      const draft = JSON.parse(saved);
      setBody(draft.body || "");
      // Restore other draft fields if applicable
    } catch (e) {
      // Ignore corrupt draft
    }
  }
}, []);

// Save draft on text change (debounced 1s)
const saveDraft = useDebouncedCallback((text: string) => {
  localStorage.setItem(DRAFT_KEY, JSON.stringify({
    body: text,
    savedAt: Date.now(),
  }));
}, 1000);

useEffect(() => {
  if (body.trim()) {
    saveDraft(body);
  } else {
    localStorage.removeItem(DRAFT_KEY);
  }
}, [body]);

// Clear draft on successful publish
const handlePublish = async () => {
  await createPostMutation.mutateAsync(payload);
  localStorage.removeItem(DRAFT_KEY);
  setBody("");
  // ... reset other state
};
```

Draft notification on load:
```tsx
{hasDraft && (
  <div className="flex items-center gap-2 text-sm text-muted-foreground p-2 bg-muted/50 rounded">
    <Info className="h-4 w-4" />
    <span>Draft restored from {formatTimeAgo(draftSavedAt)}</span>
    <Button variant="ghost" size="sm" onClick={clearDraft}>Discard</Button>
  </div>
)}
```

### 3.4 Character Count

```tsx
const MAX_CHARS = 5000;
const charCount = body.length;
const isOverLimit = charCount > MAX_CHARS;

// Below textarea:
<div className={cn(
  "text-xs text-right",
  isOverLimit ? "text-destructive" : charCount > MAX_CHARS * 0.9 ? "text-yellow-500" : "text-muted-foreground"
)}>
  {charCount.toLocaleString()} / {MAX_CHARS.toLocaleString()}
</div>

// Disable publish when over limit:
<Button disabled={isOverLimit || (!body.trim() && !pendingMedia)}>
  Publish
</Button>
```

Color coding:
- Normal (< 90%): muted gray
- Warning (90-100%): yellow
- Over limit (> 100%): red (publish disabled)

### 3.5 Preview Mode

```typescript
const [previewMode, setPreviewMode] = useState(false);

// Toggle button:
<Button
  variant={previewMode ? "default" : "ghost"}
  size="sm"
  onClick={() => setPreviewMode(!previewMode)}
>
  <Eye className="h-4 w-4 mr-1" />
  {previewMode ? "Edit" : "Preview"}
</Button>

// Preview rendering:
{previewMode ? (
  <div className="border rounded-lg p-4">
    <PostCard
      post={{
        post_id: "preview",
        user_id: currentUser.sub,
        user_name: currentUser.display_name,
        body: body,
        body_plain: body,
        image_urls: imageUrls,
        created_at: Math.floor(Date.now() / 1000),
        like_count: 0,
        comment_count: 0,
        // ... minimal fields for preview
      }}
      isPreview={true}
    />
  </div>
) : (
  // Normal edit view (textarea + toolbar)
  ...
)}
```

PostCard needs an `isPreview` prop that:
- Disables all interactive buttons (like, comment, tip, react)
- Shows a "Preview" badge
- Renders content identically to the real post

### 3.6 Emoji Picker Integration

```tsx
<Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
  <PopoverTrigger asChild>
    <Button variant="ghost" size="sm">
      <Smile className="h-4 w-4" />
    </Button>
  </PopoverTrigger>
  <PopoverContent className="w-80 p-0" align="start">
    <EmojiPicker
      onSelect={(emoji) => {
        // Insert emoji at cursor position
        const textarea = textareaRef.current;
        if (textarea) {
          const start = textarea.selectionStart;
          const end = textarea.selectionEnd;
          const newText = body.slice(0, start) + emoji + body.slice(end);
          setBody(newText);
          // Set cursor after inserted emoji
          setTimeout(() => {
            textarea.selectionStart = textarea.selectionEnd = start + emoji.length;
            textarea.focus();
          }, 0);
        } else {
          setBody(body + emoji);
        }
        setEmojiOpen(false);
      }}
    />
  </PopoverContent>
</Popover>
```

### 3.7 GIF/Sticker Post Integration

GIF post: selecting a GIF from GifPicker sets the GIF URL as the post's image:
```typescript
const handleGifSelect = (gif: GifResult) => {
  setImageUrls([gif.url]);
  setPendingGif(gif);
  setContentType("gif");
};
```

Sticker post: selecting a sticker creates a post with the sticker image:
```typescript
const handleStickerSelect = (sticker: StickerResult) => {
  setImageUrls([sticker.url]);
  setPendingSticker(sticker);
  setContentType("sticker");
};
```

Both GIF and sticker posts are stored as regular posts with `image_urls` — the distinction is visual only in the composer.

### 3.8 Sub-Composer Integration

Each content type has its own sub-composer panel that appears below the toolbar:

```tsx
{contentType === "poll" && <PollComposer ... />}
{contentType === "find_datetime" && <FindDateTimeComposer ... />}
{contentType === "countdown" && <CountdownComposerDialog ... />}
{contentType === "gif" && <GifPicker onSelect={handleGifSelect} />}
{contentType === "sticker" && <StickerPicker onSelect={handleStickerSelect} />}
```

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Changes |
|------|---------|
| `frontend/src/pages/feed/CreatePost.tsx` | Major enhancement: content type selector, emoji picker, GIF/sticker, draft auto-save, character count, preview mode |
| `frontend/src/pages/feed/PostCard.tsx` | Add `isPreview` prop to disable interactions |

### 4.2 Step-by-Step Order

1. Add content type state and selector buttons
2. Integrate EmojiPicker (insert at cursor)
3. Add GIF and Sticker picker integration
4. Add Find-a-DateTime and Countdown composer buttons
5. Implement draft auto-save (localStorage + debounce)
6. Add character count with color coding
7. Implement preview mode with PostCard preview rendering
8. Add responsive toolbar (overflow on mobile)
9. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-enhanced-composer.spec.ts` — 12 tests across 3 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  // Set up Alice session
  // Clear any existing drafts: localStorage.removeItem("feed_post_draft")
});
```

### 5.3 Section 333: Composer Content Types (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 333.1 | Emoji picker inserts emoji into composer | Click emoji button; select 😀; textarea contains "😀" |
| 333.2 | GIF picker selects and previews GIF | Click GIF button; picker opens; select GIF; image preview visible |
| 333.3 | Content type buttons are visible | Navigate to feed; composer toolbar has Emoji, GIF, Poll, Find Time buttons |
| 333.4 | Only one content type active at a time | Select Poll; poll composer visible; select GIF; poll composer hidden |
| 333.5 | Schedule button opens date picker | Click schedule button; date picker visible |

### 5.4 Section 334: Draft Auto-Save (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 334.1 | Draft saved on text input | Type text; wait 1.5s; check localStorage has draft |
| 334.2 | Draft restored on page reload | Type text; reload page; textarea pre-filled with draft text |
| 334.3 | Draft cleared on publish | Type + publish; localStorage draft removed |
| 334.4 | Discard draft button works | Load page with draft; click "Discard"; textarea empty; draft removed |

### 5.5 Section 335: Character Count & Preview (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 335.1 | Character count updates on input | Type "hello"; count shows "5 / 5,000" |
| 335.2 | Character count turns red over limit | Paste 5001+ characters; count text has destructive class; publish disabled |
| 335.3 | Preview mode renders post card | Type text; click Preview; PostCard-style rendering visible; "Edit" button returns to editor |

---

## 6. Error Handling

| Scenario | Handling |
|----------|----------|
| localStorage quota exceeded | Silently fail draft save (try-catch); show console warning |
| Corrupt draft JSON | Discard corrupt draft; start fresh |
| Over character limit | Publish button disabled; red character count |
| No content (empty text + no media) | Publish button disabled |

---

## 7. Security Considerations

- Draft stored in localStorage (client-side only, never sent to server until publish)
- Preview mode renders mock PostCard (no API calls)
- Emoji/GIF/sticker content goes through normal post creation validation

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Draft save on every keystroke | Debounced to 1 second; only saves to localStorage |
| EmojiPicker lazy loading | Dynamic import on first open; cached after |
| GifPicker API calls | Debounced search (300ms); trending cached |
| Preview mode re-rendering | React.memo on PostCard; preview only renders when mode toggled |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker | MSG-006 | Required |
| GifPicker, StickerPicker | MSG-008 | Required |
| FindDateTimeComposer | MSG-009 | Required |
| CountdownComposerDialog | MSG-010 | Required |
| PollComposer | Existing | Available |
