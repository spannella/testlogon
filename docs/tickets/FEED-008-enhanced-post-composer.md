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
<!-- NOTE: ALL of the following except PollComposer do NOT exist yet — MSG-006, MSG-008, MSG-009, MSG-010 have not been implemented -->
- `EmojiPicker` (MSG-006) — **does not exist yet**
- `GifPicker` (MSG-008) — **does not exist yet**
- `StickerPicker` (MSG-008) — **does not exist yet**
- `FindDateTimeComposer` (MSG-009) — **does not exist yet**
- `CountdownComposerDialog` (MSG-010) — **does not exist yet**
- `PollComposer` (existing) — available at `frontend/src/pages/feed/PollComposer.tsx`
<!-- VERIFIED: frontend/src/pages/feed/PollComposer.tsx exists -->

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

### 3.0 Architecture Diagram

```
                    Enhanced Post Composer Architecture
  ┌───────────────────────────────────────────────────────┐
  │                     CreatePost.tsx                      │
  │  ┌─────────────────────────────────────────────────┐   │
  │  │  TextArea (body input + emoji insertion)         │   │
  │  │  CharacterCount: {count} / 5,000                │   │
  │  │  DraftIndicator: "Draft restored from Xm ago"   │   │
  │  └─────────────────────────────────────────────────┘   │
  │  ┌─────────────────────────────────────────────────┐   │
  │  │  ContentTypeToolbar                              │   │
  │  │  [📷] [📁] [📊] [🎥] [😀] [GIF] [📌] [📅] [⏱]  │   │
  │  │  [🔒 Lock] [🕐 Schedule] [👁 Preview]            │   │
  │  └─────────────────────────────────────────────────┘   │
  │  ┌─────────────────────────────────────────────────┐   │
  │  │  Sub-Composer Panel (one at a time)              │   │
  │  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │   │
  │  │  │ PollComp  │  │ GifPicker│  │FindDateComp  │  │   │
  │  │  └──────────┘  └──────────┘  └──────────────┘  │   │
  │  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │   │
  │  │  │StickerPkr│  │CountComp │  │EmojiPicker   │  │   │
  │  │  └──────────┘  └──────────┘  └──────────────┘  │   │
  │  └─────────────────────────────────────────────────┘   │
  │  ┌─────────────────────────────────────────────────┐   │
  │  │  Preview Mode (conditional)                      │   │
  │  │  PostCard(isPreview=true) → disabled actions     │   │
  │  └─────────────────────────────────────────────────┘   │
  │  [Publish Button]                                       │
  └───────────────────────────────────────────────────────┘
           │                                    │
           │  localStorage                      │  POST /ui/posts
           v                                    v
  ┌─────────────────┐              ┌──────────────────┐
  │  Draft Storage    │              │  Backend          │
  │  feed_post_draft  │              │  newsfeed.py      │
  │  (debounced 1s)   │              │  create_post()    │
  └─────────────────┘              └──────────────────┘
```

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

### 5.5 Section 335: Character Count & Preview (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 335.1 | Character count updates on input | Type "hello"; count shows "5 / 5,000" |
| 335.2 | Character count turns yellow at 90% | Paste 4500+ characters; count text has yellow/warning style |
| 335.3 | Character count turns red over limit | Paste 5001+ characters; count text has destructive class; publish disabled |
| 335.4 | Preview mode renders post card | Type text; click Preview; PostCard-style rendering visible; interactions disabled |
| 335.5 | Edit button returns from preview | Click "Edit" in preview mode; textarea visible again with same text |

### 5.6 Section 336: Composer Edge Cases & Negative Tests (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 336.1 | Publish disabled when empty | No text or media; Publish button disabled |
| 336.2 | Switch content type clears previous | Select Poll; add options; switch to GIF; poll composer hidden; switch back to Poll; options cleared |
| 336.3 | Draft survives navigation away and back | Type text; navigate to /messages; navigate back to /feed; draft restored |
| 336.4 | Multiple emojis at cursor position | Place cursor mid-text; insert emoji; emoji appears at cursor position, not at end |
| 336.5 | Mobile toolbar overflow | Set viewport to 375px width; overflow items in "More" dropdown; all content types accessible |

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| localStorage quota exceeded | N/A (client) | — | Silent fail; console warning | Draft not saved; user can still publish |
| Corrupt draft JSON | N/A (client) | — | Silent discard of corrupt draft | Start with empty composer |
| Over character limit | N/A (client) | — | Red counter; "Publish" disabled | Delete text to come under 5000 chars |
| No content (empty text + no media) | N/A (client) | — | "Publish" disabled | Add text or media |
| Text exceeds server limit | 400 | `body_too_long` | "Post body exceeds maximum length" | Trim text |
| Invalid image URL from GIF picker | 422 | `validation_error` | "Invalid image URL" | Re-select GIF |
| Publish fails (network error) | N/A (client) | — | Toast: "Failed to publish. Your draft has been saved." | Draft preserved; retry |
| Post creation rate limit | 429 | `rate_limited` | "Too many posts. Please wait." | Wait and retry |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Redirect to login |
| CSRF token mismatch | 403 | `csrf_invalid` | "Invalid CSRF token" | Refresh page; draft preserved in localStorage |
| Stale session during draft | 401 | `unauthorized` | "Session expired. Your draft has been saved." | Login; draft restored from localStorage |

---

## 7. Security Considerations

- Draft stored in localStorage (client-side only, never sent to server until publish)
- Preview mode renders mock PostCard (no API calls)
- Emoji/GIF/sticker content goes through normal post creation validation
- localStorage drafts cleared on logout to prevent data leakage between users on shared devices
- GIF picker external URLs validated against allowlisted domains (e.g., giphy.com, tenor.com)
- Character limit enforced both client-side and server-side (defense in depth)

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Draft save on every keystroke | < 1ms per save | Debounced to 1 second; only saves to localStorage (sync, fast) |
| EmojiPicker lazy loading | < 200ms first open | Dynamic import (`React.lazy`) on first open; cached after |
| GifPicker API calls | < 500ms per search | Debounced search (300ms); trending results cached 5 min |
| StickerPicker bundle | < 30KB | Static sticker pack bundled; no external API |
| Preview mode re-rendering | < 50ms toggle | `React.memo` on PostCard; preview only renders when mode toggled |
| Content type switch | Instant | Sub-composer panels unmounted on switch (no background state) |
| Toolbar responsive layout | No jank | CSS flexbox wrap; "More" dropdown computed once on mount + resize |
| Multiple large images | < 2s upload | Images uploaded one at a time with progress indicator |

### 8.1 Bundle Size Impact

| Component | Size (gzipped) | Loading Strategy |
|-----------|---------------|-----------------|
| EmojiPicker | ~40KB | Lazy loaded on first open |
| GifPicker | ~15KB | Lazy loaded on first open |
| StickerPicker | ~10KB | Lazy loaded on first open |
| FindDateTimeComposer | ~8KB | Lazy loaded when content type selected |
| CountdownComposerDialog | ~5KB | Lazy loaded when content type selected |
| Total incremental | ~78KB | Only loaded on demand; no impact on initial page load |

### 8.2 Draft Storage Limits

- Max draft size: ~100KB (localStorage item limit)
- Draft only stores: body text, content type, media URLs (not actual image data)
- Stale draft cleanup: drafts older than 7 days are auto-discarded on load

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `composer_content_type_selected_total` | Counter | `type` (text/poll/gif/sticker/fadt/countdown) | Content type selections |
| `composer_draft_saved_total` | Counter | — | Draft auto-save events |
| `composer_draft_restored_total` | Counter | — | Draft restored on page load |
| `composer_draft_discarded_total` | Counter | `reason` (user/stale/publish) | Draft discards |
| `composer_preview_toggled_total` | Counter | — | Preview mode toggles |
| `composer_emoji_inserted_total` | Counter | — | Emojis inserted from picker |
| `composer_gif_selected_total` | Counter | — | GIFs selected from picker |
| `composer_char_limit_hit_total` | Counter | — | Times user exceeded character limit |
| `composer_publish_latency_ms` | Histogram | `content_type` | Time from click Publish to API response |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Post published via enhanced composer | INFO | `user_sub`, `content_type`, `has_media`, `body_length`, `is_scheduled` |
| Draft restored | DEBUG | `user_sub`, `draft_age_seconds`, `body_length` |
| Draft discarded (stale) | DEBUG | `user_sub`, `draft_age_seconds` |
| Character limit exceeded | DEBUG | `user_sub`, `char_count` |
| Sub-composer opened | DEBUG | `user_sub`, `content_type` |

### 9.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High publish error rate | > 5% of publish attempts fail | High | Check backend health |
| GIF picker API errors | > 20% of GIF searches fail | Medium | Check GIF provider API status |
| Draft save failures | > 1% of save attempts throw | Low | Check localStorage availability |

### 9.4 Dashboard Queries

**Content type distribution**:
```promql
sum(increase(composer_content_type_selected_total[1d])) by (type)
```

**Draft usage rate** (% of sessions that use draft):
```promql
sum(rate(composer_draft_restored_total[1d])) / sum(rate(composer_draft_saved_total[1d])) * 100
```

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
enhanced_composer_enabled: bool = os.environ.get("ENHANCED_COMPOSER_ENABLED", "true").lower() == "true"
```

Frontend flag passed via `/ui/feature-flags` endpoint:
```typescript
const { data: flags } = useQuery(["feature-flags"], fetchFlags);
const showEnhancedComposer = flags?.enhanced_composer_enabled ?? false;
```

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend ready | All post creation validation supports new content types | 1 day | Unit tests pass |
| Phase 2: Internal | Enhanced composer visible to internal users | 3 days | All 12 E2E tests pass; manual QA |
| Phase 3: Canary 10% | Enable for 10% of creators | 3 days | No publish errors; positive feedback |
| Phase 4: GA | Enable for all creators | Permanent | Content type adoption metrics positive |

### 10.3 Migration

No backend migration needed. All new content types (GIF, sticker, countdown, FADT) use existing post creation API with standard fields. Draft auto-save is entirely client-side.

### 10.4 Rollback

1. Set `ENHANCED_COMPOSER_ENABLED=false` — frontend falls back to legacy toolbar
2. Existing drafts in localStorage persist but are not loaded by legacy composer
3. All posts created with enhanced composer remain valid (same API)
4. No data loss or corruption risk

---

## 11. Frontend Component Tree (Detailed)

```
CreatePost (enhanced)
├── DraftIndicator (conditional)
│   ├── Info icon + "Draft restored from {time} ago"
│   └── DiscardButton → clearDraft()
├── TextArea (with auto-resize)
│   ├── placeholder: "What's on your mind?"
│   ├── onInput → setBody + saveDraft (debounced)
│   └── ref → textareaRef (for emoji cursor insertion)
├── CharacterCount
│   ├── count: body.length
│   ├── max: 5000
│   └── color: muted → yellow → red
├── ContentTypeToolbar
│   ├── Row 1 (always visible)
│   │   ├── ImageButton → file input
│   │   ├── FileButton → FilePickerDialog
│   │   ├── PollButton → setContentType("poll")
│   │   └── VideoButton → VideoPickerDialog
│   ├── Row 2 (extended)
│   │   ├── EmojiButton → Popover(EmojiPicker)
│   │   ├── GifButton → setContentType("gif")
│   │   ├── StickerButton → setContentType("sticker")
│   │   ├── FindTimeButton → setContentType("find_datetime")
│   │   └── CountdownButton → setContentType("countdown")
│   └── Row 3 (actions)
│       ├── LockToggle → lock_price_cents
│       ├── ScheduleButton → publish_at DateTimePicker
│       └── PreviewButton → toggle previewMode
├── SubComposerPanel (conditional, one at a time)
│   ├── PollComposer (existing)
│   ├── GifPicker (lazy loaded)
│   ├── StickerPicker (lazy loaded)
│   ├── FindDateTimeComposer (lazy loaded)
│   └── CountdownComposerDialog (lazy loaded)
├── PreviewPanel (conditional, when previewMode=true)
│   └── PostCard(isPreview=true)
│       ├── PostHeader (author, "just now")
│       ├── PostBody (rendered body text)
│       ├── Media preview (images, GIF, sticker)
│       └── Disabled action buttons (grayed out)
├── MediaPreview (conditional, when images/GIF/sticker selected)
│   └── Thumbnail grid with remove buttons
└── PublishButton
    ├── disabled: isOverLimit || noContent || isSubmitting
    └── onClick → createPostMutation → clearDraft → resetState
```

---

## 12. API Request/Response Examples

**Publish a post with emoji in body** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_a" \
  -d '{
    "body": "Hello world! 😀🎉 Check out this update!",
    "image_urls": []
  }'
```

**Response (201)**:
```json
{
  "post_id": "p_abc123",
  "user_id": "alice@test.local",
  "body": "Hello world! 😀🎉 Check out this update!",
  "created_at": 1748520100,
  "like_count": 0,
  "comment_count": 0
}
```

**Publish a GIF post** (curl):

```bash
curl -X POST http://localhost:8000/ui/posts \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_a" \
  -d '{
    "body": "When the code finally compiles",
    "image_urls": ["https://media.giphy.com/media/xxx/giphy.gif"]
  }'
```

**Response (201)**:
```json
{
  "post_id": "p_gif001",
  "user_id": "alice@test.local",
  "body": "When the code finally compiles",
  "image_urls": ["https://media.giphy.com/media/xxx/giphy.gif"],
  "created_at": 1748520200,
  "like_count": 0,
  "comment_count": 0
}
```

---

## 13. Pydantic Models

```python
# In app/models.py — the CreatePostRequest already handles all content types.
# No new Pydantic model needed for the enhanced composer, as it reuses
# the existing CreatePostRequest with standard fields.

class CreatePostRequest(ContentFieldsMixin):
    """Unified post creation request supporting all content types."""
    body: Optional[str] = Field(default=None, max_length=5000)
    body_rich: Optional[str] = Field(default=None, max_length=20000)
    image_urls: Optional[List[str]] = None
    video_id: Optional[str] = None
    # Poll fields
    poll_question: Optional[str] = Field(default=None, max_length=500)
    poll_options: Optional[List[str]] = None
    # Countdown fields (FEED-005)
    post_kind: Optional[str] = Field(default=None, pattern=r"^(text|countdown|find_datetime)$")
    countdown_title: Optional[str] = Field(default=None, max_length=200)
    target_datetime: Optional[int] = None
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None
    # Scheduling
    publish_at: Optional[int] = None
    schedule_timezone: Optional[str] = None
    # Lock
    lock_price_cents: Optional[int] = Field(default=None, ge=0)
    lock_description: Optional[str] = None

    @model_validator(mode="after")
    def validate_has_content(self):
        """Ensure post has at least some content."""
        has_text = bool(self.body and self.body.strip())
        has_media = bool(self.image_urls or self.video_id)
        has_poll = bool(self.poll_question)
        has_countdown = bool(self.countdown_title)
        if not (has_text or has_media or has_poll or has_countdown):
            raise ValueError("Post must have text, media, poll, or countdown content")
        return self
```

---

## 14. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker | MSG-006 | Required — **NOT YET IMPLEMENTED** |
| GifPicker, StickerPicker | MSG-008 | Required — **NOT YET IMPLEMENTED** |
| FindDateTimeComposer | MSG-009 | Required — **NOT YET IMPLEMENTED** |
| CountdownComposerDialog | MSG-010 | Required — **NOT YET IMPLEMENTED** |
| PollComposer | Existing | Available (`frontend/src/pages/feed/PollComposer.tsx`) |

---

## Codebase References

### Existing Files (verified)
| File | Purpose |
|------|---------|
| `frontend/src/pages/feed/CreatePost.tsx` | Current post composer |
| `frontend/src/pages/feed/PollComposer.tsx` | Poll creation sub-composer |
| `frontend/src/pages/feed/PollCard.tsx` | Poll rendering in PostCard |
| `frontend/src/pages/feed/VideoPickerDialog.tsx` | Video attachment picker (FEED-001) |
| `frontend/src/pages/feed/PostCard.tsx` | Post card rendering (for preview mode) |
| `app/routers/newsfeed.py` | `CreatePostRequest` (line 1276), `create_post` (line 3013) |

### Files That Do NOT Exist Yet (blocking dependencies)
| File | Dependency |
|------|-----------|
| `frontend/src/components/shared/EmojiPicker.tsx` | MSG-006 |
| `frontend/src/components/shared/GifPicker.tsx` | MSG-008 |
| `frontend/src/components/shared/StickerPicker.tsx` | MSG-008 |
| `frontend/src/components/shared/AvailabilityGrid.tsx` | MSG-009 |
| `frontend/src/pages/messages/CountdownCard.tsx` | MSG-010 |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_enhanced_composer.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_feed_008_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_feed_008_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_feed_008_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_feed_008_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_feed_008_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_feed_008_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_feed_008_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_feed_008_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/enhanced-composer.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 12

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `ENHANCED_COMPOSER_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `ENHANCED_COMPOSER_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| FEED-004 | Required | Emoji/gif/sticker picker components |
| FEED-005 | Required | Countdown post component |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Sequential (after FEED-004, FEED-005)** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `ENHANCED_COMPOSER_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
