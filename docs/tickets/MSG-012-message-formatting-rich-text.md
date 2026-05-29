# MSG-012: Message Formatting & Rich Text

**Ticket**: MSG-012
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-012 adds basic markdown formatting, URL auto-linking with preview cards, and @mention autocomplete to the messaging system. Users can toggle between plain text and rich text mode in the compose bar. Formatted messages render bold, italic, strikethrough, inline code, code blocks, quotes, and hyperlinks in the message bubble. URLs are automatically detected and linked, with Open Graph preview cards fetched for supported domains (mock OG parser in dev mode).

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Sender | As a sender, I want to format messages with **bold**, *italic*, ~~strikethrough~~, and `code`. | Markdown syntax rendered in message bubble. |
| Sender | As a sender, I want to write code blocks with syntax highlighting. | Triple-backtick blocks render as code blocks with monospace font. |
| Sender | As a sender, I want to quote text using `>` prefix. | Quote lines render with left border and muted background. |
| Sender | As a sender, I want URLs I type to become clickable links automatically. | URLs auto-detected and rendered as `<a>` tags. |
| Sender | As a sender, I want URLs to show preview cards (title, description, image). | OG metadata fetched; preview card displayed below message text. |
| Sender | As a sender, I want to @mention other users in the conversation with autocomplete. | Type `@` → autocomplete dropdown of conversation participants; select → inserts mention. |
| Sender | As a sender, I want to see a live preview of my formatted message as I type. | Preview panel below compose bar shows rendered output. |
| Sender | As a sender, I want to toggle between plain text and rich text mode. | Toggle button in compose bar; plain mode sends raw text; rich mode enables formatting. |
| Recipient | As a recipient, I want to see properly formatted messages. | Markdown rendered; links clickable; mentions highlighted. |

### 1.3 Why This Is Needed Now

Text-only messages are limiting for technical communication, content sharing, and expressive messaging. Markdown support is standard in Slack, Discord, and Teams. URL previews increase engagement with shared links. Mentions enable directed communication in group chats, which is critical as the platform grows group messaging usage.

---

## 2. Current State Analysis

### 2.1 Message Storage

Messages are stored with `text` field as a plain string. The backend performs no text processing — text is stored and returned as-is. Adding formatting support is primarily a frontend rendering concern, with the raw markdown/text stored in the `text` field unchanged.

### 2.2 Newsfeed Rich Text

The newsfeed already supports markdown and rich text via `ContentFieldsMixin`:
- `body_format`: `"plain"`, `"markdown"`, `"richtext"`
- `body_markdown`: Markdown source
- `body_rich`: Serialized rich text document

However, messages do not use this mixin. For messaging, a simpler approach is preferred: store the raw text and render markdown on the frontend.

### 2.3 Mention Infrastructure

No @mention system exists in the codebase. Mentions require:
1. Frontend: Autocomplete UI that shows conversation participants when user types `@`
2. Storage: Mention metadata on the message (which user_subs are mentioned)
3. Notifications: Mentioned users receive a notification
4. Rendering: Mentioned names highlighted in message text

### 2.4 URL Detection

No URL detection or link preview system exists. URL patterns need to be detected in message text and:
1. Rendered as clickable `<a>` tags
2. Open Graph metadata fetched for preview cards

### 2.5 Gaps

1. **No markdown rendering** — message text displayed as plain text.
2. **No URL auto-linking** — URLs are plain text, not clickable.
3. **No link preview cards** — no OG metadata fetching.
4. **No @mention system** — no autocomplete, storage, or rendering.
5. **No formatting toggle** — no plain/rich mode in compose bar.
6. **No live preview** — no preview panel in compose bar.
7. **No mock OG parser** — dev mode needs deterministic OG results.

---

## 3. Technical Design

### 3.1 Message Format Field

Add `format` field to message items:

| Field | Type | Description |
|-------|------|-------------|
| `format` | String | `"plain"` (default) or `"markdown"` |
| `mentioned_user_ids` | List[String] | User subs mentioned in the message |

The `text` field stores the raw input (including markdown syntax). The `format` field tells the frontend how to render it.

### 3.2 Backend Changes

#### 3.2.1 Message Send Extension

**File**: `app/routers/messaging.py`

Extend the text message send model:

```python
class SendTextMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    format: str = Field(default="plain", pattern=r"^(plain|markdown)$")
    mentioned_user_ids: list[str] = Field(default_factory=list, max_length=50)
    # ... existing fields (reply_to, tip, lock, expires, send_at, encryption, view_once) ...
```

In `send_text_message()`:
```python
message_item = {
    # ... existing fields ...
    "format": body.format,
    "mentioned_user_ids": body.mentioned_user_ids,
}
```

#### 3.2.2 Mention Validation

Validate that mentioned user IDs are actual participants of the conversation:

```python
if body.mentioned_user_ids:
    participants = _get_conversation_participants(conv_id)
    participant_subs = {p["user_sub"] for p in participants}
    invalid = set(body.mentioned_user_ids) - participant_subs
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Mentioned users are not conversation participants: {', '.join(invalid)}"
        )
```

#### 3.2.3 Mention Notifications

When a message with mentions is sent, create a notification for each mentioned user:

```python
for mentioned_sub in body.mentioned_user_ids:
    if mentioned_sub != user_sub:  # Don't notify self
        create_notification(
            user_sub=mentioned_sub,
            type="message_mention",
            title=f"{sender_name} mentioned you",
            body=body.text[:100],
            link=f"/messages/{conv_id}",
        )
```

#### 3.2.4 Mock OG Parser

**File**: `app/services/og_parser.py`

```python
MOCK_OG_DATA = {
    "example.com": {
        "title": "Example Domain",
        "description": "This domain is for use in illustrative examples.",
        "image": None,
    },
    "github.com": {
        "title": "GitHub: Let's build from here",
        "description": "GitHub is where over 100 million developers shape the future of software.",
        "image": "/mock/og/github-preview.png",
    },
    # ... more mock domains ...
}

def fetch_og_metadata(url: str) -> dict | None:
    """Fetch Open Graph metadata for a URL (mock in dev mode)."""
    if S.dev_mode:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace("www.", "")
        mock = MOCK_OG_DATA.get(domain)
        if mock:
            return {"url": url, **mock}
        return {"url": url, "title": domain, "description": None, "image": None}

    # Production: HTTP GET + parse <meta property="og:..." /> tags
    # (not implemented in this ticket — production OG parsing is a separate concern)
    return None

@router.post("/ui/messaging/link-preview")
def get_link_preview(body: LinkPreviewIn, ctx=Depends(require_ui_session)):
    """Fetch link preview metadata for a URL."""
    og = fetch_og_metadata(body.url)
    if not og:
        raise HTTPException(status_code=404, detail="Could not fetch preview")
    return og
```

#### 3.2.5 MessageOut Extension

```python
format: str = "plain"
mentioned_user_ids: list[str] = Field(default_factory=list)
```

### 3.3 Frontend: Markdown Renderer

**File**: `frontend/src/components/shared/MarkdownRenderer.tsx`

A lightweight markdown-to-JSX renderer that supports:
- `**bold**` → `<strong>`
- `*italic*` → `<em>`
- `~~strikethrough~~` → `<del>`
- `` `inline code` `` → `<code>`
- ```` ```code block``` ```` → `<pre><code>`
- `> quote` → `<blockquote>`
- `[text](url)` → `<a href="url">`
- URL auto-detection → `<a href="url">`
- @mention rendering → `<span class="mention">`

```typescript
interface MarkdownRendererProps {
  text: string;
  format: "plain" | "markdown";
  mentionedUserIds?: string[];
  className?: string;
}
```

**Implementation approach**: Use a simple regex-based parser (not a full AST parser like remark) for performance. The supported subset is small enough for regex handling. Sanitize output to prevent XSS (no raw HTML support).

### 3.4 Frontend: MentionAutocomplete

**File**: `frontend/src/pages/messages/MentionAutocomplete.tsx`

```typescript
interface MentionAutocompleteProps {
  participants: ConversationParticipant[];
  onSelect: (user: ConversationParticipant) => void;
  query: string;  // text after "@"
  position: { top: number; left: number };
}
```

- Triggered when user types `@` in compose textarea
- Filters participants by display name prefix
- Shows dropdown below cursor position
- Arrow keys + Enter to select
- Escape to dismiss
- Selection inserts `@DisplayName` and records the user_sub in `mentionedUserIds`

### 3.5 Frontend: LinkPreviewCard

**File**: `frontend/src/pages/messages/LinkPreviewCard.tsx`

```typescript
interface LinkPreviewCardProps {
  url: string;
}
```

- Fetches OG metadata via `POST /ui/messaging/link-preview`
- Renders card with: title, description (truncated), image (if available), domain name
- Clickable → opens URL in new tab
- Loading skeleton while fetching
- Cached per URL via React Query (staleTime: 1 hour)
- `data-testid="link-preview-card"`

### 3.6 Frontend: ComposeBar Enhancements

**RichTextToggle**: Button to switch between plain and markdown mode.

```tsx
<Button
  variant={formatMode === "markdown" ? "default" : "ghost"}
  size="icon"
  onClick={() => setFormatMode(prev => prev === "plain" ? "markdown" : "plain")}
  title={formatMode === "markdown" ? "Switch to plain text" : "Switch to rich text"}
>
  <Type className="h-4 w-4" />
</Button>
```

**Live Preview**: When in markdown mode, show a preview below the textarea:

```tsx
{formatMode === "markdown" && text.trim() && (
  <div className="border-t p-2 text-sm max-h-24 overflow-y-auto bg-muted/30">
    <MarkdownRenderer text={text} format="markdown" />
  </div>
)}
```

**Mention state tracking**:

```typescript
const [mentionedUserIds, setMentionedUserIds] = useState<string[]>([]);
const [mentionQuery, setMentionQuery] = useState<string | null>(null);
const [mentionPosition, setMentionPosition] = useState({ top: 0, left: 0 });
```

### 3.7 Frontend: MessageBubble Integration

In `MessageBubble.tsx`, replace plain text rendering with MarkdownRenderer:

```tsx
{message.text && (
  <MarkdownRenderer
    text={message.text}
    format={message.format || "plain"}
    mentionedUserIds={message.mentioned_user_ids}
    className="whitespace-pre-wrap break-words"
  />
)}

{/* Link preview cards for detected URLs */}
{message.text && extractUrls(message.text).map(url => (
  <LinkPreviewCard key={url} url={url} />
))}
```

### 3.8 URL Extraction Utility

```typescript
// frontend/src/utils/urls.ts
const URL_REGEX = /https?:\/\/[^\s<>"\]]+/g;

export function extractUrls(text: string): string[] {
  const matches = text.match(URL_REGEX) || [];
  return [...new Set(matches)]; // deduplicate
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/MarkdownRenderer.tsx` | Markdown → JSX renderer |
| `frontend/src/pages/messages/MentionAutocomplete.tsx` | @mention autocomplete dropdown |
| `frontend/src/pages/messages/LinkPreviewCard.tsx` | OG link preview card |
| `frontend/src/utils/urls.ts` | URL extraction utility |
| `app/services/og_parser.py` | Mock OG metadata parser |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add `format`, `mentioned_user_ids` to send; add link-preview endpoint; mention validation |
| `app/models.py` | Extend SendTextMessageIn and MessageOut |
| `frontend/src/api/types.ts` | Add `format`, `mentioned_user_ids` to MessageOut |
| `frontend/src/api/endpoints/messaging.ts` | Add `getLinkPreview` API function |
| `frontend/src/pages/messages/ComposeBar.tsx` | Rich text toggle, live preview, mention autocomplete |
| `frontend/src/pages/messages/MessageBubble.tsx` | MarkdownRenderer + LinkPreviewCard integration |

### 4.3 Step-by-Step Order

1. Add `format` and `mentioned_user_ids` to backend message model
2. Add mention validation in send endpoint
3. Implement mock OG parser
4. Add link-preview endpoint
5. Build MarkdownRenderer component
6. Build MentionAutocomplete component
7. Build LinkPreviewCard component
8. Integrate into ComposeBar (toggle, preview, mentions)
9. Integrate into MessageBubble (rendering, link previews)
10. Add mention notifications
11. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/message-formatting.spec.ts` — 15 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let dmConvoId: string;
let groupConvoId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Create DM conversation
  // Create group conversation with Alice + Bob
});
```

### 5.3 Section 329: Markdown Message API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 329.1 | Send markdown-formatted message | POST with `format=markdown`, `text="**bold** and *italic*"`; 201; `format=markdown` in response |
| 329.2 | Plain format is default | POST without `format` field; 201; `format=plain` |
| 329.3 | Send message with mentions | POST with `mentioned_user_ids=[bob_sub]`, `text="Hey @Bob check this"`; 201; `mentioned_user_ids` populated |
| 329.4 | Reject mention of non-participant | POST with `mentioned_user_ids=[random_sub]`; 400; "not conversation participants" |

### 5.4 Section 330: Link Preview API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 330.1 | Fetch link preview for known domain | POST `/ui/messaging/link-preview` with `url=https://github.com`; 200; `title` present |
| 330.2 | Fetch link preview for unknown domain | POST with unfamiliar URL; 200; `title` is domain name |
| 330.3 | Message with URL stores text as-is | POST message with URL in text; message `text` contains full URL string |

### 5.5 Section 331: Markdown Rendering UI (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 331.1 | Bold text renders as `<strong>` | Send `**bold**` message; navigate; `<strong>` element with "bold" text visible |
| 331.2 | Italic text renders as `<em>` | Send `*italic*`; `<em>` element visible |
| 331.3 | Code block renders as `<pre><code>` | Send triple-backtick block; `<pre>` element visible |
| 331.4 | URL auto-linked in plain mode | Send `check https://example.com` with `format=plain`; link element with href visible |
| 331.5 | Link preview card appears for URL | Send message with URL; `[data-testid="link-preview-card"]` visible |

### 5.6 Section 332: Mention & Rich Text Toggle UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 332.1 | Rich text toggle switches compose mode | Click format toggle button; visual indicator changes |
| 332.2 | Live preview shows formatted text | Enable markdown mode; type `**test**`; preview shows bold "test" |
| 332.3 | Mention autocomplete appears on @ | Type "@" in compose; autocomplete dropdown with participant names visible |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Mentioned user not in conversation | 400 | "Mentioned users are not conversation participants" |
| Link preview fetch failure | 404 | "Could not fetch preview" |
| Invalid format value | 422 | Pydantic pattern validation |
| Malformed markdown | N/A | Rendered as plain text (parser ignores invalid syntax) |

---

## 7. Security Considerations

### 7.1 XSS Prevention

- MarkdownRenderer does NOT support raw HTML — only the defined markdown subset
- All text content is rendered via React JSX (auto-escaped)
- URLs in `<a>` tags are sanitized: only `http://` and `https://` protocols allowed
- `target="_blank"` with `rel="noopener noreferrer"` on all external links

### 7.2 Link Preview SSRF

- Mock OG parser in dev mode does not make HTTP requests
- Production OG parser (future) must: validate URL scheme (http/https only), deny private IP ranges, timeout after 5s, limit response size to 512KB

### 7.3 Mention Privacy

- Mentioned user IDs are validated as conversation participants
- Mention notifications only sent to actual participants
- Display names resolved client-side from conversation participant list

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Markdown parsing per message | Lightweight regex parser; memoized via React.memo on MessageBubble |
| Link preview fetching | React Query with 1-hour staleTime; lazy-loaded (only when message scrolls into view) |
| Mention autocomplete | Filters conversation participant list (typically <100 members); no API call needed |
| Live preview re-rendering | Debounced (200ms) to avoid per-keystroke rendering |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | Uses existing message infrastructure |

### 9.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| FEED-008 (Enhanced Post Composer) | MarkdownRenderer component |
