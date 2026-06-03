# MSG-012: Message Formatting & Rich Text

**Ticket**: MSG-012
**Author**: Engineering
**Status**: Implemented
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
| Sender | As a sender, I want to @mention other users in the conversation with autocomplete. | Type `@` then autocomplete dropdown of conversation participants; select inserts mention. |
| Sender | As a sender, I want to see a live preview of my formatted message as I type. | Preview panel below compose bar shows rendered output. |
| Sender | As a sender, I want to toggle between plain text and rich text mode. | Toggle button in compose bar; plain mode sends raw text; rich mode enables formatting. |
| Recipient | As a recipient, I want to see properly formatted messages. | Markdown rendered; links clickable; mentions highlighted. |

### 1.3 Why This Is Needed Now

Text-only messages are limiting for technical communication, content sharing, and expressive messaging. Markdown support is standard in Slack, Discord, and Teams. URL previews increase engagement with shared links. Mentions enable directed communication in group chats, which is critical as the platform grows group messaging usage.

---

## 2. Current State Analysis

### 2.1 Message Storage

Messages are stored with `text` field as a plain string (see `SendTextMessageIn` at `app/routers/messaging.py:1844`). The backend already auto-detects URLs and fetches OG metadata on send (see `_extract_first_url` at line 4661 and `_fetch_link_preview` at line 4674), storing the result in a `preview` field. However, there is no markdown format field or mention system. Adding markdown rendering support is primarily a frontend concern, with the raw markdown/text stored in the `text` field unchanged.

<!-- NOTE: The backend ALREADY has link preview fetching built into send_text_message (lines 7809-7815). A separate /link-preview endpoint as described later in this ticket would be supplementary (e.g., for live preview in the compose bar). -->

### 2.2 Newsfeed Rich Text

The newsfeed already supports markdown and rich text via `ContentFieldsMixin` (see `app/routers/newsfeed.py:1182`):
- `body_format`: `"plain"`, `"markdown"`, `"richtext"`
- `body_markdown`: Markdown source
- `body_rich`: Serialized rich text document (validated by `_validate_rich_body_schema` at line 1165)
- `body_markdown_html`: Pre-rendered HTML (sanitized by `_sanitize_markdown_html` at line ~1050)

However, messages do not use this mixin. For messaging, a simpler approach is preferred: store the raw text and render markdown on the frontend.

### 2.3 Mention Infrastructure

No @mention system exists in the codebase. Mentions require:
1. Frontend: Autocomplete UI that shows conversation participants when user types `@`
2. Storage: Mention metadata on the message (which user_subs are mentioned)
3. Notifications: Mentioned users receive a notification
4. Rendering: Mentioned names highlighted in message text

### 2.4 URL Detection

URL detection and link preview ALREADY EXISTS in the backend. On `send_text_message` (see `app/routers/messaging.py:7809-7815`):
1. `_extract_first_url(text)` (line 4661) extracts the first URL from message text
2. `_fetch_link_preview(url)` (line 4674) fetches OG metadata via HTTP GET
3. Result stored in message item as `preview` field (line 7815)
4. `MessageOut.preview` (line 2342) returns this data to the frontend

The frontend already receives link preview data via `MessageOut.preview`. What's MISSING:
1. **Frontend rendering** — no `LinkPreviewCard` component exists to render the `preview` data
2. **On-demand preview endpoint** — the preview is only fetched at send time; no endpoint for live preview in the compose bar
3. **URL auto-linking in rendered text** — URLs in message text are not rendered as clickable `<a>` tags

### 2.5 Gaps

1. **No markdown rendering** — message text displayed as plain text.
2. **No URL auto-linking** — URLs are plain text, not clickable.
3. **No link preview cards** — no OG metadata fetching.
4. **No @mention system** — no autocomplete, storage, or rendering.
5. **No formatting toggle** — no plain/rich mode in compose bar.
6. **No live preview** — no preview panel in compose bar.
7. **No mock OG parser** — dev mode needs deterministic OG results.

---

## 3. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                       FRONTEND (React)                                │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  ComposeBar (enhanced)                                         │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  TextArea                                                │  │  │
│  │  │  "Hey @Bob, check **this link**: https://github.com"     │  │  │
│  │  │                          ↑                                │  │  │
│  │  │                     typing "@B..."                        │  │  │
│  │  │                          ↓                                │  │  │
│  │  │  ┌────────────────────────┐                               │  │  │
│  │  │  │ MentionAutocomplete    │  ← dropdown below cursor     │  │  │
│  │  │  │  avatar Bob            │                               │  │  │
│  │  │  │  avatar Bobby          │                               │  │  │
│  │  │  └────────────────────────┘                               │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Toolbar: [Emoji] [GIF] [Sticker] [Image] [Type] [Send] │  │  │
│  │  │                                     ↑                    │  │  │
│  │  │                            RichTextToggle (plain/md)     │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Live Preview (when markdown mode enabled)               │  │  │
│  │  │  "Hey @Bob, check this link: https://github.com"         │  │  │
│  │  │        ↑bold     ↑link auto-detected  ↑mention highlight │  │  │
│  │  │                                                          │  │  │
│  │  │  MarkdownRenderer (debounced 200ms)                      │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  MessageBubble (enhanced)                                      │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  MarkdownRenderer                                        │  │  │
│  │  │  format=markdown → parse + render:                        │  │  │
│  │  │    **bold**   → <strong>bold</strong>                     │  │  │
│  │  │    *italic*   → <em>italic</em>                           │  │  │
│  │  │    ~~strike~~  → <del>strike</del>                        │  │  │
│  │  │    `code`     → <code>code</code>                         │  │  │
│  │  │    ```block```→ <pre><code>block</code></pre>             │  │  │
│  │  │    > quote    → <blockquote>quote</blockquote>            │  │  │
│  │  │    @Bob       → <span class="mention">@Bob</span>        │  │  │
│  │  │    https://   → <a href="...">https://...</a>             │  │  │
│  │  │                                                          │  │  │
│  │  │  format=plain → auto-link URLs only (no markdown parse)  │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  LinkPreviewCard (per URL, lazy-loaded)                  │  │  │
│  │  │  ┌────────────────────────────────────────────────────┐  │  │  │
│  │  │  │ [img]  GitHub: Let's build from here               │  │  │  │
│  │  │  │        GitHub is where over 100 million...          │  │  │  │
│  │  │  │        github.com                                   │  │  │  │
│  │  │  └────────────────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ HTTP
┌────────────────────────────────▼─────────────────────────────────────┐
│                       BACKEND (FastAPI)                               │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  messaging router                                              │  │
│  │                                                                │  │
│  │  POST /conversations/{id}/messages                             │  │
│  │       body: { text, format, mentioned_user_ids, ... }          │  │
│  │       → validate mentions (participants only)                  │  │
│  │       → store message with format + mentioned_user_ids         │  │
│  │       → create notification per mentioned user                 │  │
│  │                                                                │  │
│  │  POST /ui/messaging/link-preview                               │  │
│  │       body: { url }                                            │  │
│  │       → og_parser.fetch_og_metadata(url)                       │  │
│  │       → return { url, title, description, image }              │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  og_parser.py (service)                                        │  │
│  │                                                                │  │
│  │  MOCK_OG_DATA = {                                              │  │
│  │    "github.com": { title, description, image },                │  │
│  │    "example.com": { title, description, image: null },         │  │
│  │    ...                                                         │  │
│  │  }                                                             │  │
│  │                                                                │  │
│  │  fetch_og_metadata(url) → dict | None                          │  │
│  │    dev_mode → lookup MOCK_OG_DATA by domain                    │  │
│  │    prod → HTTP GET + parse <meta og:*> tags (future)           │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Messages DDB Table                                            │  │
│  │  + format: "plain" | "markdown"  (new field)                   │  │
│  │  + mentioned_user_ids: ["sub1", "sub2"]  (new field)           │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  notifications service                                         │  │
│  │  type: "message_mention"                                       │  │
│  │  → one notification per mentioned user (excluding sender)      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

**Data Flow — Sending a Markdown Message with Mentions**:
1. User enables markdown mode via RichTextToggle
2. Types `Hey @` → MentionAutocomplete shows participants filtered by query
3. Selects "Bob" → text becomes `Hey @Bob` + `mentionedUserIds` includes Bob's sub
4. Types more: `Hey @Bob, check **this link**: https://github.com`
5. Live preview renders: **this link** as bold, `@Bob` highlighted, URL as clickable link
6. User clicks Send → POST with `{ text, format: "markdown", mentioned_user_ids: [bob_sub] }`
7. Backend: validates mentioned_user_ids are conversation participants
8. Backend: stores message with `format=markdown` and `mentioned_user_ids`
9. Backend: creates notification for Bob (`type=message_mention`)
10. SSE broadcasts message → MessageBubble renders via MarkdownRenderer

**Data Flow — Link Preview**:
1. MessageBubble detects URLs in message text via `extractUrls()`
2. For each URL, `LinkPreviewCard` mounts and calls `POST /ui/messaging/link-preview`
3. Backend's `og_parser.fetch_og_metadata()` returns mock OG data for known domains
4. LinkPreviewCard renders card with title, description, image, domain
5. React Query caches result (`staleTime: 1 hour`) so subsequent renders skip API call

---

## 4. Technical Design

### 4.1 Message Format Field

Add `format` field to message items:

| Field | Type | Description |
|-------|------|-------------|
| `format` | String | `"plain"` (default) or `"markdown"` |
| `mentioned_user_ids` | List[String] | User subs mentioned in the message |

The `text` field stores the raw input (including markdown syntax). The `format` field tells the frontend how to render it.

### 4.2 DynamoDB Access Patterns

| # | Access Pattern | Table/Index | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Store formatted message | `messages` | `conversation_id` | `message_id` | `PutItem` | Includes `format` + `mentioned_user_ids` fields |
| 2 | Get message with format | `messages` | `conversation_id` | `message_id` | `GetItem` | Returns `format` field for rendering decision |
| 3 | List messages (includes format) | `messages` | `conversation_id` | — | `Query` | All messages include `format` field; default "plain" for old messages |
| 4 | Get conversation participants | `conversations` | `conversation_id` | `BEGINS_WITH "PART#"` | `Query` | For mention validation |
| 5 | Create mention notification | `notifications` | `user_sub` | `notif_id` | `PutItem` | One per mentioned user (type=message_mention) |
| 6 | Fetch OG metadata (mock) | — | — | — | In-memory | No DDB access; mock data is hardcoded in `og_parser.py` |

**Example DynamoDB Items**:

```json
// Markdown message with mentions
{
  "conversation_id": {"S": "conv_abc123"},
  "message_id": {"S": "m_def456"},
  "kind": {"S": "text"},
  "text": {"S": "Hey @Bob, check **this link**: https://github.com"},
  "format": {"S": "markdown"},
  "mentioned_user_ids": {"L": [
    {"S": "bob-sub-002"}
  ]},
  "sender_id": {"S": "alice-sub-001"},
  "created_at": {"N": "1748500000"}
}

// Plain text message (no format field — defaults to "plain")
{
  "conversation_id": {"S": "conv_abc123"},
  "message_id": {"S": "m_ghi789"},
  "kind": {"S": "text"},
  "text": {"S": "Just a regular message"},
  "sender_id": {"S": "alice-sub-001"},
  "created_at": {"N": "1748500100"}
}

// Message with code block
{
  "conversation_id": {"S": "conv_abc123"},
  "message_id": {"S": "m_jkl012"},
  "kind": {"S": "text"},
  "text": {"S": "Here is the fix:\n```python\ndef hello():\n    return 'world'\n```\nLet me know if it works"},
  "format": {"S": "markdown"},
  "mentioned_user_ids": {"L": []},
  "sender_id": {"S": "alice-sub-001"},
  "created_at": {"N": "1748500200"}
}

// Mention notification
{
  "pk": {"S": "USER#bob-sub-002"},
  "sk": {"S": "NOTIF#notif_abc123"},
  "type": {"S": "message_mention"},
  "title": {"S": "Alice mentioned you"},
  "body": {"S": "Hey @Bob, check this link: https://github.com"},
  "link": {"S": "/messages/conv_abc123"},
  "created_at": {"N": "1748500000"},
  "read": {"BOOL": false}
}
```

### 4.3 Backend Changes

#### 4.3.1 Message Send Extension

**File**: `app/routers/messaging.py` — extend `SendTextMessageIn` (line 1844)

Add new fields to the existing model:

```python
class SendTextMessageIn(BaseModel):
    text: Optional[str] = Field(default=None, min_length=1, max_length=MESSAGE_TEXT_MAX_CHARS)  # existing
    body: Optional[str] = None  # existing legacy field
    reply_to_message_id: Optional[str] = None  # existing
    preview: Optional[LinkPreviewIn] = None  # existing (line 1851)
    encryption: Optional[MessageEncryptionEnvelope] = None  # existing
    # ... other existing fields ...

    # NEW fields:
    format: str = Field(default="plain", pattern=r"^(plain|markdown)$")
    mentioned_user_ids: list[str] = Field(default_factory=list, max_length=50)
```

In `send_text_message()`:
```python
message_item = {
    # ... existing fields ...
    "format": body.format,
    "mentioned_user_ids": body.mentioned_user_ids,
}
```

#### 4.3.2 Mention Validation

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

#### 4.3.3 Mention Notifications

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

#### 4.3.4 Link Preview Endpoint (On-Demand)

<!-- NOTE: app/services/og_parser.py does NOT exist and is NOT needed. OG parsing already exists inline in messaging.py:
  - _LinkPreviewParser (HTMLParser subclass, line 4632)
  - _extract_first_url(text) at line 4661
  - _fetch_link_preview(url) at line 4674 — makes HTTP GET, parses og:title/og:description/og:image
  - LinkPreviewIn model at line 1782 (url, title, description, image_url, site_name)
  - SendTextMessageIn.preview field at line 1851
  - Auto-fetch on send at lines 7809-7815

The existing _fetch_link_preview does a real HTTP GET (not mock). In dev mode, the request may fail for external URLs but that's acceptable. A mock fallback could be added to _fetch_link_preview for dev_mode. -->

Add a standalone link-preview endpoint for the compose bar live preview:

```python
# New endpoint in app/routers/messaging.py
@router.post("/messaging/link-preview")
def get_link_preview(body: LinkPreviewUrlIn, user_id: str = Depends(get_messaging_user_id)):
    """Fetch link preview metadata for a URL (for compose bar preview)."""
    og = _fetch_link_preview(body.url)  # reuse existing function at line 4674
    if not og:
        raise HTTPException(status_code=404, detail="Could not fetch preview")
    return og

class LinkPreviewUrlIn(BaseModel):
    url: str = Field(..., max_length=2048, pattern=r"^https?://")
```

#### 4.3.5 MessageOut Extension

Add to `MessageOut` (see `app/routers/messaging.py:2325`):

```python
format: str = "plain"
mentioned_user_ids: list[str] = Field(default_factory=list)
```

Also update `_message_out_from_item()` (line 3766) to populate these fields.

### 4.4 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Optional

# ---------- Request Models ----------

class LinkPreviewIn(BaseModel):
    """Request body for fetching a link preview."""
    url: str = Field(..., max_length=2048, pattern=r"^https?://",
        description="URL to fetch Open Graph metadata for")

    model_config = {"json_schema_extra": {"examples": [
        {"url": "https://github.com"}
    ]}}

# ---------- Response Models ----------

class LinkPreviewOut(BaseModel):
    """Response with Open Graph metadata for a URL."""
    url: str = Field(..., description="Original URL")
    title: Optional[str] = Field(None, description="OG title")
    description: Optional[str] = Field(None, description="OG description")
    image: Optional[str] = Field(None, description="OG image URL")

    model_config = {"json_schema_extra": {"examples": [
        {"url": "https://github.com",
         "title": "GitHub: Let's build from here",
         "description": "GitHub is where over 100 million developers shape the future of software.",
         "image": "/mock/og/github-preview.png"}
    ]}}

class MentionNotificationOut(BaseModel):
    """Mention notification payload (internal, written to notifications table)."""
    type: str = "message_mention"
    title: str
    body: str
    link: str
    created_at: int
    read: bool = False
```

**Extended SendTextMessageIn** (additions to existing model):

```python
class SendTextMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    format: str = Field(default="plain", pattern=r"^(plain|markdown)$",
        description="Message format: 'plain' for raw text, 'markdown' for markdown rendering")
    mentioned_user_ids: list[str] = Field(default_factory=list, max_length=50,
        description="User subs of @mentioned participants")
    # ... existing fields unchanged ...

    model_config = {"json_schema_extra": {"examples": [
        {"text": "Hey @Bob, check **this link**: https://github.com",
         "format": "markdown",
         "mentioned_user_ids": ["bob-sub-002"]}
    ]}}
```

**Extended MessageOut** (additions to existing model):

```python
class MessageOut(BaseModel):
    # ... existing fields ...
    format: str = Field(default="plain",
        description="Message format: 'plain' or 'markdown'")
    mentioned_user_ids: list[str] = Field(default_factory=list,
        description="User subs mentioned in this message")
```

### 4.5 API Request/Response Examples

#### 4.5.1 Send Markdown Message with Mentions

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Hey @Bob, check **this link**: https://github.com",
    "format": "markdown",
    "mentioned_user_ids": ["bob-sub-002"]
  }' | jq .
```

**Response** (201):
```json
{
  "message_id": "m_def456ghi789",
  "conversation_id": "conv_abc123",
  "sender_id": "alice-sub-001",
  "kind": "text",
  "text": "Hey @Bob, check **this link**: https://github.com",
  "format": "markdown",
  "mentioned_user_ids": ["bob-sub-002"],
  "created_at": 1748500000,
  "reactions": {}
}
```

#### 4.5.2 Send Plain Text Message (default format)

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Just a regular message with https://example.com"
  }' | jq .
```

**Response** (201):
```json
{
  "message_id": "m_jkl012mno345",
  "conversation_id": "conv_abc123",
  "sender_id": "alice-sub-001",
  "kind": "text",
  "text": "Just a regular message with https://example.com",
  "format": "plain",
  "mentioned_user_ids": [],
  "created_at": 1748500100,
  "reactions": {}
}
```

#### 4.5.3 Send Message with Invalid Mention

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Hey @Unknown",
    "format": "markdown",
    "mentioned_user_ids": ["nonexistent-sub-999"]
  }' | jq .
```

**Response** (400):
```json
{
  "detail": "Mentioned users are not conversation participants: nonexistent-sub-999"
}
```

#### 4.5.4 Fetch Link Preview (Known Domain)

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/link-preview" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/anthropics/claude"}' \
  | jq .
```

**Response** (200):
```json
{
  "url": "https://github.com/anthropics/claude",
  "title": "GitHub: Let's build from here",
  "description": "GitHub is where over 100 million developers shape the future of software.",
  "image": "/mock/og/github-preview.png"
}
```

#### 4.5.5 Fetch Link Preview (Unknown Domain)

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/link-preview" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://my-unknown-site.com/page"}' \
  | jq .
```

**Response** (200):
```json
{
  "url": "https://my-unknown-site.com/page",
  "title": "my-unknown-site.com",
  "description": null,
  "image": null
}
```

#### 4.5.6 Send Code Block Message

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Here is the fix:\n```python\ndef hello():\n    return \"world\"\n```\nLet me know if it works",
    "format": "markdown"
  }' | jq .
```

**Response** (201):
```json
{
  "message_id": "m_pqr678stu901",
  "conversation_id": "conv_abc123",
  "sender_id": "alice-sub-001",
  "kind": "text",
  "text": "Here is the fix:\n```python\ndef hello():\n    return \"world\"\n```\nLet me know if it works",
  "format": "markdown",
  "mentioned_user_ids": [],
  "created_at": 1748500200,
  "reactions": {}
}
```

### 4.6 Frontend: Markdown Renderer

**File**: `frontend/src/components/shared/MarkdownRenderer.tsx`

A lightweight markdown-to-JSX renderer that supports:
- `**bold**` -> `<strong>`
- `*italic*` -> `<em>`
- `~~strikethrough~~` -> `<del>`
- `` `inline code` `` -> `<code>`
- ```` ```code block``` ```` -> `<pre><code>`
- `> quote` -> `<blockquote>`
- `[text](url)` -> `<a href="url">`
- URL auto-detection -> `<a href="url">`
- @mention rendering -> `<span class="mention">`

```typescript
interface MarkdownRendererProps {
  text: string;
  format: "plain" | "markdown";
  mentionedUserIds?: string[];
  className?: string;
}
```

**Implementation approach**: Use a simple regex-based parser (not a full AST parser like remark) for performance. The supported subset is small enough for regex handling. Sanitize output to prevent XSS (no raw HTML support).

### 4.7 Frontend: MentionAutocomplete

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

### 4.8 Frontend: LinkPreviewCard

**File**: `frontend/src/pages/messages/LinkPreviewCard.tsx`

```typescript
interface LinkPreviewCardProps {
  url: string;
}
```

- Fetches OG metadata via `POST /ui/messaging/link-preview`
- Renders card with: title, description (truncated), image (if available), domain name
- Clickable opens URL in new tab
- Loading skeleton while fetching
- Cached per URL via React Query (staleTime: 1 hour)
- `data-testid="link-preview-card"`

### 4.9 Frontend Component Tree

```
ComposeBar (enhanced)
├── TextAreaWrapper
│   ├── TextArea (existing, enhanced with @ detection)
│   │   └── onKeyDown: detect "@" trigger → show MentionAutocomplete
│   └── MentionAutocomplete (positioned below cursor)
│       ├── FilteredParticipantList
│       │   └── ParticipantRow[] (avatar + display_name)
│       ├── KeyboardNavigation (ArrowUp/Down + Enter + Escape)
│       └── data-testid="mention-autocomplete"
│
├── ToolbarRow
│   ├── ... (existing buttons)
│   ├── RichTextToggle (new — Type icon)
│   │   ├── State: formatMode ("plain" | "markdown")
│   │   ├── Active indicator (variant=default when markdown)
│   │   └── Tooltip: "Switch to rich text" / "Switch to plain text"
│   └── SendButton (existing)
│
├── LivePreview (shown when formatMode="markdown" and text.trim())
│   ├── MarkdownRenderer
│   │   ├── text: current textarea value
│   │   ├── format: "markdown"
│   │   └── debounced: 200ms
│   └── className: "border-t p-2 text-sm max-h-24 overflow-y-auto bg-muted/30"
│
└── MentionState
    ├── mentionedUserIds: string[] (accumulated from selections)
    ├── mentionQuery: string | null (text after "@")
    └── mentionPosition: { top, left } (cursor position)

MessageBubble (enhanced)
├── ContentArea
│   └── MarkdownRenderer (replaces plain text rendering)
│       ├── text: message.text
│       ├── format: message.format || "plain"
│       ├── mentionedUserIds: message.mentioned_user_ids
│       └── Renders:
│           ├── <strong> for **bold**
│           ├── <em> for *italic*
│           ├── <del> for ~~strikethrough~~
│           ├── <code> for `inline code`
│           ├── <pre><code> for ```code blocks```
│           ├── <blockquote> for > quotes
│           ├── <a> for [text](url) and auto-detected URLs
│           └── <span class="mention bg-primary/10 text-primary rounded px-1">
│               for @mentions
│
├── LinkPreviewCards (per URL detected in text)
│   └── LinkPreviewCard[]
│       ├── useQuery(["link-preview", url])
│       ├── LoadingSkeleton (h-20 w-full)
│       ├── CardContent
│       │   ├── Image (optional, left side)
│       │   ├── Title (truncated to 1 line)
│       │   ├── Description (truncated to 2 lines)
│       │   └── Domain (muted text)
│       └── data-testid="link-preview-card"
│
└── ... (existing: ReactionBar, MessageMeta)

MarkdownRenderer (shared component)
├── Props: { text, format, mentionedUserIds?, className? }
├── Parsing pipeline (memoized):
│   1. Escape HTML entities (prevent XSS)
│   2. Extract code blocks (```...```) → placeholder tokens
│   3. Parse inline: **bold**, *italic*, ~~strike~~, `code`
│   4. Parse [text](url) links
│   5. Auto-detect bare URLs → <a> tags
│   6. Parse @mention references → <span class="mention">
│   7. Parse > quote lines → <blockquote>
│   8. Replace code block placeholders with <pre><code>
│   9. Convert \n to <br> (outside code blocks)
└── Output: React.ReactNode[]
```

**State Management (ComposeBar)**:
```typescript
const [formatMode, setFormatMode] = useState<"plain" | "markdown">(
  () => localStorage.getItem("compose-format") || "plain"
);
const [mentionedUserIds, setMentionedUserIds] = useState<string[]>([]);
const [mentionQuery, setMentionQuery] = useState<string | null>(null);
const [mentionPosition, setMentionPosition] = useState({ top: 0, left: 0 });

// Persist format mode
useEffect(() => {
  localStorage.setItem("compose-format", formatMode);
}, [formatMode]);

// Send handler includes format + mentions
const handleSend = () => {
  sendMessageMut.mutate({
    text: inputValue,
    format: formatMode,
    mentioned_user_ids: mentionedUserIds,
    // ... existing fields ...
  });
  setMentionedUserIds([]);
};
```

### 4.10 URL Extraction Utility

```typescript
// frontend/src/utils/urls.ts
const URL_REGEX = /https?:\/\/[^\s<>"\])+/g;

export function extractUrls(text: string): string[] {
  const matches = text.match(URL_REGEX) || [];
  return [...new Set(matches)]; // deduplicate
}
```

---

## 5. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|-----------------|
| 1 | Mentioned user not in conversation | 400 | `invalid_mentions` | "Mentioned users are not conversation participants: user1, user2" | Remove invalid mentions before sending |
| 2 | Link preview fetch failure (prod) | 404 | `preview_not_found` | "Could not fetch preview" | No preview shown for this URL |
| 3 | Invalid format value | 422 | `validation_error` | "format must be 'plain' or 'markdown'" | Use a valid format value |
| 4 | Malformed markdown | N/A | — | (Rendered as plain text; parser ignores invalid syntax) | No error; graceful degradation |
| 5 | URL not http/https | 422 | `validation_error` | "URL must start with http:// or https://" | Use a valid URL scheme |
| 6 | Link preview URL too long (>2048) | 422 | `validation_error` | "URL is too long" | Use a shorter URL |
| 7 | Too many mentions (>50) | 422 | `validation_error` | "Maximum 50 mentions per message" | Reduce the number of @mentions |
| 8 | Self-mention | 200 | — | (Allowed; no notification for self) | No restriction |
| 9 | Mention in plain format | 200 | — | (mentioned_user_ids stored; no special rendering in plain mode) | Switch to markdown to see highlight |
| 10 | Code block with unsupported language | 200 | — | (Rendered as plain code block; language hint ignored) | No syntax highlighting; future enhancement |
| 11 | Link preview rate limit | 429 | `rate_limit` | "Too many link preview requests" | Wait and retry |
| 12 | Message text >10000 chars | 422 | `validation_error` | "Message must be 10000 characters or fewer" | Shorten the message |

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/MarkdownRenderer.tsx` | Markdown to JSX renderer |
| `frontend/src/pages/messages/MentionAutocomplete.tsx` | @mention autocomplete dropdown |
| `frontend/src/pages/messages/LinkPreviewCard.tsx` | OG link preview card (renders existing `MessageOut.preview` data) |
| `frontend/src/utils/urls.ts` | URL extraction utility |

<!-- NOTE: app/services/og_parser.py is NOT needed as a separate file. OG parsing already exists inline in messaging.py (see _LinkPreviewParser at line 4632, _fetch_link_preview at line 4674). A mock fallback for dev_mode can be added directly to _fetch_link_preview. -->

### 6.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add `format`, `mentioned_user_ids` to `SendTextMessageIn` (line 1844) and `MessageOut` (line 2325); add link-preview endpoint; mention validation in `send_text_message` (line 7684) |
| `frontend/src/api/types.ts` | Add `format`, `mentioned_user_ids` to `MessageOut` interface |
| `frontend/src/api/endpoints/messaging.ts` | Add `getLinkPreview` API function |
| `frontend/src/pages/messages/ComposeBar.tsx` | Rich text toggle, live preview, mention autocomplete |
| `frontend/src/pages/messages/MessageBubble.tsx` | MarkdownRenderer + LinkPreviewCard integration |

<!-- NOTE: app/models.py is NOT the correct location — all messaging Pydantic models are in app/routers/messaging.py (e.g., SendTextMessageIn at line 1844, MessageOut at line 2325). -->

### 6.3 Step-by-Step Order

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

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `msg012_markdown_message_sent_total` | Counter | — | Messages sent with format=markdown |
| `msg012_plain_message_sent_total` | Counter | — | Messages sent with format=plain |
| `msg012_mention_count_per_message` | Histogram | — | Number of @mentions per message |
| `msg012_link_preview_fetched_total` | Counter | `status` (hit/miss) | Link preview API calls |
| `msg012_link_preview_latency_ms` | Histogram | — | Link preview fetch time |
| `msg012_mention_notification_sent_total` | Counter | — | Mention notifications created |

### 7.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `message.markdown.sent` | INFO | `user_sub`, `conversation_id`, `mention_count` | Markdown message sent |
| `message.mention.notification` | INFO | `mentioned_sub`, `sender_sub`, `conversation_id` | Mention notification created |
| `message.mention.invalid` | WARN | `user_sub`, `invalid_subs` | Attempt to mention non-participants |
| `link_preview.fetched` | DEBUG | `url`, `domain`, `has_image` | Link preview data fetched |
| `link_preview.cache_hit` | DEBUG | `url` | Link preview served from cache |

### 7.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Markdown adoption < 5% after 7d | `msg012_markdown_message_sent / total_messages < 0.05` after 7 days | Info | UX review; consider making markdown default |
| Link preview latency p95 > 2s | `histogram_quantile(0.95, msg012_link_preview_latency_ms) > 2000` | Warning | Check OG parser; add caching layer |
| Mention validation failure rate > 10% | Frequent invalid mention attempts | Info | Check frontend mention autocomplete; may have stale participant list |

### 7.4 Dashboard Queries

```promql
# Markdown vs plain message ratio
sum(increase(msg012_markdown_message_sent_total[24h]))
  / (sum(increase(msg012_markdown_message_sent_total[24h]))
     + sum(increase(msg012_plain_message_sent_total[24h])))

# Mention usage per day
sum(increase(msg012_mention_notification_sent_total[24h]))

# Link preview hit rate
sum(increase(msg012_link_preview_fetched_total{status="hit"}[24h]))
  / sum(increase(msg012_link_preview_fetched_total[24h]))
```

---

## 8. Rollout Plan

### 8.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `MSG012_MARKDOWN_ENABLED` | `false` | Enable markdown toggle in ComposeBar + rendering in MessageBubble |
| `MSG012_LINK_PREVIEW_ENABLED` | `false` | Enable link preview cards |
| `MSG012_MENTIONS_ENABLED` | `false` | Enable @mention autocomplete + notifications |

### 8.2 Rollout Phases

| Phase | Duration | Actions |
|-------|----------|---------|
| 1. Backend deploy | Day 1 | Deploy `format` field on messages + link-preview endpoint + mention validation. Flags OFF. Old messages default to `format=plain`. |
| 2. Markdown rendering | Day 2-3 | Enable `MSG012_MARKDOWN_ENABLED`. Users can toggle markdown mode; messages render formatted. Monitor MarkdownRenderer performance (no XSS). |
| 3. Link previews | Day 4-5 | Enable `MSG012_LINK_PREVIEW_ENABLED`. LinkPreviewCard renders for URLs. Monitor API call volume and latency. |
| 4. Mentions | Day 6-8 | Enable `MSG012_MENTIONS_ENABLED`. MentionAutocomplete active in compose. Mention notifications sent. Monitor notification volume. |
| 5. GA | Day 9 | Remove feature flags. All features enabled. |

### 8.3 Rollback Procedure

1. **Markdown rendering**: Disable `MSG012_MARKDOWN_ENABLED`. Messages with `format=markdown` are stored raw; frontend renders them as plain text (markdown syntax visible but not rendered). No data loss.
2. **Link previews**: Disable `MSG012_LINK_PREVIEW_ENABLED`. LinkPreviewCard components hidden. URLs still auto-linked in message text. No data impact.
3. **Mentions**: Disable `MSG012_MENTIONS_ENABLED`. MentionAutocomplete hidden. `mentioned_user_ids` still stored on messages but no highlighting. Mention notifications stop. Existing notifications remain delivered.
4. **Full rollback**: Revert backend deploy. `format` field ignored (defaults to "plain"). `mentioned_user_ids` field ignored. Link preview endpoint returns 404 (frontend gracefully hides card).

---

## 9. Performance Considerations

| # | Concern | Impact | Mitigation |
|---|---------|--------|------------|
| 1 | Markdown parsing per message | CPU cost on render for each message | Lightweight regex parser; memoized via `React.memo` on MessageBubble and `useMemo` on parsed output. Parse time: <1ms for typical messages (<1000 chars). |
| 2 | Link preview fetching | N API calls per message with N URLs | React Query with `staleTime: 3600000` (1 hour). Lazy-loaded via IntersectionObserver (only fetch when message scrolls into view). Max 3 previews per message. |
| 3 | Mention autocomplete | Filtering participant list on every keystroke after `@` | Conversation participant list typically <100 members. `Array.filter()` with string prefix match is O(N) — negligible. No API call needed (participants already in React Query cache). |
| 4 | Live preview re-rendering | Re-render on every keystroke in markdown mode | Debounced at 200ms. MarkdownRenderer wrapped in `React.memo`. Only renders when debounced text value changes. |
| 5 | MentionAutocomplete positioning | Computing cursor position in textarea | Use `textarea.selectionStart` + measurement span technique. Compute position once on `@` trigger, not on every keystroke. |
| 6 | Link preview SSRF (production) | Fetching arbitrary URLs server-side | Mock mode: no HTTP requests (in-memory lookup). Production: URL allowlist, private IP denial, 5s timeout, 512KB response limit. |
| 7 | Large messages with many URLs | 10+ URLs = 10+ link preview cards | Limit to 3 link preview cards per message. Show "N more links" text for additional URLs. |
| 8 | Code block rendering | Large code blocks may cause layout issues | `max-height: 300px` with `overflow-y: auto` on `<pre>` elements. No syntax highlighting (avoids heavy parsing library). |
| 9 | Mention notification volume | Group chat with 50 participants; mention @all | No `@all` support in v1. Max 50 mentioned_user_ids per message. Notifications are fire-and-forget DDB writes (no blocking). |

---

## 10. E2E Test Plan

### 10.1 Test File

`frontend/e2e/message-formatting.spec.ts` — 21 tests across 5 sections.

### 10.2 Test Setup

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

### 10.3 Section 329: Markdown Message API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 329.1 | Send markdown-formatted message | POST with `format=markdown`, `text="**bold** and *italic*"`; 201; `format=markdown` in response |
| 329.2 | Plain format is default | POST without `format` field; 201; `format=plain` |
| 329.3 | Send message with mentions | POST with `mentioned_user_ids=[bob_sub]`, `text="Hey @Bob check this"`; 201; `mentioned_user_ids` populated |
| 329.4 | Reject mention of non-participant | POST with `mentioned_user_ids=[random_sub]`; 400; "not conversation participants" |
| 329.5 | Send message with code block | POST with triple-backtick text; 201; text stored as-is with newlines preserved |

### 10.4 Section 330: Link Preview API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 330.1 | Fetch link preview for known domain | POST `/ui/messaging/link-preview` with `url=https://github.com`; 200; `title` present |
| 330.2 | Fetch link preview for unknown domain | POST with unfamiliar URL; 200; `title` is domain name |
| 330.3 | Message with URL stores text as-is | POST message with URL in text; message `text` contains full URL string |
| 330.4 | Link preview rejects non-http URL | POST with `url=ftp://example.com`; 422 |

### 10.5 Section 331: Markdown Rendering UI (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 331.1 | Bold text renders as `<strong>` | Send `**bold**` message; navigate; `<strong>` element with "bold" text visible |
| 331.2 | Italic text renders as `<em>` | Send `*italic*`; `<em>` element visible |
| 331.3 | Strikethrough renders as `<del>` | Send `~~deleted~~`; `<del>` element visible |
| 331.4 | Code block renders as `<pre><code>` | Send triple-backtick block; `<pre>` element visible |
| 331.5 | URL auto-linked in plain mode | Send `check https://example.com` with `format=plain`; link element with href visible |
| 331.6 | Link preview card appears for URL | Send message with URL; `[data-testid="link-preview-card"]` visible |

### 10.6 Section 332: Mention & Rich Text Toggle UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 332.1 | Rich text toggle switches compose mode | Click format toggle button; visual indicator changes |
| 332.2 | Live preview shows formatted text | Enable markdown mode; type `**test**`; preview shows bold "test" |
| 332.3 | Mention autocomplete appears on @ | Type "@" in compose; autocomplete dropdown with participant names visible |

### 10.7 Section 333: Edge Cases & Negative Tests (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 333.1 | XSS in markdown is escaped | Send `<script>alert("xss")</script>`; no script execution; text rendered as literal |
| 333.2 | Nested formatting renders correctly | Send `***bold italic***`; both `<strong>` and `<em>` present |
| 333.3 | Empty mentions list accepted | POST with `mentioned_user_ids: []`; 201; no notifications |

---

## 11. Security Considerations

### 11.1 XSS Prevention

- MarkdownRenderer does NOT support raw HTML — only the defined markdown subset
- All text content is rendered via React JSX (auto-escaped)
- URLs in `<a>` tags are sanitized: only `http://` and `https://` protocols allowed
- `target="_blank"` with `rel="noopener noreferrer"` on all external links

### 11.2 Link Preview SSRF

- Mock OG parser in dev mode does not make HTTP requests
- Production OG parser (future) must: validate URL scheme (http/https only), deny private IP ranges, timeout after 5s, limit response size to 512KB

### 11.3 Mention Privacy

- Mentioned user IDs are validated as conversation participants
- Mention notifications only sent to actual participants
- Display names resolved client-side from conversation participant list

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | Uses existing message infrastructure |

### 12.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| FEED-008 (Enhanced Post Composer) | MarkdownRenderer component |

---

## Codebase References

### Backend — `app/routers/messaging.py`
| Reference | Line | Notes |
|-----------|------|-------|
| `LinkPreviewIn` model | 1782 | Existing model: `url`, `title`, `description`, `image_url`, `site_name` |
| `SendTextMessageIn` | 1844 | Existing model to extend with `format` and `mentioned_user_ids` fields |
| `SendTextMessageIn.preview` | 1851 | Already accepts `Optional[LinkPreviewIn]` |
| `MessageOut` class | 2325 | Add `format` and `mentioned_user_ids` fields |
| `MessageOut.preview` | 2342 | Already returns `Optional[Dict[str, Any]]` for link previews |
| `_message_out_from_item(message_item, viewer_user_id)` | 3766 | Extend to populate `format` and `mentioned_user_ids` |
| `_LinkPreviewParser` (HTMLParser) | 4632 | Existing OG tag parser (parses og:title, og:description, og:image, og:site_name) |
| `_extract_first_url(text)` | 4661 | Existing URL detection via regex |
| `_fetch_link_preview(url)` | 4674 | Existing OG metadata fetcher (HTTP GET + parse HTML) |
| Auto-fetch on send | 7809-7815 | `_serialize_preview` or `_extract_first_url` + `_fetch_link_preview` on `send_text_message` |
| `send_text_message()` | 7684 | Main send endpoint; add mention validation and `format` storage here |

### Backend — `app/routers/newsfeed.py`
| Reference | Line | Notes |
|-----------|------|-------|
| `ContentFieldsMixin` | 1182 | Rich text support for newsfeed (body_format, body_markdown, body_rich) — NOT used for messaging, but a reference pattern |

### Frontend — Existing Files to Modify
| File | Notes |
|------|-------|
| `frontend/src/pages/messages/MessageBubble.tsx` | Integrate MarkdownRenderer + LinkPreviewCard for `message.preview` data |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add RichTextToggle, MentionAutocomplete, live preview panel |
| `frontend/src/api/types.ts` | Add `format`, `mentioned_user_ids` to `MessageOut` interface |
| `frontend/src/api/endpoints/messaging.ts` | Add `getLinkPreview()` API function |

### Frontend — New Files
| File | Notes |
|------|-------|
| `frontend/src/components/shared/MarkdownRenderer.tsx` | New — markdown-to-JSX renderer |
| `frontend/src/pages/messages/MentionAutocomplete.tsx` | New — @mention autocomplete dropdown |
| `frontend/src/pages/messages/LinkPreviewCard.tsx` | New — renders `MessageOut.preview` data as a card |
| `frontend/src/utils/urls.ts` | New — URL extraction utility for compose bar |

### DynamoDB Tables
| Table | Notes |
|-------|-------|
| `Messages` (PK: `conversation_id`, SK: `message_id`) | Add `format` and `mentioned_user_ids` fields to message items |

### Corrections Applied
| Original Claim | Correction |
|----------------|------------|
| "No URL detection or link preview system exists" | URL detection (`_extract_first_url` at line 4661) and OG fetching (`_fetch_link_preview` at line 4674) ALREADY EXIST; previews auto-fetched on send and stored in `preview` field |
| `app/services/og_parser.py` as new file | Not needed — OG parsing is inline in `messaging.py` (lines 4632-4722); reuse `_fetch_link_preview` for the new endpoint |
| `app/models.py` in files to modify | All messaging models are in `app/routers/messaging.py`, not `app/models.py` |
| `MessageOut.preview` does not exist | It already exists at line 2342 as `Optional[Dict[str, Any]]` |
| `SendTextMessageIn` needs `preview` field added | Already has `preview: Optional[LinkPreviewIn]` at line 1851 |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_message_formatting.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_send_markdown_message` | POST format=markdown; 201; format=markdown in response |
| 2 | `test_default_format_plain` | POST without format; format=plain |
| 3 | `test_mentions_non_participant_rejected` | mentioned_user_ids with non-participant; 400 |
| 4 | `test_mentions_empty_list` | mentioned_user_ids=[]; 201 |
| 5 | `test_mention_creates_notification` | Mention Bob; notification created |
| 6 | `test_link_preview_valid_url` | POST /link-preview known URL; 200; title present |
| 7 | `test_link_preview_invalid_scheme` | POST ftp:// URL; 422 |
| 8 | `test_mentions_over_50_rejected` | >50 mentions; 422 |
| 9 | `test_self_mention_no_notification` | Mention self; no notification |

Moto-mocked DynamoDB. Existing `_fetch_link_preview` reused.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Mention creates notification | messaging router + notifications table |
| 2 | Link preview auto-fetched on send | messaging router + _fetch_link_preview |
| 3 | Format field persisted and returned | messaging router + Messages table |

### E2E Tests (Playwright)

**File**: `frontend/e2e/message-formatting.spec.ts` -- 21 tests, sections 329-333

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF for POST.

| Section | Tests | Key Assertions |
|---------|-------|----------------|
| 329 | 5 | Markdown API: markdown format (201), plain default, mentions, non-participant (400), code block |
| 330 | 4 | Link preview: known domain (200), unknown domain, text preserved, non-http (422) |
| 331 | 6 | Rendering: bold strong, italic em, strike del, code pre, URL auto-linked, preview card |
| 332 | 3 | Toggle & mention: format toggle, live preview, @ autocomplete |
| 333 | 3 | Edge cases: XSS escaped, nested formatting, empty mentions |

**Negative tests**: 400 non-participant mention, 422 non-http URL, 422 >50 mentions.

### Test Data Requirements

- DDB seeds: Messages, Conversations, Participants, Notifications
- Test users: Alice, Bob

### CI/Pipeline

- Feature flags: `MSG012_MARKDOWN_ENABLED`, `MSG012_LINK_PREVIEW_ENABLED`, `MSG012_MENTIONS_ENABLED`
- Serial execution, retry-safe with unique text prefixes


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Uses existing message + link preview infrastructure |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| FEED-008 | Component | MarkdownRenderer shared with enhanced post composer |

### Merge Strategy

**Independent** -- No prerequisites. Feature flags gate each sub-feature.

### Merge Checklist

- [ ] `format` and `mentioned_user_ids` on SendTextMessageIn and MessageOut
- [ ] Mention validation in send_text_message
- [ ] Link preview endpoint added
- [ ] MarkdownRenderer.tsx, MentionAutocomplete.tsx, LinkPreviewCard.tsx created
- [ ] ComposeBar integrates toggle, preview, autocomplete
- [ ] E2E pass: `npx playwright test e2e/message-formatting.spec.ts`
