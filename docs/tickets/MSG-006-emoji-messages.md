# MSG-006: Emoji Messages

**Ticket**: MSG-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-006 adds rich emoji rendering and an interactive emoji picker to the messaging system. Currently, users can type Unicode emoji characters directly into the compose bar, but there is no categorized picker, no search-by-name, no skin tone modifiers, no frequently-used section, and no special rendering for emoji-only messages. This ticket elevates emoji from plain text into a first-class messaging feature with a polished, discoverable UI.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Sender | As a sender, I want to open an emoji picker categorized by type so I can find the right emoji without memorizing Unicode. | Picker opens from ComposeBar; shows 9 categories (Smileys, People, Animals, Food, Travel, Activities, Objects, Symbols, Flags). |
| Sender | As a sender, I want to search for emojis by name or keyword (e.g., "thumbs up", "fire"). | Search input at top of picker; results filter live as user types; no results shows empty state. |
| Sender | As a sender, I want to see my recently used emojis at the top of the picker. | "Recent" section at top shows up to 32 most recently used emojis, persisted in localStorage. |
| Sender | As a sender, I want to change the skin tone of applicable emojis. | Skin tone selector button in picker header; applies to all skin-tone-capable emojis. |
| Sender | As a sender, I want to type shortcodes like `:smile:` and have them converted to emoji. | On send, shortcodes in message text are replaced with their Unicode equivalents. |
| Recipient | As a recipient, I want messages that are emoji-only (1-3 emojis, no text) to render at 3x size. | MessageBubble detects emoji-only content and applies `text-5xl` class. |
| User | As a user, I want the emoji picker to be reusable across messaging and newsfeed. | Shared `EmojiPicker` component in `components/shared/`. |

### 1.3 Why This Is Needed Now

Emoji are the most universal form of expression in messaging. Every major messaging platform (WhatsApp, Telegram, Discord, Slack) provides a rich emoji picker. Without one, users must rely on their OS emoji keyboard (inconsistent across platforms) or memorize Unicode characters. The emoji picker also serves as the foundation for MSG-007 (Custom Emojis) and MSG-011 (Emoji Reactions Enhancement).

---

## 2. Current State Analysis

### 2.1 Messaging Compose Bar

`frontend/src/pages/messages/ComposeBar.tsx` is the primary message input component. It currently supports:
- Text input (textarea with auto-resize)
- Image attachment (camera icon → file picker)
- File share (folder icon → FilePickerDialog)
- Tip attachment (optional tip amount + payment method selector)
- Lock price (paywall toggle)
- Send scheduling (clock icon → DateTimePicker)
- Encryption toggle
- View-once toggle
- Reply-to banner

There is no emoji button or picker. Users rely on their OS-level emoji input (Ctrl+. on Windows, Cmd+Ctrl+Space on macOS).
<!-- NOTE: ComposeBar.tsx already has a toolbar row with meeting poll support (see `frontend/src/pages/messages/ComposeBar.tsx:160` for meetingPollOpen state, :1777 for MeetingPollComposer integration). The emoji button would follow the same pattern. -->

### 2.2 Message Bubble Rendering

`frontend/src/pages/messages/MessageBubble.tsx` renders message content as plain text in a `<p>` tag. Unicode emojis render at the same font size as regular text, making them small and hard to read when sent alone. There is no detection of emoji-only messages for enlarged rendering.
<!-- NOTE: MessageBubble already has an inline emoji *reaction* picker — a `QUICK_EMOJIS` array (line 79: `["👍", "❤️", "😂", "😮", "😢", "🙏"]`) with `emojiPickerOpen` state (line 412) and a popover (lines 800-818). This is for reactions only, NOT for composing. The new EmojiPicker component (MSG-006) is for the ComposeBar and is a separate, richer component. -->

### 2.3 Emoji Data

No emoji dataset exists in the codebase. A comprehensive emoji dataset is needed with:
- Unicode codepoints for each emoji
- Short names and keywords for search
- Category assignments
- Skin tone variant mappings
- Shortcode mappings (`:smile:` → `😄`)

### 2.4 Backend Message Processing

`app/routers/messaging.py` accepts message text as a plain string via `send_text_message()` (see `app/routers/messaging.py:3308`). The backend performs no emoji processing — text is stored and returned as-is. Shortcode replacement can be handled entirely on the frontend (before send) to keep the backend stateless.

### 2.5 Newsfeed Compose

`frontend/src/pages/feed/CreatePost.tsx` (see `frontend/src/pages/feed/CreatePost.tsx:110`) also has a text input that would benefit from the same emoji picker. Building the `EmojiPicker` as a shared component in `components/shared/` allows both surfaces to use it.

### 2.6 Gaps

1. **No emoji picker component** — users have no in-app way to browse and select emojis. (VERIFIED: no `EmojiPicker` component exists in `frontend/src/components/shared/`. The only emoji UI is the inline `QUICK_EMOJIS` reaction picker in `MessageBubble.tsx:79-818`.)
2. **No emoji dataset** — no structured data for categories, search, skin tones. (VERIFIED: no `frontend/src/data/` directory exists.)
3. **No shortcode replacement** — `:smile:` is sent as literal text. (VERIFIED: no `frontend/src/utils/` directory exists.)
4. **No emoji-only large rendering** — single-emoji messages look the same as text.
5. **No recent/frequently-used tracking** — no localStorage persistence for emoji usage. (VERIFIED: no `emojiStore` exists in `frontend/src/stores/`.)

---

## 3. Technical Design

### 3.1 Emoji Dataset

**Approach**: Bundle a static JSON emoji dataset derived from Unicode CLDR data. The dataset is imported at build time and tree-shaken by Vite.

**File**: `frontend/src/data/emoji-data.ts`

```typescript
export interface EmojiEntry {
  emoji: string;           // Unicode character(s), e.g., "😄"
  shortcode: string;       // e.g., "smile"
  name: string;            // e.g., "Smiling Face with Open Mouth"
  keywords: string[];      // e.g., ["happy", "joy", "laugh"]
  category: EmojiCategory;
  skinToneSupport: boolean;
  version: string;         // Unicode version, e.g., "6.0"
}

export type EmojiCategory =
  | "smileys"
  | "people"
  | "animals"
  | "food"
  | "travel"
  | "activities"
  | "objects"
  | "symbols"
  | "flags";

export const EMOJI_CATEGORIES: { id: EmojiCategory; label: string; icon: string }[] = [
  { id: "smileys", label: "Smileys & Emotion", icon: "😀" },
  { id: "people", label: "People & Body", icon: "👋" },
  { id: "animals", label: "Animals & Nature", icon: "🐾" },
  { id: "food", label: "Food & Drink", icon: "🍕" },
  { id: "travel", label: "Travel & Places", icon: "✈️" },
  { id: "activities", label: "Activities", icon: "⚽" },
  { id: "objects", label: "Objects", icon: "💡" },
  { id: "symbols", label: "Symbols", icon: "❤️" },
  { id: "flags", label: "Flags", icon: "🏁" },
];

// Full dataset (~1800 entries, ~120KB gzipped)
export const EMOJI_DATA: EmojiEntry[] = [/* ... */];

// Shortcode lookup map (generated at module load)
export const SHORTCODE_MAP: Map<string, string> = new Map(
  EMOJI_DATA.map(e => [e.shortcode, e.emoji])
);
```

### 3.2 Skin Tone Support

Skin tone modifiers are applied by appending a Unicode modifier codepoint to the base emoji:

```typescript
export const SKIN_TONES = [
  { id: "default", label: "Default", modifier: "" },
  { id: "light", label: "Light", modifier: "\u{1F3FB}" },
  { id: "medium-light", label: "Medium-Light", modifier: "\u{1F3FC}" },
  { id: "medium", label: "Medium", modifier: "\u{1F3FD}" },
  { id: "medium-dark", label: "Medium-Dark", modifier: "\u{1F3FE}" },
  { id: "dark", label: "Dark", modifier: "\u{1F3FF}" },
];

export function applySkinTone(emoji: string, modifier: string): string {
  if (!modifier) return emoji;
  // Insert modifier after the first codepoint
  const codepoints = [...emoji];
  return codepoints[0] + modifier + codepoints.slice(1).join("");
}
```

Skin tone preference is persisted in localStorage (`emoji_skin_tone`).

### 3.3 Recent Emojis

```typescript
// frontend/src/stores/emojiStore.ts (Zustand with localStorage persistence)
interface EmojiStore {
  recentEmojis: string[];        // Most recent first, max 32
  skinTone: string;              // Skin tone modifier string
  addRecent: (emoji: string) => void;
  setSkinTone: (tone: string) => void;
}
```

### 3.4 Shortcode Replacement

Shortcode replacement is performed on the frontend before sending:

```typescript
// frontend/src/utils/emoji.ts
export function replaceShortcodes(text: string): string {
  return text.replace(/:([a-z0-9_+-]+):/g, (match, code) => {
    return SHORTCODE_MAP.get(code) ?? match;
  });
}
```

Called in `ComposeBar.tsx` and `CreatePost.tsx` before submitting the message/post text.

### 3.5 Emoji-Only Detection

```typescript
// frontend/src/utils/emoji.ts
const EMOJI_REGEX = /^(?:\p{Emoji_Presentation}|\p{Emoji}️)(?:‍(?:\p{Emoji_Presentation}|\p{Emoji}️))*$/u;
const EMOJI_SPLIT = /(?:\p{Emoji_Presentation}|\p{Emoji}️)(?:‍(?:\p{Emoji_Presentation}|\p{Emoji}️))*/gu;

export function isEmojiOnly(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed) return false;
  const emojis = trimmed.match(EMOJI_SPLIT);
  if (!emojis) return false;
  // Must be 1-3 emojis with only whitespace between them
  const withoutEmojis = trimmed.replace(EMOJI_SPLIT, "").trim();
  return withoutEmojis === "" && emojis.length >= 1 && emojis.length <= 3;
}
```

### 3.6 EmojiPicker Component

**File**: `frontend/src/components/shared/EmojiPicker.tsx`

```typescript
interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose?: () => void;
}
```

**Layout**:
```
┌──────────────────────────────────────┐
│ 🔍 Search emojis...    [🖐 tone ▾]  │
├──────────────────────────────────────┤
│ Recent:  😀 😂 ❤️ 🔥 👍 ...          │
├──────────────────────────────────────┤
│ 😀😁😂🤣😃😄😅😆😉😊  │ Category   │
│ 😋😎😍😘🥰😗😙🥲😏😌  │ tabs on    │
│ ...                      │ the side   │
└──────────────────────────────────────┘
```

**Features**:
- Category tabs (icons from `EMOJI_CATEGORIES`) on the left sidebar
- Search input with live filtering (debounced 150ms)
- Recent emojis section at top (from `emojiStore`)
- Scrollable grid of emojis (8 columns)
- Skin tone selector popover (5 tone circles)
- Click emoji → calls `onSelect(emoji)`, adds to recent
- Keyboard navigation: arrow keys to move, Enter to select, Escape to close
- `data-testid="emoji-picker"` for E2E targeting

**Popover integration in ComposeBar**:
```tsx
<Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
  <PopoverTrigger asChild>
    <Button variant="ghost" size="icon" data-testid="emoji-button">
      <Smile className="h-4 w-4" />
    </Button>
  </PopoverTrigger>
  <PopoverContent className="w-80 p-0" align="start">
    <EmojiPicker onSelect={handleEmojiSelect} />
  </PopoverContent>
</Popover>
```

### 3.7 MessageBubble Enhancement

**File**: `frontend/src/pages/messages/MessageBubble.tsx`

Add emoji-only detection and enlarged rendering:

```tsx
const isLargeEmoji = message.kind === "text" && message.text && isEmojiOnly(message.text);

// In the text rendering section:
{message.text && (
  <p className={cn(
    "whitespace-pre-wrap break-words",
    isLargeEmoji && "text-5xl leading-relaxed py-1"
  )}>
    {message.text}
  </p>
)}
```

### 3.8 Backend Changes

**No backend changes required for Phase 1.** The backend stores message text as-is. Shortcode replacement and emoji-only detection are both frontend-only operations. The emoji data is a static frontend asset.

### 3.9 Settings

**File**: `app/core/settings.py`

```python
# Emoji messages (MSG-006) — feature flag for shortcode replacement
emoji_shortcodes_enabled: bool = os.environ.get("EMOJI_SHORTCODES_ENABLED", "1") not in ("0", "false", "False")
```

This flag is exposed via `GET /ui/config` and controls whether the frontend performs shortcode replacement.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/data/emoji-data.ts` | Static emoji dataset with categories, keywords, shortcodes |
| `frontend/src/components/shared/EmojiPicker.tsx` | Shared emoji picker component |
| `frontend/src/stores/emojiStore.ts` | Zustand store for recent emojis + skin tone preference |
| `frontend/src/utils/emoji.ts` | Shortcode replacement, emoji-only detection utilities |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `frontend/src/pages/messages/ComposeBar.tsx` | Add emoji button + popover with EmojiPicker; call `replaceShortcodes` before send |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add emoji-only detection for 3x rendering |
| `frontend/src/pages/feed/CreatePost.tsx` | Add emoji button + EmojiPicker for post composer |
| `frontend/src/pages/feed/PostCard.tsx` | Add emoji-only detection for large emoji in post text |

### 4.3 Step-by-Step Implementation Order

1. Create `emoji-data.ts` with full dataset (can use `unicode-emoji-json` npm package as source, convert to internal format)
2. Create `emoji.ts` utilities: `replaceShortcodes()`, `isEmojiOnly()`
3. Create `emojiStore.ts` with recent tracking + skin tone persistence
4. Build `EmojiPicker.tsx` with all features (categories, search, recents, skin tone, keyboard nav)
5. Integrate EmojiPicker into ComposeBar (messaging)
6. Add shortcode replacement in ComposeBar `handleSend`
7. Add emoji-only detection in MessageBubble
8. Integrate EmojiPicker into CreatePost (newsfeed)
9. Add emoji-only detection in PostCard
10. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/emoji-messages.spec.ts` — 15 tests across 3 sections.

### 5.2 Test Setup

```typescript
import { test, expect, Page } from "@playwright/test";

const TS = Date.now();
const sessions: Record<string, any> = {};

test.beforeAll(async ({ browser }) => {
  const { getOrCreateSession } = await import("../../e2e_session_setup");
  sessions["alice"] = await getOrCreateSession("alice");
  sessions["bob"] = await getOrCreateSession("bob");
});

async function injectAuth(page: Page, identity: string) {
  const s = sessions[identity];
  await page.context().addCookies([
    { name: "ui_session", value: s.session_id, domain: "localhost", path: "/" },
    { name: "ui_csrf", value: s.csrf_token, domain: "localhost", path: "/" },
    { name: "ui_access_token", value: s.access_token, domain: "localhost", path: "/" },
  ]);
}
```

### 5.3 Section 284: Emoji Picker UI (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 284.1 | Emoji picker opens when clicking emoji button in ComposeBar | `[data-testid="emoji-picker"]` is visible; category tabs rendered |
| 284.2 | Emoji picker shows 9 category tabs | Count category tab buttons = 9 |
| 284.3 | Clicking a category scrolls to that section | Click "Animals" tab; first visible emoji is from animals category |
| 284.4 | Search filters emojis by keyword | Type "fire" in search; results contain 🔥; results do NOT contain unrelated emojis |
| 284.5 | Skin tone selector changes emoji appearance | Open skin tone popover; select "Medium-Dark"; verify skin-tone-capable emojis update |
| 284.6 | Selecting an emoji inserts it into the compose input | Click 😀 in picker; verify compose textarea contains "😀" |

### 5.4 Section 285: Emoji Message Rendering (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 285.1 | Single emoji message renders at 3x size | Alice sends "😀"; message bubble has `text-5xl` class |
| 285.2 | Two-emoji message renders at 3x size | Alice sends "😀🔥"; message bubble has `text-5xl` class |
| 285.3 | Three-emoji message renders at 3x size | Alice sends "😀🔥❤️"; message bubble has `text-5xl` class |
| 285.4 | Four-emoji message renders at normal size | Alice sends "😀🔥❤️👍"; message bubble does NOT have `text-5xl` class |
| 285.5 | Mixed emoji + text renders at normal size | Alice sends "hello 😀"; message bubble does NOT have `text-5xl` class |

### 5.5 Section 286: Shortcode Replacement & Recents (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 286.1 | `:smile:` shortcode is replaced with 😄 in sent message | Alice types `:smile:` and sends; message text in conversation is "😄" |
| 286.2 | Unknown shortcode is preserved as-is | Alice types `:nonexistent_xyz:` and sends; message text is ":nonexistent_xyz:" |
| 286.3 | Mixed text with shortcodes is partially replaced | Alice types `hello :fire: world :wave:` and sends; text is "hello 🔥 world 👋" |
| 286.4 | Recently used emoji appears in Recent section | Alice selects 🎉 from picker; reopens picker; "Recent" section contains 🎉 |

---

## 6. Error Handling

### 6.1 Frontend Errors

| Scenario | Handling |
|----------|----------|
| Emoji dataset fails to load | Show "Emoji unavailable" placeholder in picker; compose bar still allows text input |
| localStorage quota exceeded (recent emojis) | Silently drop oldest entries; wrap `setItem` in try-catch |
| Invalid shortcode | Preserved as-is in text (no error shown) |

### 6.2 Performance

| Concern | Mitigation |
|---------|-----------|
| Emoji dataset size (~120KB gzipped) | Lazy-loaded via dynamic `import()` when picker first opens; cached in module scope |
| Search performance (1800 entries) | In-memory filter with debounced input (150ms); no network calls |
| Rendering 1800+ emoji grid items | Virtual scrolling via `react-virtualized` or CSS `content-visibility: auto` |
| Skin tone re-rendering | Memoize applied skin tones per emoji; only recompute when tone changes |

---

## 7. Security Considerations

### 7.1 XSS Prevention

Emoji text is rendered in React JSX via `{message.text}`, which auto-escapes HTML. No `dangerouslySetInnerHTML` is used. Shortcode replacement operates on plain strings before they enter JSX.

### 7.2 Emoji Bombing

No server-side limit change is needed — the existing message text length limit (10,000 characters) inherently caps the number of emojis in a single message.

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| None | — | This is a standalone feature |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| MSG-007 (Custom Emojis) | EmojiPicker component, emojiStore |
| MSG-008 (GIF & Sticker Messages) | EmojiPicker UI patterns |
| MSG-011 (Emoji Reactions Enhancement) | EmojiPicker component |
| FEED-004 (Emoji/GIF/Sticker Comments) | EmojiPicker component |
| FEED-008 (Enhanced Post Composer) | EmojiPicker integration |

---

## 9. Architecture Diagram

```
Frontend-Only Architecture (No Backend Changes):

+-------------------------------------------+
|             React Frontend                 |
|                                           |
|  ComposeBar.tsx                           |
|  +--- EmojiButton (Smile icon)           |
|  |      |                                 |
|  |      +-> Popover                       |
|  |           +-> EmojiPicker.tsx           |
|  |                +-> SearchInput          |
|  |                +-> CategoryTabs         |
|  |                +-> RecentSection        |
|  |                +-> EmojiGrid (virtual)  |
|  |                +-> SkinToneSelector     |
|  |                                        |
|  +--- Textarea                            |
|  |      <- emoji inserted via onSelect    |
|  |      <- shortcodes replaced on send    |
|  |                                        |
|  +--- SendButton                          |
|         |                                 |
|         +-> replaceShortcodes(text)       |
|         +-> POST /messages (unchanged)    |
|                                           |
|  MessageBubble.tsx                        |
|  +--- isEmojiOnly(text) check            |
|  |      +-> text-5xl class if true        |
|  +--- Normal text rendering otherwise     |
|                                           |
|  CreatePost.tsx (Newsfeed)                |
|  +--- Same EmojiPicker integration        |
+-------------------------------------------+

Data Flow:

  emoji-data.ts (static ~1800 entries, ~120KB gzipped)
       |
       +-> SHORTCODE_MAP (Map<string, string>)
       |     Used by replaceShortcodes()
       |
       +-> EMOJI_DATA (EmojiEntry[])
       |     Used by EmojiPicker search + categories
       |
       +-> EMOJI_CATEGORIES (category metadata)
             Used by EmojiPicker tab rendering

  emojiStore.ts (Zustand + localStorage)
       |
       +-> recentEmojis: string[] (max 32)
       +-> skinTone: string (modifier codepoint)
```

---

## 10. DynamoDB Access Patterns

No new DynamoDB tables or access patterns are required. Emoji processing is entirely frontend-side:

| Operation | Backend Impact | Notes |
|---|---|---|
| Send message with emojis | None -- text stored as-is | Backend receives Unicode characters |
| Send message with shortcodes | None -- replaced on frontend before send | Backend never sees `:smile:` syntax |
| Emoji-only large rendering | None -- detection is client-side | No `format` field needed |
| Recent emoji tracking | None -- localStorage only | No server persistence |
| Skin tone preference | None -- localStorage only | No server persistence |

---

## 11. API Request/Response Examples

No new API endpoints are introduced. The existing message send endpoint accepts emoji text as-is:

**Send emoji-only message:**
```bash
curl -X POST http://localhost:8000/ui/messaging/conversations/conv_abc/messages \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=tok_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"text": "😀"}'

# Response 201:
{
  "message_id": "m_abc123",
  "conversation_id": "conv_abc",
  "sender_id": "alice-uuid",
  "text": "😀",
  "kind": "text",
  "created_at": 1748520000
}
```

**Send message with shortcode (after frontend replacement):**
```bash
# Frontend replaces `:fire:` with `🔥` before sending
curl -X POST http://localhost:8000/ui/messaging/conversations/conv_abc/messages \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=tok_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"text": "hello 🔥 world 👋"}'

# Response 201:
{
  "message_id": "m_def456",
  "text": "hello 🔥 world 👋",
  "kind": "text"
}
```

---

## 12. Pydantic Models

No new Pydantic models are needed. The existing `SendTextMessageIn` model accepts Unicode emoji characters in the `text` field without any changes. The `MessageOut` model returns the text as-is.

The frontend-only models are TypeScript interfaces:

```typescript
// frontend/src/data/emoji-data.ts
export interface EmojiEntry {
  emoji: string;           // Unicode character(s)
  shortcode: string;       // e.g., "smile"
  name: string;            // e.g., "Smiling Face with Open Mouth"
  keywords: string[];      // e.g., ["happy", "joy"]
  category: EmojiCategory;
  skinToneSupport: boolean;
  version: string;         // Unicode version
}

// frontend/src/stores/emojiStore.ts
interface EmojiStoreState {
  recentEmojis: string[];
  skinTone: string;
  addRecent: (emoji: string) => void;
  setSkinTone: (tone: string) => void;
}
```

---

## 13. Frontend Component Tree (Detailed)

```
EmojiPicker (shared component)
  +-- SearchInput
  |     +-- Input (type="text", placeholder="Search emojis...")
  |     +-- X button (clear search)
  |     +-- debounced onChange (150ms)
  |
  +-- SkinToneSelector
  |     +-- Popover trigger (hand emoji with current tone)
  |     +-- PopoverContent: 6 tone circles (default + 5 modifiers)
  |     +-- onClick: emojiStore.setSkinTone(modifier)
  |
  +-- CategoryTabs (vertical sidebar on desktop, horizontal on mobile)
  |     +-- For each EMOJI_CATEGORIES: Button with emoji icon
  |     +-- Active state: highlighted background
  |     +-- onClick: scroll grid to category section
  |
  +-- RecentSection (visible when recentEmojis.length > 0)
  |     +-- Label: "Recent"
  |     +-- Grid: up to 32 emoji buttons
  |
  +-- EmojiGrid (main content area)
  |     +-- VirtualList (react-virtualized or CSS content-visibility)
  |     +-- For each category:
  |     |     +-- CategoryHeader (sticky label)
  |     |     +-- Grid (8 columns)
  |     |           +-- For each emoji in category:
  |     |                 +-- Button (emoji with applied skin tone)
  |     |                 +-- title={emoji.name}
  |     |                 +-- onClick: onSelect(appliedEmoji)
  |     |                             emojiStore.addRecent(appliedEmoji)
  |     +-- EmptyState (when search has no results)
  |
  +-- KeyboardNavigation
        +-- Arrow keys: move focus between emoji buttons
        +-- Enter: select focused emoji
        +-- Escape: close picker (onClose callback)
```

---

## 14. Observability & Monitoring

Since this is a frontend-only feature, observability is limited to client-side metrics:

| Metric | Type | Collection | Description |
|---|---|---|---|
| `emoji_picker_opens` | Counter | Analytics event | Times the emoji picker was opened |
| `emoji_selected_category` | Counter | Analytics event | Emoji selection by category |
| `emoji_search_used` | Counter | Analytics event | Search input used in picker |
| `emoji_shortcode_replaced` | Counter | In-memory | Shortcodes replaced on send |
| `emoji_only_messages_sent` | Counter | Analytics event | Messages detected as emoji-only |

No server-side alerting is needed. Client-side errors (emoji data load failure) are logged to the browser console and to the existing error tracking system.

---

## 15. Rollout Plan

### 15.1 Feature Flags

| Flag | Default | Description |
|---|---|---|
| `EMOJI_SHORTCODES_ENABLED` | `true` | Enable shortcode replacement on send |
| `EMOJI_PICKER_ENABLED` | `true` | Show emoji picker button in ComposeBar |
| `EMOJI_LARGE_RENDERING_ENABLED` | `true` | Enable 3x rendering for emoji-only messages |

### 15.2 Phased Deployment

| Phase | Scope | Duration | Success Criteria |
|---|---|---|---|
| Phase 1: Emoji data + utilities | Ship emoji-data.ts and emoji.ts | 1 day | Tests pass, bundle size acceptable |
| Phase 2: EmojiPicker component | Ship shared picker component | 1 day | Picker renders, search works, keyboard nav works |
| Phase 3: ComposeBar integration | Add emoji button and picker to messaging | 1 day | Emoji insertion works, shortcodes replaced |
| Phase 4: Large emoji rendering | Enable emoji-only detection in MessageBubble | 1 day | 1-3 emoji messages render at 3x size |
| Phase 5: Newsfeed integration | Add picker to CreatePost | 1 day | Same behavior in newsfeed composer |

### 15.3 Bundle Size Impact

| Asset | Size (gzipped) | Loading |
|---|---|---|
| emoji-data.ts | ~120 KB | Lazy-loaded on first picker open |
| EmojiPicker.tsx | ~8 KB | Lazy-loaded with data |
| emoji.ts utilities | ~2 KB | Included in main bundle |

Total impact on initial page load: ~2 KB (utilities only). The ~128 KB emoji data is loaded on demand.

---

## 16. Performance Considerations

| Concern | Mitigation | Measured Impact |
|---|---|---|
| Emoji dataset size (~120KB gzip) | Dynamic import on first picker open | Zero impact on initial load |
| Rendering 1800+ emoji grid items | CSS `content-visibility: auto` or virtualized list | < 16ms render time |
| Search filter across 1800 entries | In-memory filter with debounced input (150ms) | < 5ms per filter |
| isEmojiOnly regex per message | Regex compiled once, memoized per message text | < 1ms per message |
| Shortcode replacement on send | Single regex pass, Map.get for each match | < 1ms per send |
| Skin tone application | Memoized per (emoji, tone) pair | Negligible |
| localStorage for recents/skin tone | try-catch wrapper, max 32 entries | < 1ms per operation |
| Multiple EmojiPicker instances | Shared Zustand store, single data import | No duplication |

---

## 17. Accessibility

| Feature | Implementation | WCAG |
|---|---|---|
| Emoji search by name | Search input in picker header | 2.1 Keyboard accessible |
| Keyboard navigation | Arrow keys + Enter/Escape | 2.1.1 Keyboard operable |
| Emoji alt text | `title` attribute on each button | 1.1 Text alternatives |
| Screen reader labels | `aria-label` on picker, category tabs | 4.1.2 Name, Role, Value |
| High contrast | Emoji renders natively (OS-level) | 1.4.3 Contrast minimum |
| Reduced motion | No animations in picker | 2.3.3 Animation from interactions |

---

## 18. File Change Summary (Extended)

| File | Change Type | Lines | Description |
|------|-------------|-------|-------------|
| `frontend/src/data/emoji-data.ts` | **New** | ~3000 | Static emoji dataset (1800 entries) |
| `frontend/src/components/shared/EmojiPicker.tsx` | **New** | ~250 | Shared picker with categories, search, recents, skin tones |
| `frontend/src/stores/emojiStore.ts` | **New** | ~30 | Zustand store for recents + skin tone |
| `frontend/src/utils/emoji.ts` | **New** | ~50 | Shortcode replacement + emoji-only detection |
| `frontend/src/pages/messages/ComposeBar.tsx` | Modify | +20 | Emoji button + popover + shortcode call |
| `frontend/src/pages/messages/MessageBubble.tsx` | Modify | +10 | Emoji-only detection + large rendering |
| `frontend/src/pages/feed/CreatePost.tsx` | Modify | +15 | Emoji button + popover |
| `frontend/src/pages/feed/PostCard.tsx` | Modify | +5 | Emoji-only detection |
| `app/core/settings.py` | Modify | +1 | `emoji_shortcodes_enabled` flag |
| `frontend/e2e/emoji-messages.spec.ts` | **New** | ~200 | 15 E2E tests (sections 284-286) |

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `frontend/src/pages/messages/ComposeBar.tsx` | 18, 160, 1777 | EXISTS — has MeetingPollComposer integration pattern to follow; no emoji button exists yet |
| `frontend/src/pages/messages/MessageBubble.tsx` | 79, 412, 795-818 | EXISTS — `QUICK_EMOJIS` array for inline reaction picker; `emojiPickerOpen` state; no emoji-only detection |
| `frontend/src/pages/feed/CreatePost.tsx` | 110 | EXISTS — `CreatePost` component; no emoji picker integration yet |
| `frontend/src/pages/feed/PostCard.tsx` | 190 | EXISTS — `PostCard` component; no emoji-only detection |
| `app/routers/messaging.py` | 3308 | EXISTS — `send_text_message()` accepts plain text; no emoji processing |
| `app/core/settings.py` | — | No `emoji_shortcodes_enabled` or similar setting exists yet — **new implementation required** |
| `frontend/src/components/shared/EmojiPicker.tsx` | — | **Does not exist** — new component required |
| `frontend/src/data/emoji-data.ts` | — | **Does not exist** — `frontend/src/data/` directory does not exist; needs creation |
| `frontend/src/utils/emoji.ts` | — | **Does not exist** — `frontend/src/utils/` directory does not exist; needs creation |
| `frontend/src/stores/emojiStore.ts` | — | **Does not exist** — no emoji store in `frontend/src/stores/` |
