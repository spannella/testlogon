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

### 2.2 Message Bubble Rendering

`frontend/src/pages/messages/MessageBubble.tsx` renders message content as plain text in a `<p>` tag. Unicode emojis render at the same font size as regular text, making them small and hard to read when sent alone. There is no detection of emoji-only messages for enlarged rendering.

### 2.3 Emoji Data

No emoji dataset exists in the codebase. A comprehensive emoji dataset is needed with:
- Unicode codepoints for each emoji
- Short names and keywords for search
- Category assignments
- Skin tone variant mappings
- Shortcode mappings (`:smile:` → `😄`)

### 2.4 Backend Message Processing

`app/routers/messaging.py` accepts message text as a plain string via `send_text_message()`. The backend performs no emoji processing — text is stored and returned as-is. Shortcode replacement can be handled entirely on the frontend (before send) to keep the backend stateless.

### 2.5 Newsfeed Compose

`frontend/src/pages/feed/CreatePost.tsx` also has a text input that would benefit from the same emoji picker. Building the `EmojiPicker` as a shared component in `components/shared/` allows both surfaces to use it.

### 2.6 Gaps

1. **No emoji picker component** — users have no in-app way to browse and select emojis.
2. **No emoji dataset** — no structured data for categories, search, skin tones.
3. **No shortcode replacement** — `:smile:` is sent as literal text.
4. **No emoji-only large rendering** — single-emoji messages look the same as text.
5. **No recent/frequently-used tracking** — no localStorage persistence for emoji usage.

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
