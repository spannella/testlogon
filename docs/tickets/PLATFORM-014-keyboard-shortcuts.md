# PLATFORM-014: Comprehensive Keyboard Shortcuts — Navigation, Actions, and Customizable Keybindings

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### The Gap

The platform has a functional but minimal keyboard shortcut system. The `useGlobalShortcuts` hook (`frontend/src/hooks/useGlobalShortcuts.ts`, line 48) <!-- VERIFIED: useGlobalShortcuts.ts:48 --> registers a global `keydown` listener that matches events against a list of `Shortcut` objects. The `Header` component (`frontend/src/components/layout/Header.tsx`, line 205) <!-- CORRECTED: was "line 193"; shortcuts useMemo is at line 205 --> defines 6 shortcuts:

```typescript
const shortcuts = React.useMemo<Shortcut[]>(() => [
  { key: "ctrl+k",       label: "Open command palette", group: "General",   action: () => setSearchOpen(true), activeInInput: true },
  { key: "shift+?",      label: "Show keyboard shortcuts", group: "General", action: () => setShortcutHelpOpen(true) },
  { key: "ctrl+shift+d", label: "Toggle dark mode",     group: "Actions",   action: () => setTheme(...) },
  { key: "ctrl+shift+n", label: "New message",          group: "Actions",   action: () => navigate("/messages?new=1") },
  { key: "ctrl+shift+p", label: "New post",             group: "Actions",   action: () => navigate("/feed?compose=1") },
  { key: "ctrl+enter",   label: "Send message",         group: "Messaging", action: () => { /* handled locally in ComposeBar */ }, activeInInput: true },
], [navigate, setTheme, theme]);
```

The `ShortcutHelpDialog` (`frontend/src/components/shared/ShortcutHelpDialog.tsx`, line 48) <!-- CORRECTED: was "line 29"; ShortcutHelpDialog function is at line 48 --> displays these shortcuts in a modal grouped by category (`General`, `Navigation`, `Actions`, `Messaging`). The E2E tests (`frontend/e2e/keyboard-shortcuts.spec.ts`) verify palette opening (section 73), actions (section 74), overlay display (section 75), Ctrl+Enter send (section 76), and filtering (section 77).

What is missing:

1. **Navigation shortcuts**: There are no shortcuts for navigating between pages. Users cannot press `g then m` to go to messages, `g then f` to go to feed, etc. The `SEARCH_PAGES` array (line 88 in `Header.tsx`) <!-- CORRECTED: was "line 79"; SEARCH_PAGES is at line 88 --> lists 15 navigable pages but none have keyboard shortcuts.

2. **Page-specific action shortcuts**: Within a page, there are no shortcuts for common actions. For example: `n` for new message/post/ticket, `r` for reply, `e` for edit, `j`/`k` for next/previous item navigation.

3. **Chord sequences**: The current `normalizeKeyEvent` function (line 19 in `useGlobalShortcuts.ts`) <!-- VERIFIED: useGlobalShortcuts.ts:19 --> handles single key combinations (e.g., `ctrl+k`) but not chord sequences (e.g., `g` followed by `m` within 1 second). Chord sequences are the standard pattern for navigation shortcuts in Gmail, GitHub, and Notion.

4. **Customizable keybindings**: All shortcuts are hardcoded in the `Header` component. Users cannot remap shortcuts to their preferred keys. The `Shortcut` interface (line 3) <!-- VERIFIED: useGlobalShortcuts.ts:3 --> defines `key` as a simple string with no indirection through a user-configurable mapping.

5. **Focus management**: After navigating to a new page via a shortcut, focus is not managed. The user may need to Tab multiple times to reach the main content area. The `AppShell` component (`frontend/src/components/layout/AppShell.tsx`, line 45) <!-- CORRECTED: was "line 39"; AppShell function is at line 45 --> has a "Skip to content" link but no programmatic focus management after navigation.

6. **Shortcut conflicts**: The current system does not detect or handle conflicts between global shortcuts and page-specific shortcuts. For example, `?` opens the help overlay globally, but a page might want `?` to trigger a context-sensitive help tooltip.

### Why This Is Needed

1. **Power user productivity**: Keyboard-driven users (developers, writers, power users) expect comprehensive shortcuts for navigation and actions. This is table stakes for any productivity SaaS.
2. **Accessibility**: Keyboard navigation is an accessibility requirement (WCAG 2.1 SC 2.1.1). While the app is technically keyboard-navigable via Tab, dedicated shortcuts dramatically improve the experience for keyboard-only users.
3. **Reduced mouse dependency**: Each mouse interaction costs 1-3 seconds. Navigation shortcuts save 10-30 seconds per task for frequent users.
4. **Consistency with industry conventions**: Gmail's `g+i` (go to inbox), GitHub's `g+n` (go to notifications), and Notion's Cmd+/ (open shortcut help) are widely known patterns. Users expect similar shortcuts.

### Architecture After This Change

```
Shortcut System Architecture
==============================

ShortcutRegistry (singleton)
    |
    +--- Global shortcuts (always active)
    |     |--- ctrl+k: Open command palette
    |     |--- shift+?: Show shortcut help
    |     |--- ctrl+shift+d: Toggle dark mode
    |     |--- Escape: Close active modal/dialog
    |
    +--- Navigation chords (g + <key> within 1s)
    |     |--- g,m: Go to Messages
    |     |--- g,f: Go to Feed
    |     |--- g,c: Go to Calendar
    |     |--- g,s: Go to Settings
    |     |--- g,b: Go to Billing
    |     |--- g,t: Go to Tickets
    |     |--- g,i: Go to Files
    |     |--- g,d: Go to Dashboard
    |     |--- g,h: Go to Shop
    |     |--- g,a: Go to Alerts
    |     |--- g,p: Go to Profile
    |     |--- g,k: Go to Security
    |
    +--- Action shortcuts (context-dependent)
    |     |--- n: New item (message/post/ticket depending on current page)
    |     |--- r: Reply to selected item
    |     |--- e: Edit selected item
    |     |--- d: Delete selected item (with confirmation)
    |     |--- j/k: Next/previous item
    |     |--- x: Toggle selection
    |     |--- Enter: Open selected item
    |
    +--- User custom bindings (stored in localStorage + server)
          |--- Override any default binding
          |--- Conflict detection
          |--- Reset to defaults

useGlobalShortcuts(shortcuts)        <- existing hook, enhanced for chords
usePageShortcuts(pageShortcuts)      <- NEW hook for page-specific shortcuts
useChordHandler(chordMap)            <- NEW hook for chord sequences
```

### Event Flow Diagram

```
User presses "g" key
    |
    v
useChordHandler
    |--- isInputFocused()? -> SKIP (user is typing)
    |--- e.isComposing? -> SKIP (IME active)
    |--- Has modifier keys (ctrl/alt/meta)? -> SKIP
    |
    |--- Is "g" a chord start? -> YES (chords.some(c => c.first === "g"))
    |       |
    |       v
    |     Set pendingFirst = "g"
    |     Start 1000ms timer
    |     Show ChordIndicator overlay: "g + ?  Navigate to..."
    |
    |--- Timer expires (1000ms)
    |       |
    |       v
    |     Clear pendingFirst
    |     Hide ChordIndicator
    |
    |--- User presses "m" within 1000ms
            |
            v
          useChordHandler
            |--- pendingFirst === "g"
            |--- Match chord: { first: "g", second: "m" }
            |--- Clear timer, clear pendingFirst
            |--- Hide ChordIndicator
            |--- Execute: navigateWithFocus("/messages")
                    |
                    v
                  React Router navigate("/messages")
                    |
                    v
                  requestAnimationFrame(() => {
                    document.getElementById("main-content")?.focus()
                  })
```

---

## 2. Current State Analysis

### 2.1 useGlobalShortcuts Hook (`frontend/src/hooks/useGlobalShortcuts.ts`)

The hook (line 48) <!-- VERIFIED: useGlobalShortcuts.ts:48 --> registers a single `keydown` event listener on `document`:

```typescript
export function useGlobalShortcuts(shortcuts: Shortcut[]) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      const normalized = normalizeKeyEvent(e);
      for (const shortcut of shortcuts) {
        if (shortcut.key !== normalized) continue;
        if (!shortcut.activeInInput && isInputFocused()) continue;
        e.preventDefault();
        shortcut.action();
        return;
      }
    },
    [shortcuts],
  );
  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}
```

The `normalizeKeyEvent` function (line 19) <!-- VERIFIED: useGlobalShortcuts.ts:19 --> builds a key string from modifier flags and `e.key.toLowerCase()`. It combines `ctrl`/`meta` into `ctrl` (no distinction between Mac Cmd and Ctrl), `shift`, and `alt`. Non-modifier keys are appended after modifiers.

```typescript
function normalizeKeyEvent(e: KeyboardEvent): string {
  const parts: string[] = [];
  if (e.ctrlKey || e.metaKey) parts.push("ctrl");
  if (e.shiftKey) parts.push("shift");
  if (e.altKey) parts.push("alt");
  const key = e.key.toLowerCase();
  if (!["control", "meta", "shift", "alt"].includes(key)) {
    parts.push(key);
  }
  return parts.join("+");
}
```

The `isInputFocused` function (line 35) <!-- VERIFIED: useGlobalShortcuts.ts:35 --> checks if the active element is `input`, `textarea`, `select`, or `contentEditable`. Shortcuts with `activeInInput: false` (the default) are suppressed when an input is focused.

```typescript
function isInputFocused(): boolean {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if ((el as HTMLElement).isContentEditable) return true;
  return false;
}
```

The `Shortcut` interface (line 3) supports four groups:

```typescript
group: "Navigation" | "Messaging" | "Actions" | "General";
```

The `getGroupedShortcuts` function (line 72) <!-- VERIFIED: useGlobalShortcuts.ts:72 --> creates a Record from the group field for display in the help dialog.

### 2.2 ShortcutHelpDialog (`frontend/src/components/shared/ShortcutHelpDialog.tsx`)

The dialog (line 48) <!-- CORRECTED: was "line 29"; ShortcutHelpDialog function at line 48 --> groups shortcuts by category and displays them in a grid:

```tsx
{grouped[group]!.map((s) => (
  <div key={s.key} className="flex items-center justify-between py-1">
    <span className="text-sm">{s.label}</span>
    <kbd className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
      {formatKey(s.key)}
    </kbd>
  </div>
))}
```

The `formatKey` function (line 12) <!-- CORRECTED: was "line 11"; formatKey is at line 12 --> translates key identifiers to display labels: `ctrl` becomes `Cmd` on Mac or `Ctrl` on other platforms, single characters are uppercased, and special keys like `escape` become `Esc`.

```typescript
function formatKey(key: string): string {
  return key
    .split("+")
    .map((k) => {
      if (k === "ctrl")
        return typeof navigator !== "undefined" && navigator.userAgent.includes("Mac")
          ? "Cmd"
          : "Ctrl";
      if (k === "shift") return "Shift";
      if (k === "alt") return "Alt";
      if (k === "escape") return "Esc";
      if (k === "enter") return "Enter";
      if (k === "?") return "?";
      return k.length === 1 ? k.toUpperCase() : k.charAt(0).toUpperCase() + k.slice(1);
    })
    .join(" + ");
}
```

The `groupOrder` (line 57) <!-- CORRECTED: was "line 35"; groupOrder is at line 57 --> is `["General", "Navigation", "Actions", "Messaging"]`. Currently, the "Navigation" group is empty because no navigation shortcuts are defined.

### 2.3 E2E Tests (`frontend/e2e/keyboard-shortcuts.spec.ts`)

The test file has 5 sections with 12 tests:

- **Section 73** (4 tests): Command palette basics --- Ctrl+K opens, click opens, Actions group visible, Escape closes.
- **Section 74** (3 tests): Command palette actions --- Toggle Dark Mode, New Message navigation, Keyboard Shortcuts overlay.
- **Section 75** (3 tests): Shortcut overlay --- `?` key opens, Escape closes, `?` in input types character.
- **Section 76** (1 test): Ctrl+Enter sends message in ComposeBar.
- **Section 77** (1 test): Command palette filtering by typed text.

These tests must continue to pass after the changes in this ticket.

### 2.4 ComposeBar Local Shortcuts

The `ComposeBar` component (`frontend/src/pages/messages/ComposeBar.tsx`) handles `Enter` (without Shift) locally via an `onKeyDown` handler on the textarea (line 618) <!-- VERIFIED: ComposeBar.tsx:618 -->:

```typescript
const handleKeyDown = (e: React.KeyboardEvent) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    void handleSubmit();
  }
};
```
<!-- CORRECTED: was "Ctrl+Enter" in the snippet, actually the handler fires on Enter without Shift (not Ctrl+Enter). The actual code at line 618-623 uses `e.key === "Enter" && !e.shiftKey`. -->

This is a page-specific shortcut that is NOT registered via `useGlobalShortcuts`. The global `ctrl+enter` shortcut in `Header.tsx` (line 238) has an empty action `() => {}` --- it exists only for display in the help overlay.

This pattern (local handler + global display-only registration) should be formalized. The `ShortcutRegistry` should support "display-only" entries that appear in the help dialog but whose action is handled locally by a component.

### 2.5 AppShell Focus Management (`frontend/src/components/layout/AppShell.tsx`)

The `AppShell` (line 45) <!-- CORRECTED: was "line 25"; AppShell function at line 45; "Skip to content" link at line 60 --> renders a "Skip to content" link:

```tsx
<a href="#main-content" className="sr-only focus:not-sr-only ...">
  Skip to content
</a>
```

The main content area has `id="main-content"` (line 93) <!-- CORRECTED: was "line 67"; main-content div at line 93 -->. However, after a programmatic navigation (e.g., `navigate("/messages")`), focus is not moved to the main content. The user remains focused on whatever element was active before navigation.

The `main-content` div currently has no `tabIndex` attribute, which means `element.focus()` will not work on it directly. Adding `tabIndex={-1}` (focusable but not in tab order) enables programmatic focus. <!-- NOTE: This claim is outdated — the actual AppShell.tsx line 93 already has `tabIndex={-1}` and `outline-none` on the main-content div. -->

---

## 3. Technical Design

### 3.1 Chord Sequence Handler

Implement a `useChordHandler` hook that detects two-key sequences:

```typescript
interface ChordMapping {
  first: string;         // e.g., "g"
  second: string;        // e.g., "m"
  label: string;
  group: "Navigation" | "Messaging" | "Actions" | "General";
  action: () => void;
  timeout?: number;      // ms to wait for second key (default: 1000)
}

function useChordHandler(chords: ChordMapping[], onChordStart?: (firstKey: string) => void, onChordEnd?: () => void) {
  const pendingFirst = useRef<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    // Never activate chords in inputs or during IME composition
    if (isInputFocused()) return;
    if (e.isComposing) return;

    // Never activate when modifier keys are held
    if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;

    const key = e.key.toLowerCase();

    if (pendingFirst.current) {
      // We're waiting for the second key
      const match = chords.find(
        (c) => c.first === pendingFirst.current && c.second === key
      );

      if (timerRef.current) clearTimeout(timerRef.current);
      pendingFirst.current = null;
      onChordEnd?.();

      if (match) {
        e.preventDefault();
        match.action();
        return;
      }
      // No match for second key -- chord cancelled, fall through
      return;
    }

    // Check if this key is the first key of any chord
    const isChordStart = chords.some((c) => c.first === key);
    if (isChordStart) {
      e.preventDefault();
      pendingFirst.current = key;
      onChordStart?.(key);

      const timeout = chords.find((c) => c.first === key)?.timeout ?? 1000;
      timerRef.current = setTimeout(() => {
        pendingFirst.current = null;
        onChordEnd?.();
      }, timeout);
    }
  }, [chords, onChordStart, onChordEnd]);

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [handleKeyDown]);

  return { isPending: pendingFirst.current !== null };
}
```

### 3.2 Navigation Chord Mappings

```typescript
const navigationChords: ChordMapping[] = [
  { first: "g", second: "m", label: "Go to Messages",      group: "Navigation", action: () => navigateWithFocus("/messages") },
  { first: "g", second: "f", label: "Go to Feed",           group: "Navigation", action: () => navigateWithFocus("/feed") },
  { first: "g", second: "c", label: "Go to Calendar",       group: "Navigation", action: () => navigateWithFocus("/calendar") },
  { first: "g", second: "s", label: "Go to Settings",       group: "Navigation", action: () => navigateWithFocus("/settings") },
  { first: "g", second: "b", label: "Go to Billing",        group: "Navigation", action: () => navigateWithFocus("/billing") },
  { first: "g", second: "t", label: "Go to Tickets",        group: "Navigation", action: () => navigateWithFocus("/tickets") },
  { first: "g", second: "i", label: "Go to Files",          group: "Navigation", action: () => navigateWithFocus("/files") },
  { first: "g", second: "d", label: "Go to Dashboard",      group: "Navigation", action: () => navigateWithFocus("/") },
  { first: "g", second: "h", label: "Go to Shop",           group: "Navigation", action: () => navigateWithFocus("/shop") },
  { first: "g", second: "a", label: "Go to Alerts",         group: "Navigation", action: () => navigateWithFocus("/alerts") },
  { first: "g", second: "p", label: "Go to Profile",        group: "Navigation", action: () => navigateWithFocus("/profile") },
  { first: "g", second: "k", label: "Go to Security",       group: "Navigation", action: () => navigateWithFocus("/security") },
];
```

### 3.3 Page-Specific Shortcuts via usePageShortcuts

Create a `usePageShortcuts` hook that components can call to register shortcuts scoped to their lifetime:

```typescript
const ShortcutRegistryContext = createContext<ShortcutRegistry | null>(null);

function useShortcutRegistry(): ShortcutRegistry {
  const registry = useContext(ShortcutRegistryContext);
  if (!registry) throw new Error("ShortcutRegistryContext not found");
  return registry;
}

function usePageShortcuts(shortcuts: Shortcut[]) {
  // Register shortcuts on mount, unregister on unmount
  // Priority: page shortcuts override global shortcuts for conflicting keys
  const registry = useShortcutRegistry();

  useEffect(() => {
    const ids = shortcuts.map((s) => registry.register(s, { priority: "page" }));
    return () => ids.forEach((id) => registry.unregister(id));
  }, [shortcuts, registry]);
}
```

Usage in a page component:

```typescript
// In MessagesPage
const { selectedIndex, setSelectedIndex, conversations } = useConversationList();

usePageShortcuts(React.useMemo(() => [
  {
    key: "n",
    label: "New conversation",
    group: "Actions",
    action: () => setNewDialogOpen(true),
  },
  {
    key: "j",
    label: "Next conversation",
    group: "Navigation",
    action: () => setSelectedIndex((prev) => Math.min(prev + 1, conversations.length - 1)),
  },
  {
    key: "k",
    label: "Previous conversation",
    group: "Navigation",
    action: () => setSelectedIndex((prev) => Math.max(prev - 1, 0)),
  },
  {
    key: "enter",
    label: "Open conversation",
    group: "Actions",
    action: () => {
      const conv = conversations[selectedIndex];
      if (conv) navigate(`/messages/${conv.conversation_id}`);
    },
  },
  {
    key: "escape",
    label: "Back to list",
    group: "Navigation",
    action: () => navigate("/messages"),
  },
], [selectedIndex, conversations, navigate]));

// In FeedPage
usePageShortcuts(React.useMemo(() => [
  { key: "n", label: "New post",       group: "Actions",    action: () => setComposeOpen(true) },
  { key: "j", label: "Next post",      group: "Navigation", action: () => selectNextPost() },
  { key: "k", label: "Previous post",  group: "Navigation", action: () => selectPrevPost() },
  { key: "l", label: "Like post",      group: "Actions",    action: () => likeSelectedPost() },
  { key: "c", label: "Comment",        group: "Actions",    action: () => focusCommentInput() },
], [selectNextPost, selectPrevPost, likeSelectedPost, focusCommentInput]));

// In FilesPage
usePageShortcuts(React.useMemo(() => [
  { key: "n",      label: "New folder",     group: "Actions",    action: () => setNewFolderOpen(true) },
  { key: "u",      label: "Upload file",    group: "Actions",    action: () => fileInputRef.current?.click() },
  { key: "delete", label: "Delete selected", group: "Actions",   action: () => deleteSelected() },
  { key: "enter",  label: "Open file",      group: "Actions",    action: () => openSelected() },
  { key: "j",      label: "Next file",      group: "Navigation", action: () => selectNext() },
  { key: "k",      label: "Previous file",  group: "Navigation", action: () => selectPrev() },
], [deleteSelected, openSelected, selectNext, selectPrev]));

// In TicketsPage
usePageShortcuts(React.useMemo(() => [
  { key: "n", label: "New ticket",       group: "Actions",    action: () => setCreateTicketOpen(true) },
  { key: "j", label: "Next ticket",      group: "Navigation", action: () => selectNextTicket() },
  { key: "k", label: "Previous ticket",  group: "Navigation", action: () => selectPrevTicket() },
  { key: "a", label: "Assign to me",     group: "Actions",    action: () => assignToMe() },
], [selectNextTicket, selectPrevTicket, assignToMe]));

// In CalendarPage
usePageShortcuts(React.useMemo(() => [
  { key: "n", label: "New event",        group: "Actions",    action: () => setCreateEventOpen(true) },
  { key: "t", label: "Go to today",      group: "Navigation", action: () => goToToday() },
  { key: "j", label: "Next day/week",    group: "Navigation", action: () => nextPeriod() },
  { key: "k", label: "Previous day/week", group: "Navigation", action: () => prevPeriod() },
], [goToToday, nextPeriod, prevPeriod]));
```

### 3.4 Shortcut Registry (Singleton)

Create a `ShortcutRegistry` class that manages all registered shortcuts with priority levels:

```typescript
type Priority = "global" | "page" | "component";

const PRIORITY_ORDER: Record<Priority, number> = {
  component: 3,
  page: 2,
  global: 1,
};

class ShortcutRegistry {
  private shortcuts: Map<string, { shortcut: Shortcut; priority: Priority; id: string }[]> = new Map();
  private listeners: Set<() => void> = new Set();

  register(shortcut: Shortcut, opts: { priority: Priority }): string {
    const id = crypto.randomUUID();
    const key = shortcut.key;
    const existing = this.shortcuts.get(key) ?? [];
    existing.push({ shortcut, priority: opts.priority, id });
    // Sort by priority: component > page > global
    existing.sort((a, b) => PRIORITY_ORDER[b.priority] - PRIORITY_ORDER[a.priority]);
    this.shortcuts.set(key, existing);
    this.notifyListeners();
    return id;
  }

  unregister(id: string): void {
    for (const [key, entries] of this.shortcuts.entries()) {
      const filtered = entries.filter((e) => e.id !== id);
      if (filtered.length === 0) {
        this.shortcuts.delete(key);
      } else {
        this.shortcuts.set(key, filtered);
      }
    }
    this.notifyListeners();
  }

  getActiveShortcut(key: string): Shortcut | null {
    const entries = this.shortcuts.get(key);
    return entries?.[0]?.shortcut ?? null;
  }

  getAllShortcuts(): Shortcut[] {
    // Return all shortcuts, highest priority per key only
    const result: Shortcut[] = [];
    const seen = new Set<string>();
    for (const [, entries] of this.shortcuts) {
      for (const entry of entries) {
        if (!seen.has(entry.shortcut.key)) {
          result.push(entry.shortcut);
          seen.add(entry.shortcut.key);
        }
      }
    }
    return result;
  }

  /** Detect if a proposed key binding conflicts with an existing one. */
  hasConflict(key: string, excludeId?: string): { label: string; priority: Priority } | null {
    const entries = this.shortcuts.get(key);
    if (!entries) return null;
    const conflict = entries.find((e) => e.id !== excludeId);
    if (!conflict) return null;
    return { label: conflict.shortcut.label, priority: conflict.priority };
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifyListeners() {
    for (const listener of this.listeners) {
      listener();
    }
  }
}

// Singleton instance
const shortcutRegistry = new ShortcutRegistry();
```

### 3.5 Customizable Keybindings

Store custom keybindings in the `uiStore`:

```typescript
interface UiState {
  // ... existing ...
  customKeybindings: Record<string, string>;  // { "Go to Messages": "g,m", ... }
  setKeybinding: (label: string, key: string) => void;
  resetKeybinding: (label: string) => void;
  resetAllKeybindings: () => void;
}

// Implementation:
customKeybindings: {},

setKeybinding: (label, key) => {
  set((s) => ({
    customKeybindings: { ...s.customKeybindings, [label]: key },
  }));
  debouncedSyncToServer({
    custom_keybindings: { ...get().customKeybindings, [label]: key },
  });
},

resetKeybinding: (label) => {
  set((s) => {
    const { [label]: _, ...rest } = s.customKeybindings;
    return { customKeybindings: rest };
  });
  debouncedSyncToServer({ custom_keybindings: get().customKeybindings });
},

resetAllKeybindings: () => {
  set({ customKeybindings: {} });
  debouncedSyncToServer({ custom_keybindings: {} });
},
```

The `resolveKeybinding` function resolves a shortcut's key from custom bindings:

```typescript
function resolveKeybinding(label: string, defaultKey: string): string {
  const customBindings = useUiStore.getState().customKeybindings;
  return customBindings[label] ?? defaultKey;
}
```

The keybinding customization UI:

1. Open from Settings or from the `ShortcutHelpDialog` via an "Edit" button.
2. Shows all shortcuts with their current key binding.
3. Clicking a binding puts it in "listening" mode --- the next keypress captures the new binding.
4. Conflict detection: if the new binding conflicts with an existing one, show a warning and offer to swap or cancel.
5. "Reset to defaults" button restores all bindings.

Custom bindings are persisted to localStorage and synced to the server via the preferences PATCH endpoint.

### 3.6 Focus Management After Navigation

After programmatic navigation via a shortcut, focus should be moved to the main content area:

```typescript
function navigateWithFocus(path: string) {
  navigate(path);
  // After React renders the new page, focus the first focusable element in main
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      // Double RAF to wait for React to commit the new DOM
      const main = document.getElementById("main-content");
      if (main) {
        // Try to focus the first interactive element
        const firstFocusable = main.querySelector<HTMLElement>(
          'h1, a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        if (firstFocusable) {
          firstFocusable.focus();
        } else {
          // Fallback: focus the main content container itself
          main.setAttribute("tabindex", "-1");
          main.focus();
        }
      }
    });
  });
}
```

The `main-content` div in `AppShell.tsx` needs `tabIndex={-1}` to be programmatically focusable:

```tsx
<main id="main-content" tabIndex={-1} className="flex-1 overflow-auto outline-none">
  {children}
</main>
```

### 3.7 Chord Indicator UI

When the user presses the first key of a chord (e.g., `g`), show a brief overlay in the bottom-right corner:

```
 +---------------------------+
 |  g + ?  Navigate to...    |
 |  Press a key within 1s    |
 +---------------------------+
```

This overlay disappears after 1 second (chord timeout) or after the second key is pressed.

```tsx
interface ChordIndicatorProps {
  firstKey: string | null;
  chords: ChordMapping[];
}

export function ChordIndicator({ firstKey, chords }: ChordIndicatorProps) {
  if (!firstKey) return null;

  const availableChords = chords.filter((c) => c.first === firstKey);

  return (
    <div className="fixed bottom-4 right-4 z-50 animate-in fade-in slide-in-from-bottom-2 duration-150">
      <Card className="shadow-lg border-primary/20">
        <CardContent className="p-3">
          <div className="flex items-center gap-2 mb-2">
            <kbd className="rounded bg-primary/10 px-2 py-0.5 font-mono text-sm font-bold text-primary">
              {firstKey.toUpperCase()}
            </kbd>
            <span className="text-sm text-muted-foreground">+ ?</span>
            <span className="text-sm font-medium">Navigate to...</span>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
            {availableChords.slice(0, 12).map((chord) => (
              <div key={chord.second} className="flex items-center gap-2 text-xs">
                <kbd className="w-5 text-center rounded bg-muted px-1 py-0.5 font-mono font-bold">
                  {chord.second.toUpperCase()}
                </kbd>
                <span className="text-muted-foreground truncate">{chord.label.replace("Go to ", "")}</span>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground mt-1">Press a key within 1s</p>
        </CardContent>
      </Card>
    </div>
  );
}
```

### 3.8 Enhanced ShortcutHelpDialog

The `ShortcutHelpDialog` needs to display chord shortcuts alongside single-key shortcuts. Update `formatKey` to handle chord notation:

```typescript
function formatKey(key: string): string {
  // Handle chord notation: "g,m" -> "G then M"
  if (key.includes(",")) {
    return key.split(",").map((k) => k.trim().toUpperCase()).join(" then ");
  }

  // Existing logic for single-key shortcuts
  return key
    .split("+")
    .map((k) => {
      if (k === "ctrl")
        return typeof navigator !== "undefined" && navigator.userAgent.includes("Mac")
          ? "Cmd"
          : "Ctrl";
      if (k === "shift") return "Shift";
      if (k === "alt") return "Alt";
      if (k === "escape") return "Esc";
      if (k === "enter") return "Enter";
      if (k === "delete") return "Del";
      if (k === "?") return "?";
      return k.length === 1 ? k.toUpperCase() : k.charAt(0).toUpperCase() + k.slice(1);
    })
    .join(" + ");
}
```

The help dialog should also show page-specific shortcuts with a visual distinction:

```tsx
{/* Page-specific shortcuts (shown when available) */}
{pageShortcuts.length > 0 && (
  <div>
    <h3 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center gap-2">
      Page Shortcuts
      <Badge variant="outline" className="text-[10px]">This page</Badge>
    </h3>
    <div className="space-y-1">
      {pageShortcuts.map((s) => (
        <div key={s.key} className="flex items-center justify-between py-1">
          <span className="text-sm">{s.label}</span>
          <kbd className="rounded border border-primary/30 bg-primary/5 px-2 py-0.5 font-mono text-xs text-primary">
            {formatKey(s.key)}
          </kbd>
        </div>
      ))}
    </div>
  </div>
)}
```

---

## 4. API Endpoints

### 4.1 Custom Keybindings in Preferences

```
PATCH /ui/settings/preferences
  Body: {
    custom_keybindings?: Record<string, string>   // { label: key_combo }
  }
  Auth: require_ui_session (CSRF required)
  Response 200: { ok: true }
```

Backend validation for `custom_keybindings`:

```python
@field_validator("custom_keybindings")
@classmethod
def validate_keybindings(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    if v is None:
        return v
    if len(v) > 100:
        raise ValueError("Maximum 100 custom keybindings")
    for label, key in v.items():
        if len(label) > 100:
            raise ValueError(f"Keybinding label too long: {label[:20]}...")
        if len(key) > 30:
            raise ValueError(f"Keybinding key too long: {key}")
        # Validate key format: single key, modifier+key, or chord (key,key)
        if not re.match(r"^[a-z0-9?/\[\]\\;',.-]+$|^(ctrl\+|shift\+|alt\+)*[a-z0-9?/]+$|^[a-z],[a-z]$", key):
            raise ValueError(f"Invalid keybinding format: {key}")
    return v
```

### 4.2 Get All Available Shortcuts

```
GET /ui/shortcuts
  Auth: require_ui_session (optional --- could be public)
  Response 200: {
    shortcuts: [
      {
        key: str,           // default key combo
        label: str,         // human-readable label
        group: str,         // "General" | "Navigation" | "Actions" | "Messaging"
        customizable: bool, // whether users can remap this shortcut
        scope: str          // "global" | "page:{pageName}"
      }
    ]
  }
```

This endpoint is optional (the frontend could derive the list from the registry), but useful for documentation and admin tools.

---

## 5. Frontend Components

### 5.1 Enhanced useGlobalShortcuts

**File**: `frontend/src/hooks/useGlobalShortcuts.ts`

- Add `useChordHandler` support alongside single-key shortcuts.
- Add the `ShortcutRegistry` singleton.
- Export `usePageShortcuts` hook for page-level shortcuts.
- Support custom keybindings from `uiStore`.
- Add `isInputFocused` to exports (used by chord handler).

### 5.2 Enhanced ShortcutHelpDialog

**File**: `frontend/src/components/shared/ShortcutHelpDialog.tsx`

- Display chord shortcuts with `G then M` formatting.
- Add "Edit shortcuts" button that opens the keybinding editor.
- Show page-specific shortcuts when opened from a specific page.
- Differentiate between global and page-specific shortcuts with subtle visual distinction.
- Show custom keybinding indicator (e.g., "Custom" badge) next to remapped shortcuts.

### 5.3 New: ChordIndicator Component

**File**: `frontend/src/components/shared/ChordIndicator.tsx`

- Fixed-position overlay in the bottom-right corner.
- Shows the pending first key and available second keys.
- Auto-dismisses after 1 second.
- Uses CSS `animate-in` for smooth enter/exit (from shadcn/ui animation utils).

### 5.4 New: KeybindingEditor Component

**File**: `frontend/src/pages/settings/KeybindingEditor.tsx`

- Lists all shortcuts grouped by category.
- Each row shows label, current key, and an "Edit" button.
- "Edit" puts the row in capture mode (visual highlight, "Press a key..." prompt).
- Conflict detection with inline warning.
- "Reset" button per binding and "Reset all" button.

```tsx
export function KeybindingEditor() {
  const shortcuts = shortcutRegistry.getAllShortcuts();
  const customBindings = useUiStore((s) => s.customKeybindings);
  const setKeybinding = useUiStore((s) => s.setKeybinding);
  const resetKeybinding = useUiStore((s) => s.resetKeybinding);
  const resetAllKeybindings = useUiStore((s) => s.resetAllKeybindings);

  const [editingLabel, setEditingLabel] = useState<string | null>(null);

  const handleKeyCapture = useCallback((e: KeyboardEvent) => {
    if (!editingLabel) return;
    e.preventDefault();

    const key = normalizeKeyEvent(e);
    if (key === "escape") {
      setEditingLabel(null);
      return;
    }

    // Check for conflicts
    const conflict = shortcutRegistry.hasConflict(key);
    if (conflict) {
      // Show conflict warning in UI
      toast.warning(`"${key}" conflicts with "${conflict.label}"`);
      return;
    }

    setKeybinding(editingLabel, key);
    setEditingLabel(null);
  }, [editingLabel, setKeybinding]);

  useEffect(() => {
    if (editingLabel) {
      document.addEventListener("keydown", handleKeyCapture);
      return () => document.removeEventListener("keydown", handleKeyCapture);
    }
  }, [editingLabel, handleKeyCapture]);

  const grouped = getGroupedShortcuts(shortcuts);
  const groupOrder = ["General", "Navigation", "Actions", "Messaging"];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Keyboard Shortcuts</h2>
        <Button variant="outline" size="sm" onClick={resetAllKeybindings}>
          Reset all to defaults
        </Button>
      </div>

      {groupOrder.filter((g) => grouped[g]?.length).map((group) => (
        <div key={group}>
          <h3 className="text-sm font-semibold text-muted-foreground mb-2">{group}</h3>
          <div className="space-y-1">
            {grouped[group]!.map((s) => {
              const currentKey = customBindings[s.label] ?? s.key;
              const isCustom = customBindings[s.label] !== undefined;
              const isEditing = editingLabel === s.label;

              return (
                <div key={s.label} className={cn(
                  "flex items-center justify-between py-2 px-3 rounded",
                  isEditing && "bg-primary/10 border border-primary",
                )}>
                  <span className="text-sm">{s.label}</span>
                  <div className="flex items-center gap-2">
                    {isCustom && <Badge variant="outline" className="text-[10px]">Custom</Badge>}
                    {isEditing ? (
                      <span className="text-sm text-primary animate-pulse">Press a key...</span>
                    ) : (
                      <kbd className="rounded border bg-muted px-2 py-0.5 font-mono text-xs">
                        {formatKey(currentKey)}
                      </kbd>
                    )}
                    <Button variant="ghost" size="sm" onClick={() => setEditingLabel(isEditing ? null : s.label)}>
                      {isEditing ? "Cancel" : "Edit"}
                    </Button>
                    {isCustom && (
                      <Button variant="ghost" size="sm" onClick={() => resetKeybinding(s.label)}>
                        Reset
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
```

### 5.5 Page-Level Shortcut Registration

Each page component registers its own shortcuts:

- **MessagesPage**: `n` (new), `j`/`k` (navigate), `Enter` (open), `Escape` (back to list)
- **FeedPage**: `n` (new post), `j`/`k` (navigate posts), `l` (like), `c` (comment)
- **FilesPage**: `n` (new folder), `u` (upload), `Delete` (delete selected), `Enter` (open)
- **TicketsPage**: `n` (new ticket), `j`/`k` (navigate), `a` (assign to me)
- **CalendarPage**: `n` (new event), `t` (today), `j`/`k` (next/prev day)

### 5.6 Updated AppShell

**File**: `frontend/src/components/layout/AppShell.tsx`

- Add `tabIndex={-1}` to `#main-content` div for programmatic focus
- Add `ChordIndicator` component rendering
- Wrap content in `ShortcutRegistryProvider`

```tsx
export function AppShell({ children }: { children: React.ReactNode }) {
  const [chordFirstKey, setChordFirstKey] = useState<string | null>(null);

  return (
    <ShortcutRegistryProvider value={shortcutRegistry}>
      <div className="flex h-screen">
        <Sidebar />
        <div className="flex flex-1 flex-col">
          <Header />
          <main id="main-content" tabIndex={-1} className="flex-1 overflow-auto outline-none">
            {children}
          </main>
        </div>
      </div>
      <ChordIndicator firstKey={chordFirstKey} chords={navigationChords} />
    </ShortcutRegistryProvider>
  );
}
```

---

## 6. E2E Test Plan

### Section 114: Navigation Chords

```
114.1  Press g then m within 1s: navigates to /messages
114.2  Press g then f within 1s: navigates to /feed
114.3  Press g then c within 1s: navigates to /calendar
114.4  Press g, wait 2s, then m: does NOT navigate (chord timeout)
114.5  Press g then m while input is focused: does NOT navigate
114.6  Chord indicator appears after pressing g, disappears after 1s
114.7  Press g then s: navigates to /settings
114.8  Press g then b: navigates to /billing
114.9  Press g then t: navigates to /tickets
114.10 Press g then unknown key: chord cancelled, no navigation
114.11 Press Ctrl+g then m: does NOT trigger chord (modifier blocks it)
114.12 Press g then m while IME composing: does NOT trigger chord
```

### Section 115: Page-Specific Shortcuts

```
115.1  On /messages, press n: New conversation dialog opens
115.2  On /feed, press n: Compose post form opens
115.3  On /messages, press j/k: selection moves between conversations
115.4  Press ? on /messages: help dialog shows messaging-specific shortcuts
115.5  On /files, press u: file upload input activates
115.6  On /tickets, press n: new ticket form opens
115.7  On /calendar, press t: calendar navigates to today
115.8  Page shortcuts are NOT active on other pages (n on /settings does nothing)
115.9  Page shortcuts are NOT active when input is focused
115.10 On /feed, press l: likes the currently selected post
```

### Section 116: Customizable Keybindings

```
116.1  Open Settings > Keyboard Shortcuts, click Edit on "Go to Messages"
116.2  Press "m" to remap: binding changes from "g,m" to "m"
116.3  Press m on dashboard: navigates to /messages (custom binding works)
116.4  Conflict detection: remapping to an existing binding shows warning
116.5  "Reset to defaults" restores original binding
116.6  Custom bindings persist after page reload (localStorage)
116.7  Custom bindings sync to server (PATCH /ui/settings/preferences)
116.8  "Reset all to defaults" clears all custom bindings
116.9  Custom badge appears next to remapped shortcuts in help dialog
116.10 Pressing Escape during key capture cancels the edit
```

### Section 117: Focus Management

```
117.1  After g,m navigation, first focusable element in messages page has focus
117.2  After g,f navigation, first focusable element in feed page has focus
117.3  Tab key after shortcut navigation reaches main content (not header)
117.4  Focus outline is visible on the focused element after navigation
117.5  After g,d navigation, dashboard heading is focusable (tabIndex=-1 on main)
```

### Section 118: Backward Compatibility

```
118.1  Ctrl+K still opens command palette (existing test 73.1)
118.2  Shift+? still opens shortcut help (existing test 75.1)
118.3  Ctrl+Shift+D still toggles dark mode (existing test 74.1)
118.4  Ctrl+Shift+N still navigates to /messages?new=1 (existing test 74.2)
118.5  Ctrl+Enter still sends message in ComposeBar (existing test 76.1)
118.6  ? in input still types character (existing test 75.3)
```

---

## 7. Edge Cases

1. **Chord vs single key**: Pressing `g` alone should not trigger any action --- only `g` followed by a second key. But `g` might be a valid single-key shortcut on a specific page (e.g., "go to top" in a list). The priority system handles this: page-level `g` takes priority over the global `g,*` chord prefix when on that page. However, the chord handler calls `e.preventDefault()` on the first key press, which would block the page-level `g` shortcut. Solution: only `preventDefault` on the first key if the chord handler is at a higher priority than any single-key `g` shortcut. In practice, page shortcuts should avoid using `g` as a single key.

2. **Modifier keys in chords**: The chord handler should NOT trigger when modifier keys are held. `Ctrl+g` followed by `m` should not trigger `g,m`. The chord handler should only activate on bare key presses (no ctrl/shift/alt/meta). This is implemented via the `if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;` guard.

3. **IME input**: When using Input Method Editors (Chinese, Japanese, Korean), key events fire during composition. The chord handler must check `e.isComposing` and skip those events. The `isComposing` property is `true` during IME composition on all modern browsers.

4. **Browser shortcut conflicts**: `Ctrl+N` (browser new window), `Ctrl+T` (new tab), `Ctrl+W` (close tab) are reserved by the browser and cannot be intercepted. The shortcut system must avoid these key combinations. All navigation shortcuts use chord sequences (`g,*`) or Ctrl+Shift combinations to avoid conflicts. The `useGlobalShortcuts` hook uses `e.preventDefault()` which blocks the browser's default behavior for interceptable shortcuts, but browser-reserved shortcuts fire before JavaScript event handlers.

5. **Multiple pages with same shortcut key**: If two pages both define `n` as "new item", only the currently mounted page's shortcut is active. The `usePageShortcuts` hook automatically unregisters shortcuts when the component unmounts.

6. **Rapid typing**: A user typing normally might accidentally trigger a chord if they type `g` followed quickly by `m`. The 1-second timeout mitigates this, but consider adding a minimum delay (100ms) --- the second key must come at least 100ms after the first to be treated as a chord, not as normal typing. However, this may feel sluggish for experienced users. A better approach: only activate chords when the user is NOT in an input field (already handled by `isInputFocused()`). Normal typing only happens in input fields, so false chord triggering from typing is not a concern.

7. **Screen readers**: Screen readers use keyboard shortcuts extensively. Ensure that all platform shortcuts are suppressible when a screen reader is detected. The `isInputFocused()` check covers most cases (screen readers focus on elements). Additionally, the chord handler's `isInputFocused()` check prevents chords from firing when the screen reader has focus on any interactive element. The `ChordIndicator` component should have `aria-hidden="true"` and `role="status"` with `aria-live="polite"` for screen reader announcements.

8. **Custom keybinding persistence across versions**: If the app adds new shortcuts in a future release, existing custom keybindings should not conflict with the new defaults. The custom keybindings are stored by label (e.g., "Go to Messages"), not by key. If a new shortcut is added with a key that conflicts with a custom binding, the conflict detection will flag it. However, the custom binding takes priority (page/component > global), so the new default shortcut is effectively hidden until the user resets their custom binding.

9. **Shortcut discoverability**: Users may not know that chords exist. The help dialog (?) should prominently show "Press G + key to navigate" as a header above the Navigation section. The ChordIndicator overlay provides real-time discoverability when the user accidentally presses `g`.

---

## 8. Security Considerations

1. **Keybinding storage**: Custom keybindings are stored in `localStorage` and synced to the server. The keybinding values are key combinations (strings like `g,m` or `ctrl+shift+n`). They cannot execute arbitrary code, so there is no injection risk. The backend validates the format via regex to prevent oversized or malformed values.

2. **XSS via shortcut labels**: Shortcut labels are displayed in the help dialog and keybinding editor. Since they are hardcoded strings (not user input), XSS is not a concern. However, if custom shortcut labels are ever added, they must be sanitized. React's default escaping (no `dangerouslySetInnerHTML`) provides defense in depth.

3. **Denial of service via rapid keys**: An automated tool could fire thousands of keyboard events per second. The shortcut handler's `e.preventDefault()` call is lightweight and does not pose a DoS risk. Navigation actions are rate-limited by React Router's transition mechanism. The chord handler's timer cleanup (`clearTimeout`) prevents timer accumulation.

4. **Shortcut phishing**: A malicious extension could simulate keyboard events to trigger shortcuts (e.g., programmatic `Ctrl+K` to open the command palette, then type a malicious URL). The command palette's `CommandDialog` only navigates to internal routes from `SEARCH_PAGES` --- it does not accept arbitrary URLs. The search API sanitizes input via `_sanitize_query` (`app/routers/search.py`, line 46) <!-- CORRECTED: was "line 33"; _sanitize_query is at line 46 -->. Navigation chords only navigate to hardcoded internal routes, not user-provided URLs.

5. **Custom keybinding size limit**: The server-side validation limits custom keybindings to 100 entries with 100-char labels and 30-char keys. This prevents the preferences record from growing unboundedly. The total serialized size of 100 custom keybindings is approximately 13KB, well within the 64KB DDB item size limit.

6. **CSRF on preferences PATCH**: The preferences PATCH endpoint requires CSRF validation. Custom keybindings are sent as part of the preferences payload and are protected by the same CSRF mechanism as all other preferences.

---

## Codebase References

> **NOTE**: The chord sequence system, chord indicator, and navigation chords have already been implemented. The `useChordShortcuts` and `useChordIndicator` hooks are in `useGlobalShortcuts.ts` and used by `Header.tsx`. Page-specific shortcuts (`usePageShortcuts`), `ShortcutRegistry` singleton, customizable keybindings (`KeybindingEditor`), and the separate `ChordIndicator` component have NOT been implemented yet.

| File | Line(s) | What |
|------|---------|------|
| `frontend/src/hooks/useGlobalShortcuts.ts` | 3 | `Shortcut` interface |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 19 | `normalizeKeyEvent()` |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 35 | `isInputFocused()` |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 48 | `useGlobalShortcuts()` hook |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 72 | `getGroupedShortcuts()` |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 83 | `ChordMapping` interface |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 108 | `useChordShortcuts()` hook (chord sequences) |
| `frontend/src/hooks/useGlobalShortcuts.ts` | 175 | `useChordIndicator()` hook |
| `frontend/src/components/layout/Header.tsx` | 88 | `SEARCH_PAGES` array (15 navigable pages) |
| `frontend/src/components/layout/Header.tsx` | 205 | `shortcuts` useMemo (6 global shortcuts) |
| `frontend/src/components/layout/Header.tsx` | 238 | `ctrl+enter` shortcut (display-only; handled in ComposeBar) |
| `frontend/src/components/layout/Header.tsx` | 263 | `useChordIndicator()` usage |
| `frontend/src/components/layout/Header.tsx` | 859-876 | Chord indicator inline UI rendering |
| `frontend/src/components/shared/ShortcutHelpDialog.tsx` | 12 | `formatKey()` (includes chord "G then M" formatting) |
| `frontend/src/components/shared/ShortcutHelpDialog.tsx` | 48 | `ShortcutHelpDialog` component |
| `frontend/src/components/shared/ShortcutHelpDialog.tsx` | 57 | `groupOrder` for display sections |
| `frontend/src/components/layout/AppShell.tsx` | 45 | `AppShell` component function |
| `frontend/src/components/layout/AppShell.tsx` | 60 | "Skip to content" link |
| `frontend/src/components/layout/AppShell.tsx` | 93 | `main-content` div (already has `tabIndex={-1}` and `outline-none`) |
| `frontend/src/pages/messages/ComposeBar.tsx` | 618 | `handleKeyDown` — Enter without Shift sends message |
| `app/routers/search.py` | 46 | `_sanitize_query()` |
| `frontend/e2e/keyboard-shortcuts.spec.ts` | — | E2E tests: sections 73-77 (12 tests) |
