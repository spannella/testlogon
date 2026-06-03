# UX-002: Keyboard Shortcuts / Command Palette

**Ticket**: UX-002
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 3-5 days

---

## 1. Executive Summary

<!-- NOTE: This feature is ALREADY FULLY IMPLEMENTED. The global shortcuts hook exists at frontend/src/hooks/useGlobalShortcuts.ts, the ShortcutHelpDialog at frontend/src/components/shared/ShortcutHelpDialog.tsx, the shortcutStore at frontend/src/stores/shortcutStore.ts. Header.tsx already imports and uses useGlobalShortcuts (line 50, mounted at line 246), ShortcutHelpDialog (line 49, rendered at line 851), and has an "Actions" CommandGroup (line 606+). The uiStore already has recentCommands (line 28, 64, 89-92) and trackRecentCommand (line 47, 89-92). -->

The platform has a minimal command palette in the header that only supports page navigation. The `cmdk` library (package.json:46) is installed but its only non-trivial usage is `TimezoneCombobox.tsx`. There are no global keyboard shortcuts for common actions like sending a message, closing dialogs, or navigating between sections. Power users and accessibility-conscious users expect keyboard-driven workflows.

Keyboard-driven interfaces are a hallmark of professional-grade SaaS tools. Applications like Slack, Linear, Notion, and GitHub invest heavily in command palettes and shortcut systems because they dramatically reduce the time-to-action for experienced users. The current platform has the foundational library (`cmdk`) already installed and a working Ctrl+K listener, but the palette is limited to static page navigation with no action commands, no recent history, and no shortcut discoverability. Users who press Ctrl+K expecting to toggle dark mode, compose a new message, or search contacts are met with a simple 14-item page list.

This feature extends the existing `CommandDialog` in `Header.tsx` into a full command palette with actions (not just navigation), and adds a global keyboard shortcut system with a discoverable shortcut overlay (accessible via `?`). The `cmdk` library is already installed and the Ctrl+K listener already exists -- this is primarily a frontend feature that builds on existing infrastructure. No backend changes are required.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Command palette with actions**
As a power user, I want to press Ctrl+K to open a command palette that lets me both navigate to pages and perform actions (toggle dark mode, compose a new message, log out) so that I can accomplish tasks without reaching for the mouse.

Acceptance Criteria:
- Ctrl+K opens the command palette with both "Pages" and "Actions" groups visible.
- Typing "dark" filters to "Toggle Dark Mode" action.
- Pressing Enter on "Toggle Dark Mode" changes the theme immediately and closes the palette.
- The palette shows at least: New Message, New Post, Toggle Dark Mode, Log Out as action items.
- Each action item has an icon matching the navigation icon used elsewhere in the UI.

**US-2: Keyboard-driven message send**
As a user composing a message, I want Ctrl+Enter to send the message as an alternative to Enter, so that I can use Enter for newlines in multi-line messages.

Acceptance Criteria:
- Pressing Ctrl+Enter in the ComposeBar textarea sends the message.
- The existing Enter-to-send behavior (line 618 of ComposeBar.tsx) remains unchanged.
- Shift+Enter continues to insert a newline (existing behavior).

**US-3: Universal Escape key**
As a user, I want pressing Escape to close the topmost open dialog, popover, or sheet so that I have a consistent way to dismiss UI overlays.

Acceptance Criteria:
- Pressing Escape closes any open radix-ui Dialog, Sheet, or Popover.
- If multiple overlays are open (e.g., a dialog inside a sheet), Escape closes only the topmost one.
- If no overlay is open, Escape is a no-op (does not navigate away from the page).

**US-4: Shortcut reference overlay**
As a user, I want to press `?` to see all available keyboard shortcuts grouped by category so that I can learn the available shortcuts.

Acceptance Criteria:
- Pressing `?` when no input/textarea is focused opens a full-screen or modal dialog listing all shortcuts.
- Shortcuts are grouped by category (Navigation, Messaging, Actions, General).
- Each shortcut shows the key combination and a brief description.
- The overlay is closeable via Escape or clicking outside.
- Pressing `?` inside an input or textarea types the `?` character normally (no overlay).

**US-5: Section-level keyboard navigation**
As a power user, I want Ctrl+1 through Ctrl+9 to navigate to the first 9 sidebar items so that I can jump between sections without mouse interaction.

Acceptance Criteria:
- Ctrl+1 navigates to Dashboard (first sidebar item).
- Ctrl+2 navigates to Messages (second sidebar item).
- Ctrl+3 through Ctrl+9 navigate to their respective sidebar items.
- Ctrl+0 is reserved (no action) to avoid conflict with browser zoom reset.
- The shortcut mapping matches the visual order of sidebar items.

**US-6: Recently used commands**
As a returning user, I want the command palette to show my recently used commands first so that I can quickly repeat common actions.

Acceptance Criteria:
- The command palette shows a "Recently Used" section above "Pages" and "Actions".
- The section shows the last 5 commands used (including both navigation and actions).
- Recent commands are stored in Zustand (persisted to localStorage).
- Clicking a recent command executes it and moves it to the top of the recency list.

### 2.2 Pain Points

1. **No action commands**: The existing Ctrl+K dialog only navigates to pages -- it cannot compose a message, create a post, toggle theme, or perform any action.
2. **No shortcut discoverability**: There is no way for users to learn what shortcuts exist. Unlike Slack (`Ctrl+/`) or GitHub (`?`), the platform has no shortcut reference.
3. **Scattered keydown listeners**: ComposeBar.tsx:618 has its own Enter handler; no centralized shortcut system. Adding new shortcuts requires adding ad-hoc keydown listeners in individual components.
4. **Accessibility**: Screen reader users and keyboard-only users have no efficient navigation path beyond Tab. The command palette is the expected accessibility pattern for keyboard-first navigation.
5. **No Cmd+K parity on macOS**: The Ctrl+K listener (Header.tsx:141) checks `e.metaKey || e.ctrlKey`, so Cmd+K works on macOS. But there is no indication in the UI that Cmd+K is an option (no `Cmd+K` badge on the search button).

---

## 3. Current State Analysis

### 3.1 Existing Command Palette

`Header.tsx` imports `CommandDialog`, `CommandInput`, `CommandList`, `CommandEmpty`, `CommandGroup`, `CommandItem`, and `CommandShortcut` from `@/components/ui/command` (lines 41-47). A `SEARCH_PAGES` constant (line 88+) defines navigable pages across groups:

```typescript
const SEARCH_PAGES = [
  { label: "Dashboard", path: "/", group: "Pages" },
  { label: "Messages", path: "/messages", group: "Pages" },
  { label: "Feed", path: "/feed", group: "Pages" },
  { label: "Shop", path: "/shop", group: "Pages" },
  { label: "Cart", path: "/cart", group: "Pages" },
  { label: "Billing", path: "/billing", group: "Pages" },
  { label: "Orders", path: "/purchases", group: "Pages" },
  { label: "Subscriptions", path: "/subscriptions", group: "Pages" },
  { label: "Files", path: "/files", group: "Pages" },
  { label: "Calendar", path: "/calendar", group: "Pages" },
  { label: "Profile", path: "/profile", group: "Account" },
  { label: "Security", path: "/security", group: "Account" },
  { label: "Alerts", path: "/alerts", group: "Account" },
  { label: "Settings", path: "/settings", group: "Account" },
];
```

The `searchOpen` state (line 144) is toggled by clicking the search button (line 324) and by keyboard shortcut. The `CommandDialog` renders at line 550+ with multiple `CommandGroup` sections (Recently Used, Pages/Account, Actions, Recent Searches, Users, Posts, Catalog, Files, Messages).

<!-- NOTE: The command palette has ALREADY been extended with action commands (line 606+), recently used commands (line 561+), and full global search (users, posts, catalog, files, messages). The "Actions" group and "Recently Used" section described in this ticket are ALREADY IMPLEMENTED. -->

**Citations**:
- `frontend/src/components/layout/Header.tsx:41-47` -- cmdk imports (including CommandShortcut)
- `frontend/src/components/layout/Header.tsx:88+` -- `SEARCH_PAGES` navigation items
- `frontend/src/components/layout/Header.tsx:144` -- `const [searchOpen, setSearchOpen] = React.useState(false)`
- `frontend/src/components/layout/Header.tsx:550+` -- `CommandDialog` rendering with multiple CommandGroups (Recently Used, Pages, Actions, Search, etc.)
- `frontend/src/components/layout/Header.tsx:606+` -- `CommandGroup heading="Actions"` (already implemented)

### 3.2 cmdk Library Usage

`cmdk` is installed at version `^1.1.1` (package.json:46). Beyond Header.tsx, it is used only in `TimezoneCombobox.tsx` (lines 10-15) for timezone search within a `Popover`. The `Command` primitives from `@/components/ui/command` are shadcn/ui wrappers around `cmdk`, providing styled versions of the underlying command menu components.

The shadcn/ui `command.tsx` wrapper file exists at `frontend/src/components/ui/command.tsx`. It re-exports cmdk components with Tailwind styling and provides:
- `Command` -- the root wrapper
- `CommandDialog` -- a Dialog-wrapped command menu
- `CommandInput` -- search input
- `CommandList` -- scrollable result list
- `CommandEmpty` -- no-results fallback
- `CommandGroup` -- grouped results with heading
- `CommandItem` -- individual selectable item
- `CommandSeparator` -- visual separator
- `CommandShortcut` -- keyboard shortcut badge (used inside CommandItem)

**Citations**:
- `frontend/package.json:42` -- `"cmdk": "^1.1.1"`
- `frontend/src/components/shared/TimezoneCombobox.tsx:10-15` -- `Command` component usage
- `frontend/src/components/ui/command.tsx` -- shadcn/ui wrapper (exists, exports CommandShortcut)

### 3.3 Existing Keyboard Handlers

ComposeBar.tsx has a `handleKeyDown` function (line 618) that sends on Enter (non-Shift):

```typescript
const handleKeyDown = (e: React.KeyboardEvent) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    void handleSubmit();
  }
};
```

<!-- NOTE: A centralized global shortcut registry NOW EXISTS at frontend/src/hooks/useGlobalShortcuts.ts. Header.tsx uses useGlobalShortcuts (line 246) instead of a standalone keydown listener. -->

**Citations**:
- `frontend/src/pages/messages/ComposeBar.tsx:618-619` -- Enter to send handler
- `frontend/src/hooks/useGlobalShortcuts.ts` -- centralized shortcut registry (already implemented)

### 3.4 Sidebar Navigation Structure

The sidebar (`frontend/src/components/layout/Sidebar.tsx`) renders navigation items in groups. The item order is fixed in the component JSX. For Ctrl+1-9 mapping, the shortcut registry needs to know the ordered list of sidebar paths. The sidebar component uses `useUiStore` (line 143) for collapse state.

**Citations**:
- `frontend/src/components/layout/Sidebar.tsx:166-167` -- Sidebar component with collapsed state from `useUiStore`

### 3.5 Theme Store

The `setTheme` action in `uiStore.ts` (line 73) is the target for the "Toggle Dark Mode" command palette action. After UX-001, this action also syncs to the backend.

**Citations**:
- `frontend/src/stores/uiStore.ts:73` -- `setTheme: (theme) => {`

### 3.6 Gaps

<!-- NOTE: Items 1-6 are now RESOLVED. The implementation already exists. -->

1. ~~Command palette only navigates -- no action commands~~ **RESOLVED**: Actions CommandGroup at Header.tsx:606+
2. ~~No global keyboard shortcut registry or hook~~ **RESOLVED**: `frontend/src/hooks/useGlobalShortcuts.ts` exists, mounted at Header.tsx:246
3. ~~No shortcut reference overlay~~ **RESOLVED**: `frontend/src/components/shared/ShortcutHelpDialog.tsx` exists, rendered at Header.tsx:851
4. No section-level keyboard navigation (Ctrl+1 through Ctrl+9) -- may still need implementation
5. ~~No "recently used" or "recent actions" in the command palette~~ **RESOLVED**: `recentCommands` in uiStore.ts:28,64,89-92; "Recently Used" CommandGroup at Header.tsx:561
6. ~~No Cmd+K badge on the search button for discoverability~~ **RESOLVED**: Header.tsx:329 shows Cmd+K/Ctrl+K badge
7. No Ctrl+Enter alternative for message send -- may still need implementation
8. ~~The `CommandShortcut` component from shadcn/ui is available but unused~~ **RESOLVED**: imported at Header.tsx:47

---

## 4. Implementation Plan

### 4.1 Frontend: Shortcut Registry (`useGlobalShortcuts.ts`)

**New file `frontend/src/hooks/useGlobalShortcuts.ts`:**

A centralized shortcut registry that manages global keydown listeners. The hook:
- Registers a single `document.addEventListener("keydown", ...)` listener
- Maintains a registry of `Shortcut` definitions
- Checks if the active element is an input/textarea before firing non-input shortcuts
- Supports modifier keys (Ctrl/Cmd, Shift, Alt)
- Provides a `getShortcuts()` function for the help overlay

```typescript
import { useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useUiStore, type Theme } from "@/stores/uiStore";

export interface Shortcut {
  /** Key combination, e.g., "ctrl+k", "escape", "?", "ctrl+1" */
  key: string;
  /** Human-readable label for the help overlay */
  label: string;
  /** Category grouping for the help overlay */
  group: "Navigation" | "Messaging" | "Actions" | "General";
  /** The action to execute */
  action: () => void;
  /** Optional: only fire when this condition is true */
  when?: () => boolean;
  /** If true, the shortcut fires even when an input/textarea is focused */
  activeInInput?: boolean;
}

/**
 * Normalize a KeyboardEvent into a key string like "ctrl+k", "shift+?", etc.
 */
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

/**
 * Check if the currently focused element is an input, textarea, or
 * contenteditable element.
 */
function isInputFocused(): boolean {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if ((el as HTMLElement).isContentEditable) return true;
  return false;
}

// ─── Sidebar navigation mapping ────────────────────────────────

const SIDEBAR_PATHS = [
  "/",            // 1 - Dashboard
  "/messages",    // 2 - Messages
  "/contacts",    // 3 - Contacts
  "/feed",        // 4 - Feed
  "/files",       // 5 - Files
  "/calendar",    // 6 - Calendar
  "/shop",        // 7 - Shop
  "/billing",     // 8 - Billing
  "/tickets",     // 9 - Tickets
];

/**
 * Build the full shortcut list. Called once per mount.
 */
export function buildShortcuts(
  navigate: (path: string) => void,
  setTheme: (theme: Theme) => void,
  currentTheme: () => Theme,
  openCommandPalette: () => void,
  openShortcutHelp: () => void,
  handleLogout: () => void,
): Shortcut[] {
  const shortcuts: Shortcut[] = [
    // ─── General ──────────────────────────────────────────
    {
      key: "ctrl+k",
      label: "Open command palette",
      group: "General",
      action: openCommandPalette,
      activeInInput: true,
    },
    {
      key: "?",
      label: "Show keyboard shortcuts",
      group: "General",
      action: openShortcutHelp,
    },
    // ─── Navigation (Ctrl+1..9) ───────────────────────────
    ...SIDEBAR_PATHS.map((path, i) => ({
      key: `ctrl+${i + 1}`,
      label: `Go to ${path === "/" ? "Dashboard" : path.slice(1).charAt(0).toUpperCase() + path.slice(2)}`,
      group: "Navigation" as const,
      action: () => navigate(path),
    })),
    // ─── Actions ──────────────────────────────────────────
    {
      key: "ctrl+shift+n",
      label: "New message",
      group: "Actions",
      action: () => navigate("/messages?new=1"),
    },
    {
      key: "ctrl+shift+p",
      label: "New post",
      group: "Actions",
      action: () => navigate("/feed?compose=1"),
    },
    {
      key: "ctrl+shift+d",
      label: "Toggle dark mode",
      group: "Actions",
      action: () => {
        const next = currentTheme() === "dark" ? "light" : "dark";
        setTheme(next);
      },
    },
  ];
  return shortcuts;
}

/**
 * Custom hook that registers a global keydown listener for all shortcuts.
 * Mount this once at the app root (e.g., in AppShell or App.tsx).
 */
export function useGlobalShortcuts(shortcuts: Shortcut[]) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      const normalized = normalizeKeyEvent(e);
      for (const shortcut of shortcuts) {
        if (shortcut.key !== normalized) continue;
        if (!shortcut.activeInInput && isInputFocused()) continue;
        if (shortcut.when && !shortcut.when()) continue;
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

/**
 * Get all registered shortcuts for display in the help overlay.
 */
export function getGroupedShortcuts(shortcuts: Shortcut[]): Record<string, Shortcut[]> {
  const groups: Record<string, Shortcut[]> = {};
  for (const s of shortcuts) {
    if (!groups[s.group]) groups[s.group] = [];
    groups[s.group]!.push(s);
  }
  return groups;
}
```

### 4.2 Frontend: Extend Command Palette in Header.tsx

Add action commands to the existing `CommandDialog`. The changes are:

1. Add a `SEARCH_ACTIONS` array alongside `SEARCH_PAGES`:

```typescript
import {
  MessageSquare, PenLine, Moon, Sun, LogOut, Keyboard,
} from "lucide-react";

const SEARCH_ACTIONS = [
  {
    label: "New Message",
    group: "Actions",
    icon: MessageSquare,
    action: (nav: ReturnType<typeof useNavigate>) => nav("/messages?new=1"),
  },
  {
    label: "New Post",
    group: "Actions",
    icon: PenLine,
    action: (nav: ReturnType<typeof useNavigate>) => nav("/feed?compose=1"),
  },
  {
    label: "Toggle Dark Mode",
    group: "Actions",
    icon: Moon,
    action: (_nav: unknown, setTheme: (t: Theme) => void, theme: Theme) =>
      setTheme(theme === "dark" ? "light" : "dark"),
  },
  {
    label: "Keyboard Shortcuts",
    group: "Actions",
    icon: Keyboard,
    action: () => {
      // Will be handled by opening ShortcutHelpDialog
    },
  },
  {
    label: "Log Out",
    group: "Actions",
    icon: LogOut,
    action: (_nav: unknown, _st: unknown, _th: unknown, logout: () => void) => logout(),
  },
];
```

2. Add a `CommandGroup heading="Actions"` section inside the CommandDialog:

```typescript
<CommandGroup heading="Actions">
  {SEARCH_ACTIONS.map((action) => (
    <CommandItem
      key={action.label}
      value={action.label}
      onSelect={() => {
        action.action(navigate, setTheme, theme, handleLogout);
        setSearchOpen(false);
        trackRecentCommand(action.label);
      }}
    >
      <action.icon className="mr-2 h-4 w-4" />
      {action.label}
    </CommandItem>
  ))}
</CommandGroup>
```

3. Add a `CommandGroup heading="Recently Used"` section that tracks the last 5 commands used. The recent list is stored in a new Zustand store field or a separate `uiStore` slice.

4. Add `CommandShortcut` badges to show keyboard shortcuts next to items:

```typescript
<CommandItem key="Dashboard" value="Dashboard" onSelect={...}>
  Dashboard
  <CommandShortcut>Ctrl+1</CommandShortcut>
</CommandItem>
```

### 4.3 Frontend: Recent Commands Store

Add `recentCommands` state to the `uiStore.ts` (or a new store). This is persisted to localStorage.

```typescript
// In uiStore.ts — add to the interface and implementation:
interface UiState {
  // ... existing fields ...
  recentCommands: string[];
  trackRecentCommand: (label: string) => void;
}

// In the store:
recentCommands: [],
trackRecentCommand: (label) => {
  set((s) => {
    const filtered = s.recentCommands.filter((c) => c !== label);
    return { recentCommands: [label, ...filtered].slice(0, 5) };
  });
},

// In partialize:
partialize: (state) => ({
  theme: state.theme,
  sidebarCollapsed: state.sidebarCollapsed,
  recentCommands: state.recentCommands,
}),
```

### 4.4 Frontend: Shortcut Help Overlay

**New file `frontend/src/components/shared/ShortcutHelpDialog.tsx`:**

A `Dialog` that displays all registered shortcuts grouped by category. Triggered by pressing `?` when no input is focused, or via a "Keyboard Shortcuts" item in the command palette.

```typescript
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { Shortcut } from "@/hooks/useGlobalShortcuts";
import { getGroupedShortcuts } from "@/hooks/useGlobalShortcuts";
import { Badge } from "@/components/ui/badge";

interface ShortcutHelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  shortcuts: Shortcut[];
}

function formatKey(key: string): string {
  return key
    .split("+")
    .map((k) => {
      if (k === "ctrl") return navigator.platform.includes("Mac") ? "Cmd" : "Ctrl";
      if (k === "shift") return "Shift";
      if (k === "alt") return "Alt";
      if (k === "?") return "?";
      if (k === "escape") return "Esc";
      return k.length === 1 ? k.toUpperCase() : k.charAt(0).toUpperCase() + k.slice(1);
    })
    .join(" + ");
}

export default function ShortcutHelpDialog({
  open,
  onOpenChange,
  shortcuts,
}: ShortcutHelpDialogProps) {
  const grouped = getGroupedShortcuts(shortcuts);
  const groupOrder = ["General", "Navigation", "Actions", "Messaging"];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Keyboard Shortcuts</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 max-h-[60vh] overflow-y-auto">
          {groupOrder
            .filter((g) => grouped[g]?.length)
            .map((group) => (
              <div key={group}>
                <h3 className="text-sm font-semibold text-muted-foreground mb-2">
                  {group}
                </h3>
                <div className="space-y-1">
                  {grouped[group]!.map((s) => (
                    <div
                      key={s.key}
                      className="flex items-center justify-between py-1"
                    >
                      <span className="text-sm">{s.label}</span>
                      <Badge variant="outline" className="font-mono text-xs">
                        {formatKey(s.key)}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
```

The dialog renders as:

```
Keyboard Shortcuts
─────────────────────────────────────────
General
  Open command palette          Ctrl + K
  Show keyboard shortcuts              ?

Navigation
  Go to Dashboard              Ctrl + 1
  Go to Messages               Ctrl + 2
  Go to Contacts               Ctrl + 3
  ...

Actions
  New message            Ctrl + Shift + N
  New post               Ctrl + Shift + P
  Toggle dark mode       Ctrl + Shift + D

Messaging
  Send message                     Enter
  Send message (alternative) Ctrl+Enter
  Insert newline              Shift+Enter
```

### 4.5 Frontend: Global Shortcuts Summary

| Shortcut | Action | Context | Active in Input? |
|----------|--------|---------|------------------|
| `Ctrl+K` / `Cmd+K` | Open command palette | Global | Yes |
| `?` | Open shortcut help | Global | No |
| `Escape` | Close topmost dialog | Global | Yes (handled by radix-ui) |
| `Ctrl+1` through `Ctrl+9` | Navigate to sidebar item N | Global | No |
| `Ctrl+Shift+N` | New message | Global | No |
| `Ctrl+Shift+P` | New post | Global | No |
| `Ctrl+Shift+D` | Toggle dark mode | Global | No |

### 4.6 Frontend: Ctrl+Enter in ComposeBar

Add `Ctrl+Enter` as an alternative send trigger in `ComposeBar.tsx`. This change is minimal:

```typescript
// In ComposeBar.tsx, modify handleKeyDown (line 618):
const handleKeyDown = (e: React.KeyboardEvent) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    void handleSubmit();
  }
  // Ctrl+Enter as alternative send (for users who use Enter for newlines)
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    void handleSubmit();
  }
};
```

### 4.7 Frontend: Cmd+K Badge on Search Button

Add a keyboard shortcut badge to the search button in the header for discoverability:

```typescript
<Button variant="outline" className="..." onClick={() => setSearchOpen(true)}>
  <Search className="h-4 w-4" />
  <span className="hidden sm:inline">Search...</span>
  <kbd className="pointer-events-none ml-auto hidden select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium opacity-100 sm:flex">
    <span className="text-xs">{navigator.platform.includes("Mac") ? "⌘" : "Ctrl"}</span>K
  </kbd>
</Button>
```

### 4.8 Backend Changes

None. This is a frontend-only feature. The command palette actions trigger existing navigation and API calls. The shortcut system does not persist shortcuts to the backend (they are hardcoded in the client).

---

## 5. Data Model

No DynamoDB changes required. Recent commands are stored in localStorage via Zustand persist middleware (same pattern as the existing `theme` and `sidebarCollapsed` fields).

**localStorage key**: `"ui-store"`

**New field in persisted state:**
```json
{
  "theme": "dark",
  "sidebarCollapsed": false,
  "recentCommands": ["Toggle Dark Mode", "Messages", "Feed"]
}
```

---

## 6. API Design

No new API endpoints. All shortcuts trigger client-side navigation or existing API calls.

---

## 7. Frontend Implementation

### 7.1 Component Hierarchy

```
App.tsx
  └── ProtectedRoute
       └── AppShell
            ├── useGlobalShortcuts(shortcuts)     ← NEW: global keydown listener
            ├── Header.tsx
            │   ├── CommandDialog (extended)       ← MODIFIED: add Actions group + Recent
            │   └── ShortcutHelpDialog             ← NEW: ? key overlay
            ├── Sidebar.tsx
            └── Outlet
                 └── MessagesPage
                      └── ConversationView
                           └── ComposeBar          ← MODIFIED: add Ctrl+Enter
```

### 7.2 State Management

| Store | Field | Type | Purpose |
|-------|-------|------|---------|
| `useUiStore` | `recentCommands` | `string[]` | Last 5 executed command labels |
| Component state (Header) | `searchOpen` | `boolean` | Command palette open state (existing) |
| Component state (Header) | `shortcutHelpOpen` | `boolean` | Shortcut help dialog open state (new) |

### 7.3 React Query Keys

No new React Query keys. The command palette actions use existing navigation and store actions.

### 7.4 Responsive Behavior

- The command palette is already responsive (full-width on mobile via shadcn/ui Dialog).
- The shortcut help overlay uses `max-w-lg` with vertical scrolling for small screens.
- Ctrl+1-9 shortcuts are desktop-only (touch devices do not have Ctrl keys). No mobile fallback needed.
- The Cmd+K badge on the search button is hidden on mobile (`hidden sm:flex`).

### 7.5 Browser Shortcut Conflicts

Some Ctrl+N combinations conflict with browser defaults:
- `Ctrl+N`: New browser window (all browsers)
- `Ctrl+Shift+N`: New incognito window (Chrome)
- `Ctrl+Shift+P`: New private window (Firefox)

Mitigation: Use `e.preventDefault()` in the keydown handler. Modern browsers allow web apps to override most Ctrl+Shift combinations. However, `Ctrl+N` (new window) is NOT overridable in Chrome. The chosen shortcuts (`Ctrl+Shift+N`, `Ctrl+Shift+P`) ARE overridable.

**Tested override behavior:**
| Shortcut | Chrome | Firefox | Safari | Overridable? |
|----------|--------|---------|--------|-------------|
| `Ctrl+K` | Address bar focus | Address bar focus | Address bar focus | Yes (via `e.preventDefault()`) |
| `Ctrl+Shift+N` | Incognito | No default | No default | Yes in all |
| `Ctrl+Shift+P` | No default | Private window | No default | Yes in Chrome/Safari; Firefox blocks |
| `Ctrl+1-9` | Tab switch | Tab switch | Tab switch | Varies by browser |

**Note on Ctrl+1-9**: Browser tab switching is a strong default. We should NOT `preventDefault()` on these since users expect tab switching. Instead, use `Ctrl+Shift+1-9` or fall back to the command palette for section navigation. **Decision needed** (see Open Questions).

---

## 8. Testing Plan

### 8.1 Unit Tests (Vitest)

**File**: `frontend/src/hooks/useGlobalShortcuts.test.ts`

| # | Test Name | Description | Assertion |
|---|-----------|-------------|-----------|
| 1 | `normalizeKeyEvent handles Ctrl+K` | Fire KeyboardEvent with ctrlKey=true, key="k" | Returns "ctrl+k" |
| 2 | `normalizeKeyEvent handles Cmd+K on Mac` | Fire KeyboardEvent with metaKey=true, key="k" | Returns "ctrl+k" |
| 3 | `normalizeKeyEvent handles ? key` | Fire KeyboardEvent with key="?" | Returns "?" |
| 4 | `isInputFocused returns true for textarea` | Focus a textarea, call isInputFocused() | Returns true |
| 5 | `isInputFocused returns false for body` | Focus document.body, call isInputFocused() | Returns false |
| 6 | `shortcut with activeInInput fires in input` | Register shortcut with activeInInput=true, focus input, fire key | Action called |
| 7 | `shortcut without activeInInput skips input` | Register shortcut without activeInInput, focus input, fire key | Action NOT called |
| 8 | `shortcut with when condition` | Register shortcut with when=() => false, fire key | Action NOT called |
| 9 | `getGroupedShortcuts groups correctly` | Pass 3 shortcuts in 2 groups | Returns { "General": [1], "Actions": [2] } |
| 10 | `formatKey renders Mac Cmd` | Mock navigator.platform to "MacIntel" | Returns "Cmd + K" |

**File**: `frontend/src/stores/uiStore.test.ts`

| # | Test Name | Description | Assertion |
|---|-----------|-------------|-----------|
| 11 | `trackRecentCommand adds to front` | Track "Messages" | recentCommands[0] === "Messages" |
| 12 | `trackRecentCommand deduplicates` | Track "Messages" twice | recentCommands has exactly one "Messages" |
| 13 | `trackRecentCommand caps at 5` | Track 7 items | recentCommands.length === 5 |

### 8.2 E2E Tests

**File**: `frontend/e2e/keyboard-shortcuts.spec.ts`

| # | Section | Test Name | Description | Assertion |
|---|---------|-----------|-------------|-----------|
| 1 | 1 | Ctrl+K opens command palette | Press Ctrl+K | CommandDialog visible |
| 2 | 1 | Typing filters commands | Type "mess" in palette | "Messages" item visible, others filtered |
| 3 | 1 | Enter on Messages navigates | Select "Messages", press Enter | URL is `/messages` |
| 4 | 1 | Actions group present | Open palette | "Toggle Dark Mode" item visible |
| 5 | 2 | Toggle Dark Mode action | Select "Toggle Dark Mode" | `document.documentElement.classList` toggles |
| 6 | 2 | New Message action | Select "New Message" | URL is `/messages?new=1` |
| 7 | 3 | ? key opens shortcut help | Press `?` (no input focused) | Dialog with "Keyboard Shortcuts" heading visible |
| 8 | 3 | Escape closes shortcut help | Press `?`, then Escape | Dialog closed |
| 9 | 3 | ? in input types character | Focus search input, type `?` | Input value contains `?`, no dialog |
| 10 | 4 | Recently used shows last command | Execute "Messages", reopen palette | "Recently Used" group has "Messages" |
| 11 | 4 | Recent commands cap at 5 | Execute 6 commands, reopen palette | "Recently Used" has exactly 5 items |

```typescript
// Example E2E test
import { test, expect } from "@playwright/test";
import { injectAuth } from "./helpers";

test.describe("UX-002: Keyboard shortcuts", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");
    await page.waitForLoadState("domcontentloaded");
  });

  test("Ctrl+K opens command palette dialog", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await expect(page.getByPlaceholder("Search pages...")).toBeVisible();
  });

  test("Typing 'dark' filters to Toggle Dark Mode", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await page.getByPlaceholder("Search pages...").fill("dark");
    await expect(page.getByText("Toggle Dark Mode")).toBeVisible();
    // Other items should be filtered out
    await expect(page.getByText("Dashboard")).not.toBeVisible();
  });

  test("? key opens shortcut help overlay", async ({ page }) => {
    // Ensure no input is focused
    await page.locator("body").click();
    await page.keyboard.press("?");
    await expect(page.getByRole("heading", { name: "Keyboard Shortcuts" })).toBeVisible();
  });
});
```

---

## 9. Security Considerations

### 9.1 No New Attack Surface

This feature is entirely client-side. No new API endpoints, no new data storage, no new authentication flows. The keyboard shortcuts trigger existing navigation and store actions that are already available through the UI.

### 9.2 XSS via Command Labels

All command labels are hardcoded constants (not user input). The `CommandItem` renders labels via React JSX text interpolation, which auto-escapes HTML entities. There is no risk of XSS from command labels.

### 9.3 Log Out Action

The "Log Out" action in the command palette calls the same `handleLogout()` function used by the header dropdown. It properly clears the auth store and navigates to `/login`. No special security consideration.

---

## 10. Performance Considerations

### 10.1 Event Listener Overhead

A single `document.addEventListener("keydown", ...)` listener is registered. The handler iterates through ~20 shortcut definitions per keypress. This is negligible overhead (< 0.1ms per event).

### 10.2 Bundle Size

- `cmdk` is already installed. No new npm dependency.
- `useGlobalShortcuts.ts` is ~150 lines (~2KB gzipped).
- `ShortcutHelpDialog.tsx` is ~100 lines (~1.5KB gzipped).
- Total bundle increase: ~3.5KB gzipped.

### 10.3 Render Performance

The shortcut help dialog is lazy-rendered (only mounts when `shortcutHelpOpen` is true). The command palette is already lazy-rendered via radix-ui Dialog.

---

## 11. Migration / Rollout Plan

### 11.1 Feature Flag

No feature flag needed. The shortcuts are additive -- they do not change existing behavior. The existing Ctrl+K handler in Header.tsx is replaced by the centralized `useGlobalShortcuts` hook, but the behavior is identical.

### 11.2 Backward Compatibility

- The existing Ctrl+K behavior is preserved (opens command palette).
- The existing Enter-to-send behavior in ComposeBar is preserved.
- The existing Escape handling by radix-ui Dialog is preserved.
- No localStorage format change (the `recentCommands` field is added to the existing `ui-store` key).

### 11.3 Rollout Steps

1. Deploy `useGlobalShortcuts.ts` and `ShortcutHelpDialog.tsx`.
2. Modify `Header.tsx` to add action commands and recent section.
3. Remove the standalone Ctrl+K handler from `Header.tsx` (replaced by `useGlobalShortcuts`).
4. Modify `ComposeBar.tsx` to add Ctrl+Enter.
5. Mount `useGlobalShortcuts` in `AppShell.tsx`.

---

## 12. Acceptance Criteria

1. Ctrl+K opens the command palette with both navigation pages and action commands.
2. Action commands (Toggle Dark Mode, New Message, New Post, Log Out) execute correctly from the palette.
3. The command palette shows a "Recently Used" section with the last 5 executed commands.
4. Pressing `?` (when no input is focused) opens a keyboard shortcut reference dialog.
5. The shortcut help dialog groups shortcuts by category (General, Navigation, Actions, Messaging).
6. All shortcuts work on both macOS (Cmd) and Windows/Linux (Ctrl).
7. `Ctrl+Enter` sends a message in the ComposeBar as an alternative to Enter.
8. Typing `?` in an input field does NOT open the shortcut help dialog.
9. The search button in the header shows a `Cmd+K` / `Ctrl+K` badge.
10. The command palette filters correctly when typing (both pages and actions are searchable).

---

## 13. Dependencies

### 13.1 Internal Dependencies

- `cmdk` library (already installed at `^1.1.1`).
- `@/components/ui/command` shadcn/ui wrapper (already exists).
- `useUiStore` for theme toggle and sidebar state.
- `useAuthStore` for logout action.

### 13.2 External Dependencies

None. No new npm packages required.

### 13.3 Related Tickets

- **UX-001 (Dark Mode Sync)**: The "Toggle Dark Mode" action uses the `setTheme` action which, after UX-001, syncs to the backend.
- **UX-003 (Drag-and-Drop Reorder)**: No dependency.

---

## 14. Open Questions / Risks

1. **Ctrl+1-9 vs. browser tab switching**: Most browsers use Ctrl+1-9 to switch between tabs. Overriding this may confuse users. Options:
   - (a) Use `Ctrl+1-9` and `preventDefault()` -- breaks browser tab switching when the app is focused.
   - (b) Use `Alt+1-9` instead -- less common, less conflicting.
   - (c) Drop section-level shortcuts and rely on the command palette for navigation.
   - **Recommendation**: Option (c) -- drop Ctrl+1-9, add keyboard shortcut badges to palette items instead.

2. **Ctrl+Shift+P conflicts with Firefox private window**: Firefox blocks override of this shortcut. Options:
   - (a) Accept that it does not work in Firefox.
   - (b) Use a different shortcut for "New Post" (e.g., `Ctrl+Shift+O`).

3. **Command palette search quality**: The current cmdk search is fuzzy. "dark" matches "Toggle Dark Mode" but also "Dashboard" (contains "da"). The cmdk scoring algorithm may need tuning to prioritize exact prefix matches.

4. **Mobile keyboard shortcuts**: Mobile browsers do not support keyboard shortcuts (no physical keyboard). The shortcut help dialog should detect mobile viewports and show a "Keyboard shortcuts are available on desktop" message instead of the shortcut list.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/hooks/useGlobalShortcuts.ts` | Centralized keyboard shortcut registry and listener |
| `frontend/src/components/shared/ShortcutHelpDialog.tsx` | Shortcut reference overlay dialog |
| `frontend/e2e/keyboard-shortcuts.spec.ts` | E2E tests |
| `frontend/src/hooks/useGlobalShortcuts.test.ts` | Unit tests for shortcut normalization and registry |

## 16. Files to Modify

| File | Change |
|------|--------|
| `frontend/src/components/layout/Header.tsx` | Add `SEARCH_ACTIONS`, "Recently Used" CommandGroup, action command execution, `shortcutHelpOpen` state, `ShortcutHelpDialog` rendering, `CommandShortcut` badges, Cmd+K badge on search button |
| `frontend/src/components/layout/AppShell.tsx` | Mount `useGlobalShortcuts` hook at the top level |
| `frontend/src/stores/uiStore.ts` | Add `recentCommands: string[]` state and `trackRecentCommand` action; add to `partialize` |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add `Ctrl+Enter` send handler (line 618) |

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_keyboard_shortcuts.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_shortcut_registry_stores_bindings` | Shortcut registry stores bindings verified |
| 2 | `test_shortcut_conflict_detection` | Shortcut conflict detection verified |
| 3 | `test_shortcut_context_scoping` | Shortcut context scoping verified |
| 4 | `test_shortcut_disabled_in_input_fields` | Shortcut disabled in input fields verified |
| 5 | `test_custom_shortcut_persistence` | Custom shortcut persistence verified |
| 6 | `test_default_shortcuts_loaded` | Default shortcuts loaded verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Register global shortcut -> press key -> navigation occurs
2. Shortcut in text input field -> shortcut suppressed -> normal typing
3. Custom shortcut saved -> reload -> custom binding active

### E2E Tests (Playwright)

**File**: `frontend/e2e/keyboard-shortcuts.spec.ts`
**Sections**: 1-3 (10 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Ctrl+K opens search | Press Ctrl+K; CommandDialog visible |
| 2 | G then M navigates to messages | Press g then m; URL is /messages |
| 3 | Shortcut disabled in text input | Focus input; press shortcut; no navigation |
| 4 | ? opens shortcut help | Press ?; help dialog visible |
| 5 | Esc closes dialogs | Open dialog; press Esc; dialog closed |
| 6 | Custom shortcut binding | Rebind shortcut; new key works |

**Negative tests**: Shortcut conflict warning, invalid key combination rejected

**Edge cases**: Modifier keys on Mac vs Windows, rapid key sequences, shortcut during modal

### Test Data Requirements

- **DDB seeds**: Default shortcut registry
- **Test users**: Alice

### CI/Pipeline Considerations

- **Feature flags**: None
- **Serial execution**: Tests must ensure no keyboard event leakage between tests
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| Header (existing) | CommandDialog for Ctrl+K search |

### Depended On By

| Ticket | Reason |
|--------|--------|
| SOCIAL-001 | Ctrl+D bookmark shortcut (deferred) |

### Merge Strategy: **Independent**

Frontend-only feature. No backend changes required.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| cmdk installed | `frontend/package.json` | 46 | VERIFIED: `"cmdk": "^1.1.1"` |
| cmdk imports in Header | `frontend/src/components/layout/Header.tsx` | 41-47 | VERIFIED (includes CommandShortcut) |
| SEARCH_PAGES navigation items | `frontend/src/components/layout/Header.tsx` | 88+ | VERIFIED |
| searchOpen state | `frontend/src/components/layout/Header.tsx` | 144 | VERIFIED |
| CommandDialog rendering | `frontend/src/components/layout/Header.tsx` | 550+ | VERIFIED: multiple CommandGroups (Recently Used, Pages, Actions, Search results) |
| Actions group in palette | `frontend/src/components/layout/Header.tsx` | 606+ | VERIFIED: **already implemented** |
| TimezoneCombobox cmdk usage | `frontend/src/components/shared/TimezoneCombobox.tsx` | 10-15 | VERIFIED |
| ComposeBar Enter handler | `frontend/src/pages/messages/ComposeBar.tsx` | 618-619 | VERIFIED |
| Global shortcut registry | `frontend/src/hooks/useGlobalShortcuts.ts` | exists | VERIFIED: **already implemented** |
| ShortcutHelpDialog | `frontend/src/components/shared/ShortcutHelpDialog.tsx` | exists | VERIFIED: **already implemented** |
| useGlobalShortcuts mounted | `frontend/src/components/layout/Header.tsx` | 246 | VERIFIED |
| ShortcutHelpDialog rendered | `frontend/src/components/layout/Header.tsx` | 851 | VERIFIED |
| shortcutHelpOpen state | `frontend/src/components/layout/Header.tsx` | 148 | VERIFIED |
| recentCommands in uiStore | `frontend/src/stores/uiStore.ts` | 28, 64, 89-92 | VERIFIED: **already implemented** |
| trackRecentCommand action | `frontend/src/stores/uiStore.ts` | 47, 89-92 | VERIFIED |
| CommandShortcut export | `frontend/src/components/ui/command.tsx` | 112, 125 | VERIFIED |
| Sidebar uses uiStore | `frontend/src/components/layout/Sidebar.tsx` | 166-167 | VERIFIED |
| Cmd+K badge on search button | `frontend/src/components/layout/Header.tsx` | 329 | VERIFIED: **already implemented** |
| shortcutStore | `frontend/src/stores/shortcutStore.ts` | exists | VERIFIED |
