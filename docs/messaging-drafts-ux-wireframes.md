# Messaging Drafts v1 — UX Wireframes & Interaction States

## Document metadata
- **Feature:** Messaging Drafts (v1)
- **Ticket:** MSGD-002
- **Status:** Final wireframes approved
- **Owner:** Product Design / Messaging UX
- **Last updated:** 2026-04-05

---

## 1) UX goals
- Make saving a draft obvious and low-friction.
- Keep draft management close to the composer context.
- Preserve clarity between "draft actions" and "send message" actions.
- Ensure full keyboard and screen-reader operability.

---

## 2) Layout regions
1. **Composer controls row** (attachments, save draft, schedule, send)
2. **Draft panel region** (hidden when no drafts, shown when drafts exist)
3. **Compose input** (textarea)
4. **Toast/inline feedback area**

---

## 3) Wireframes (low-fidelity)

### 3.1 Default state (no text, no drafts)

```text
┌─────────────────────────────────────────────────────────────────────┐
│ [Attach] [Gallery] [Save draft]        [Type a message...........] │
│                                                         [Send]      │
└─────────────────────────────────────────────────────────────────────┘
(no draft panel shown)
```

Behavior:
- Save draft is available but disabled validation triggers if clicked with empty input.
- No saved-drafts panel rendered.

---

### 3.2 Empty-input validation state (save attempted with empty text)

```text
┌─────────────────────────────────────────────────────────────────────┐
│ [Attach] [Gallery] [Save draft]        [Type a message...........] │
│                                                         [Send]      │
└─────────────────────────────────────────────────────────────────────┘
⚠ "Type a message before saving a draft"
```

Behavior:
- No draft is created.
- Error feedback appears via non-blocking toast.

---

### 3.3 Populated state (drafts exist)

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Saved drafts                                                       │
│ ┌───────────────────────────────────────────────────────────────┐   │
│ │ "Can we move this to tomorrow morning..." [Load] [Remove]    │   │
│ └───────────────────────────────────────────────────────────────┘   │
│ ┌───────────────────────────────────────────────────────────────┐   │
│ │ "Don’t forget to include the attachment"       [Load] [Remove]│  │
│ └───────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│ [Attach] [Gallery] [Save draft]        [Type a message...........] │
│                                                         [Send]      │
└─────────────────────────────────────────────────────────────────────┘
```

Behavior:
- Newest drafts appear first.
- Load replaces compose text and focuses textarea.
- Remove deletes the specific draft row immediately.

---

### 3.4 Error state (draft read/parse issue)

```text
┌─────────────────────────────────────────────────────────────────────┐
│ [Attach] [Gallery] [Save draft]        [Type a message...........] │
│                                                         [Send]      │
└─────────────────────────────────────────────────────────────────────┘
⚠ "Couldn’t load saved drafts. You can keep composing." 
```

Behavior:
- Composer remains usable.
- System falls back to empty draft list for this render cycle.
- No hard-blocking modal.

---

### 3.5 Loading state (future server-backed sync mode)

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Saved drafts                                                       │
│ [Loading drafts…]                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

Behavior:
- Reserved state for sync-enabled mode.
- For local-only v1 this is generally not visible, but component contract supports it.

---

## 4) Interaction annotations

### Save draft trigger
- Control label: **Save draft**.
- On activation with non-empty input: create draft + success toast.
- On activation with empty input: error toast, no draft mutation.

### Draft list row actions
- **Load:** replace textarea content with selected draft; keep draft entry.
- **Remove:** delete selected draft only.
- List order: reverse chronological by `saved_at`.

### Empty state behavior
- If list is empty, panel is omitted (no blank container).
- Composer remains primary focus area.

---

## 5) Accessibility annotations

### Semantic roles and names
- Save control is a native `button` with accessible name **"Save draft"**.
- Row actions are native buttons named **"Load"** and **"Remove"**.
- Draft container is announced with heading/text **"Saved drafts"** when present.

### Keyboard traversal
- Tab order: composer controls → save draft → textarea → send.
- In populated panel: row actions are reachable in reading order (top row to bottom row).
- Enter/Space activates Save/Load/Remove buttons.

### Focus management
- After **Load**, focus moves to textarea so user can continue editing immediately.
- After **Remove**, focus remains on next logical action in the same row (or previous/next row fallback).
- Toasts must not steal focus.

### Screen reader behavior
- Success and error feedback announced via polite live region/toast semantics.
- Draft text preview should be truncated visually but remain understandable when read.
- Buttons must not rely solely on icon-only affordances for meaning.

### Contrast and target sizing
- Draft action buttons meet minimum contrast ratio and target size guidance.
- No critical action is represented by color alone.

---

## 6) Responsive behavior notes

### Desktop
- Draft panel appears above composer with up to N visible rows (scroll optional if expanded design is introduced).

### Mobile
- Draft panel remains above composer; row content truncates earlier.
- Action buttons remain tappable and retain labels (no icon-only collapse in v1).

---

## 7) Copy deck (v1 baseline)
- Save success: **"Draft saved"**
- Empty save error: **"Type a message before saving a draft"**
- Parse/load fallback warning: **"Couldn’t load saved drafts. You can keep composing."**

---

## 8) Acceptance checklist for MSGD-002
- Wireframes include default, empty, populated, loading, and error states.
- Draft action controls and placement are defined.
- Accessibility behavior covers keyboard, focus, ARIA naming, and live announcements.
- Mobile/desktop behavior differences are documented.
