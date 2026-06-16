# Messenger Compose "+" Menu — Implementation Tickets

The messenger compose bar (`frontend/src/pages/messages/ComposeBar.tsx`) has accumulated ~13 inline toolbar buttons plus a nested calendar dropdown and five inline checkbox "mode" toggles. This backlog compacts all secondary actions into a single "+" / overflow menu while keeping send and attach primary, without breaking existing E2E selectors.

## Milestone 1 — Discovery & Design

### MCM-001: Spike — inventory every compose action and the state it toggles
**Type:** Spike  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Enumerate every interactive control rendered by `ComposeBar.tsx` and the React state each mutates. Confirmed inventory:
  - **Toolbar buttons** (render block `ComposeBar.tsx:1534-1893`):
    - Attach file — `Paperclip`, triggers hidden `<input>` via `fileInputRef` (`ComposeBar.tsx:1537-1546`); gated on `onSendImage`; sets `pendingFile` through `handleFileChange` (`ComposeBar.tsx:709-726`).
    - Record voice message — `Mic`, sets `voiceRecording=true` (`ComposeBar.tsx:1556-1567`); gated on `onSendVoiceMessage`.
    - Gallery message — `Images`, toggles `galleryMode` (`ComposeBar.tsx:1568-1579`); gated on `onSendGallery`.
    - Lottery message — `Dices`, toggles `lotteryMode` (`ComposeBar.tsx:1580-1591`); gated on `onSendLottery`.
    - Share file from Files — `FolderOpen`, opens `filePickerOpen` (`ComposeBar.tsx:1592-1603`); gated on `onSendFileShare`.
    - Share video — `Video`, opens `videoPickerOpen` (`ComposeBar.tsx:1604-1616`); gated on `onSendVideoShare`.
    - Insert emoji — `Smile`, Popover `emojiPickerOpen`, `data-testid="emoji-button"` (`ComposeBar.tsx:1617-1637`).
    - Send a GIF — `Images`, Popover `gifPickerOpen` (`ComposeBar.tsx:1639-1660`).
    - Send a sticker — `StickerIcon`, Popover `stickerPickerOpen` (`ComposeBar.tsx:1662-1683`).
    - Calendar actions — `CalendarDays` `DropdownMenu` (`ComposeBar.tsx:1685-1726`) with five items: Share my calendar (`calendarPickerOpen`), Share an event (`eventPickerOpen`), Schedule a meeting (`meetingPollOpen`), Find a Time (`findDateTimeOpen`), Create a countdown (`countdownOpen`).
    - Save draft — `Button`, calls `handleSaveDraft` (`ComposeBar.tsx:1741-1752`); gated on `draftsEnabled`. Adjacent draft-status `<span>` (`ComposeBar.tsx:1728-1739`).
    - Schedule send — `Clock`, toggles inline `scheduleOpen` panel (`ComposeBar.tsx:1800-1868`); sets `scheduledAt`.
    - Send message — primary `Send` button (`ComposeBar.tsx:1869-1893`).
  - **Inline checkbox toggles** (rows `ComposeBar.tsx:730-894`): Encrypt message → `encryptEnabled` (`737`); View once → `viewOnceText` (`824`); Require tip to unlock → `lockEnabled` (`835`); Attach tip → `tipEnabled` (`851`); Message expires → `expiresEnabled` (`872`) + duration `<select>`.
  - **Per-file consumption toggles** inside the pending-file preview: view-once image/video, listen-once audio (`ComposeBar.tsx:1495-1530`).
- Classify each as **primary** (keep inline: textarea, Attach file, Send) vs **secondary** (move into "+" menu: gallery, lottery, file share, video share, GIF, sticker, calendar group, schedule send, save draft, and the encrypt/view-once/tip/lock/expire toggles surfaced as menu entries that open their existing inline editors).
- Catalogue the related dialogs that secondary actions open: `FilePickerDialog`, `VideoPickerDialog`, `CalendarPickerDialog`, `EventPickerDialog`, `MeetingPollComposer`, `FindDateTimeComposer`, `CountdownComposerDialog`, `VoiceRecorder` (all in `frontend/src/pages/messages/`).
- Document every feature-flag/prop gate per action (`isMessagingEncryptionEnabled`, `isMessagingViewOnceImageEnabled`, `onSendGallery`, etc.) so the menu hides unavailable actions exactly as the toolbar does today.

**Acceptance Criteria**
- A written inventory table (action → icon → state → callback prop/feature flag → primary/secondary) is committed to the ticket/PR description.
- The set of actions to migrate vs keep inline is agreed and listed.
- No production code changes in this ticket.

**Dependencies**
- None.

---

### MCM-002: Spike — audit E2E selectors that target compose actions
**Type:** Spike  
**Priority:** P0  
**Estimate:** 0.5 day

**Description**
- Catalogue selectors that the menu refactor must preserve or update. Confirmed usages:
  - `getByRole("button", { name: "Send message" })` — many call sites, e.g. `messaging-features.spec.ts:574,659,972,1566,1928`.
  - `getByLabel(/encrypt message/i)` — `messaging-features.spec.ts:389,397,418,547,626`.
  - `getByLabel(/view once/i)` — `messaging-features.spec.ts:358-372`.
  - `getByRole("button", { name: "Send a GIF" })` / `"Send a sticker"` — `gif-sticker-messages.spec.ts:691,701,711`.
  - `data-testid="emoji-button"` / `name: "Insert emoji"` — `emoji-messages.spec.ts`, `rich-comments.spec.ts`.
  - `getByRole("button", { name: "Calendar actions" })` — `calendar-messaging.spec.ts:1187,1192,1202,1212,1221`.
  - `getByRole("button", { name: "Scheduled messages" })` / `"Cancel scheduled message"` — `messaging-features.spec.ts:1154,1166` (these target ConversationView, not ComposeBar — note but do not change).
- For each selector decide: keep its label/`aria-label` identical on the moved control, or update the spec to first open the "+" menu then click the menu item.
- Identify specs requiring edits: `messaging-features.spec.ts`, `messaging-group.spec.ts`, `calendar-messaging.spec.ts`, `emoji-messages.spec.ts`, `gif-sticker-messages.spec.ts`, `rich-comments.spec.ts`.

**Acceptance Criteria**
- A selector-impact list (selector → file:line → keep-as-is / update) is committed to the PR description.
- A decision is recorded on whether the "+" trigger gets a stable `aria-label` (e.g. "More compose options") and `data-testid` (e.g. `compose-overflow-menu`).
- No production code changes in this ticket.

**Dependencies**
- MCM-001.

---

## Milestone 2 — Overflow Menu Component

### MCM-003: Build the "+" overflow menu component (grouped, icons + labels)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add a new `ComposeOverflowMenu` component under `frontend/src/pages/messages/` built on the existing shadcn `DropdownMenu` primitives already imported in `ComposeBar.tsx:29-34`.
- Render a single trigger `Button variant="ghost" size="icon"` with a `Plus` icon (add to the lucide import at `ComposeBar.tsx:2`), `aria-label="More compose options"` and `data-testid="compose-overflow-menu"`.
- Group menu items with `DropdownMenuLabel` / `DropdownMenuSeparator`:
  - **Media:** Gallery message, Lottery message, Share file from Files, Share video, Send a GIF, Send a sticker.
  - **Calendar:** Share my calendar, Share an event, Schedule a meeting, Find a Time, Create a countdown (reuse the labels/icons currently at `ComposeBar.tsx:1699-1723`).
  - **Message options:** Encrypt message, View once, Require tip to unlock, Attach tip, Message expires, Schedule send.
  - **Drafts:** Save draft (only when `draftsEnabled`).
- Each item shows its existing lucide icon + label (icons+labels, mirroring the calendar dropdown pattern at `ComposeBar.tsx:1700-1722`).
- The component accepts callbacks/handlers + current toggle state from `ComposeBar` via props (no business logic moves into the menu — it only opens dialogs / flips state owned by `ComposeBar`).
- Each item is conditionally rendered using the exact same gates the toolbar uses today (callback prop presence + feature flag), so unavailable actions never appear.

**Acceptance Criteria**
- `ComposeOverflowMenu` renders all available actions grouped under section labels with icon + text.
- Items hidden when their callback prop is absent or feature flag is off, matching current toolbar behaviour.
- Component is covered by a basic render test (renders expected items given props).
- No change yet to `ComposeBar` wiring (component added but integration is MCM-004+).

**Dependencies**
- MCM-001.

---

### MCM-004: Migrate media actions into the "+" menu; keep attach + send inline
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1.5 days

**Description**
- Remove the inline toolbar buttons for Gallery (`ComposeBar.tsx:1568-1579`), Lottery (`1580-1591`), Share file (`1592-1603`), Share video (`1604-1616`), GIF (`1639-1660`), and Sticker (`1662-1683`) from the toolbar row and route them through `ComposeOverflowMenu` items.
- Keep **Attach file** (`Paperclip`, `ComposeBar.tsx:1537-1546`), the **textarea** (`ComposeBar.tsx:1771-1797`), and **Send message** (`ComposeBar.tsx:1869-1893`) inline and primary.
- For GIF/sticker/emoji, which are `Popover`-based: the menu item should open the corresponding popover/picker (e.g. set `gifPickerOpen`/`stickerPickerOpen`); keep the picker `PopoverContent` rendering anchored appropriately (a popover anchored to a closed dropdown trigger needs the open-state moved to a controlled dialog or re-anchored — resolve so the picker still appears `side="top"`).
- Preserve the `secondary` active-state visual feedback for Gallery/Lottery/File-share (currently `variant={galleryMode ? "secondary" : "ghost"}` at `ComposeBar.tsx:1570`) by reflecting active mode in the menu item styling and/or a badge on the "+" trigger.
- Keep all inline editor panels (gallery zone `ComposeBar.tsx:967-1105`, lottery editor `1149-1322`, file-share preview `1399-1460`) unchanged — only their entry-point buttons move.

**Acceptance Criteria**
- Toolbar row shows only Attach, textarea, Send (plus the "+" trigger and any kept-inline primary controls per MCM-001).
- All six media actions are reachable from the "+" menu and open the same dialogs/modes as before.
- GIF and sticker pickers still open and send successfully.
- Active gallery/lottery/file-share mode is visually indicated.

**Dependencies**
- MCM-003.

---

### MCM-005: Migrate calendar, schedule-send, and message-option toggles into the "+" menu
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1.5 days

**Description**
- Fold the existing Calendar `DropdownMenu` (`ComposeBar.tsx:1685-1726`) into the "+" menu as the "Calendar" group rather than a second top-level dropdown; preserve the five item labels and the dialog wiring (`CalendarPickerDialog`, `EventPickerDialog`, `MeetingPollComposer`, `FindDateTimeComposer`, `CountdownComposerDialog`, `ComposeBar.tsx:1913-1960`).
- Move **Schedule send** (`Clock`, `ComposeBar.tsx:1800-1868`) into the menu; the menu item opens the existing schedule popover/panel (`scheduleOpen` state). Keep the "Scheduled: …" pill (`ComposeBar.tsx:1382-1397`) inline so a pending schedule remains visible.
- Move the inline checkbox toggles — Encrypt message (`737`), View once (`824`), Require tip to unlock (`835`), Attach tip (`851`), Message expires (`872`) — into the menu as checkable items (`DropdownMenuCheckboxItem`) bound to the same state setters. Their expanded editor panels (encrypt password block `ComposeBar.tsx:757-818`, lock panel `895-919`, tip panel `920-965`, expiry `<select>` `880-893`) continue to render inline below the bar when their toggle is on.
- Keep **Save draft** + draft-status indicator behaviour; surface Save draft as a menu item (gated on `draftsEnabled`).
- Preserve the mutual-exclusion logic between Lock and Tip (`ComposeBar.tsx:840,857`) and the "no payment method" disabled state + tooltip for Attach tip (`ComposeBar.tsx:847-870`).

**Acceptance Criteria**
- All five calendar sub-actions work from the "+" menu and open the correct dialogs.
- Schedule send opens its panel and a pending schedule still shows the inline pill.
- Encrypt / view-once / lock / tip / expire toggles flip the same state and reveal their inline editors; Lock⇄Tip mutual exclusion preserved.
- Attach tip stays disabled with its tooltip when the user has no payment method.

**Dependencies**
- MCM-004.

---

## Milestone 3 — Tests, A11y, Responsive

### MCM-006: Preserve or update E2E selectors for moved actions
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Apply the decisions from MCM-002. For actions now behind the "+" menu, update the affected specs to open the menu first.
- `calendar-messaging.spec.ts:1187-1221` currently clicks `name: "Calendar actions"`; either keep an `aria-label="Calendar actions"` on the calendar group trigger or rewrite to open "+" then click the calendar items.
- `gif-sticker-messages.spec.ts:691-711` (`"Send a GIF"`, `"Send a sticker"`) and `emoji-messages.spec.ts` / `rich-comments.spec.ts` (`data-testid="emoji-button"`) — decide per MCM-002 whether to keep emoji inline (recommended: emoji stays inline, it's a primary text affordance) or update specs.
- `getByLabel(/encrypt message/i)` and `getByLabel(/view once/i)` (`messaging-features.spec.ts:358-372,389-418,547,626`) now live in the menu — update specs to open the menu before toggling, OR ensure the menu checkbox item carries an accessible name matching `/encrypt message/i` and `/view once/i`.
- `name: "Send message"` (`messaging-features.spec.ts` + others) and `name: "Attach file"` must remain unchanged (these stay inline).
- Do not touch `"Scheduled messages"` / `"Cancel scheduled message"` (`messaging-features.spec.ts:1154,1166`) — they belong to ConversationView, not ComposeBar.

**Acceptance Criteria**
- `messaging-features.spec.ts`, `messaging-group.spec.ts`, `calendar-messaging.spec.ts`, `emoji-messages.spec.ts`, `gif-sticker-messages.spec.ts`, and `rich-comments.spec.ts` pass under `cd frontend && npx playwright test`.
- No selector relies on a removed inline button without first opening the "+" menu.
- `Send message` and `Attach file` selectors remain valid without changes.

**Dependencies**
- MCM-005.

---

### MCM-007: Keyboard a11y + ARIA menu semantics
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Ensure the "+" trigger and menu follow the WAI-ARIA menu/menubutton pattern (shadcn `DropdownMenu` provides this — verify `role="menu"`, `role="menuitem"`, `aria-haspopup`, `aria-expanded`).
- The trigger has a discoverable `aria-label` ("More compose options") and is reachable in tab order before the Send button.
- Open with Enter/Space, navigate items with arrow keys, close with Escape returning focus to the trigger.
- Checkable items (encrypt/view-once/lock/tip/expire) expose `aria-checked` (`DropdownMenuCheckboxItem`).
- Verify focus returns to the textarea after a menu item that opens then closes a dialog (e.g. emoji insert keeps caret per `insertEmoji`, `ComposeBar.tsx:312-332`).
- Confirm tooltips/disabled states (e.g. Attach tip with no PM) remain announced.

**Acceptance Criteria**
- Full keyboard operation: open, arrow-navigate, activate, Escape-close with focus restoration.
- Menu and items expose correct ARIA roles/states; checkable items report `aria-checked`.
- Axe/manual a11y check on the compose bar reports no new violations.

**Dependencies**
- MCM-005.

---

### MCM-008: Mobile / responsive layout for the compacted compose bar
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- The compose bar container (`ComposeBar.tsx:728-729`, `<div className="flex items-end gap-2">` at `1534`) previously overflowed on narrow screens due to ~13 buttons; verify the new layout (Attach, textarea, "+", Send) fits at 320px width.
- Ensure the "+" menu content is scrollable / uses an appropriate `side`/`align` and `max-h` so long grouped lists fit small viewports (test bottom-sheet vs dropdown on touch).
- Keep the textarea auto-grow (`handleInput`, `ComposeBar.tsx:702-707`, capped `max-h-[120px]`) working when the row is narrower.
- Verify inline editor panels (gallery/lottery/tip/lock/encrypt/expiry/schedule) remain usable and don't push Send off-screen on mobile.

**Acceptance Criteria**
- No horizontal overflow of the compose toolbar at 320–768px widths.
- "+" menu is fully reachable and scrollable on small/touch viewports.
- Textarea, Attach, "+", and Send remain visible and tappable (min 36px targets) on mobile.

**Dependencies**
- MCM-004.

---

### MCM-009: Regression test for the "+" overflow menu
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add a Playwright spec (e.g. `frontend/e2e/messaging-compose-menu.spec.ts`) that:
  - Opens a conversation, asserts the toolbar shows only the primary inline controls (Attach file, textarea, Send message) plus the "+" trigger (`data-testid="compose-overflow-menu"`).
  - Opens the "+" menu and asserts presence of grouped items: Gallery, Lottery, Share file, Share video, GIF, Sticker, the five Calendar items, Encrypt/View once/Lock/Tip/Expire toggles, Schedule send, Save draft (gated by flags).
  - Exercises representative actions end-to-end via the menu: send a GIF, toggle Encrypt and send an encrypted message, toggle View once, open a calendar dialog, and open Schedule send — reusing patterns from `messaging-features.spec.ts` and `gif-sticker-messages.spec.ts`.
  - Verifies keyboard open/navigate/Escape (per MCM-007).
- Use the established `injectAuth` + session-cookie patterns and `request` fixtures noted in project E2E conventions.

**Acceptance Criteria**
- New spec passes under `cd frontend && npx playwright test e2e/messaging-compose-menu.spec.ts`.
- The full suite (`just e2e`) shows no regressions in the six specs from MCM-006.
- Spec asserts both the decluttered inline bar and at least five actions reachable via the menu.

**Dependencies**
- MCM-006, MCM-007.

---
