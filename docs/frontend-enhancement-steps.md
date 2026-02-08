# Frontend Enhancement Plan — 15-Step Implementation Guide

> Breaks the [enhancement plan](./frontend-enhancement-plan.md) into 15 sequenced,
> shippable steps. Each step produces a working build and can be committed independently.
> Steps are sized to match the original redesign plan (~3-8 files, 200-500 lines each).

---

## Technical Conventions (carry forward from original plan)

- All new pages use `React.lazy()` in App.tsx (code splitting already wired).
- Page pattern: `PageHeader` + optional `Tabs` wrapper.
- Forms: React Hook Form + Zod schema.
- Mutations: `useMutation` + `queryClient.invalidateQueries` + `toast`.
- Infinite scroll: `useInfiniteQuery` + IntersectionObserver sentinel.
- Empty states: `EmptyState` with `icon={<Icon className="h-8 w-8" />}` (ReactNode),
  `action={{ label, onClick }}`.
- Destructive actions: `ConfirmDialog` with `variant="danger"`.
- Types in `src/api/types.ts`, endpoints in `src/api/endpoints/<domain>.ts`.
- Strict TS: `noUnusedLocals`, `noUnusedParameters`, `noUncheckedIndexedAccess`.
- Cannot use `.at()`. Must parenthesise mixed `??`/`||`.

---

## Step 1 — Purchase History: API Layer & Transaction List

**Goal:** Expose the purchase history system with a searchable order list.

**Backend endpoints wired:**
- `GET /ui/purchase-history/transactions` — list (params: `limit`, `status`)
- `GET /ui/purchase-history/transactions/search` — search (params: `q`, `limit`)

**Types to add in `src/api/types.ts`:**
```typescript
// Already exists: PurchaseTransactionSummary, PurchaseTransactionInfo, PurchaseShipping
// (added during original Step 13 types pass — verify and add any missing fields)
```

**Files created/modified:**
```
src/api/endpoints/purchases.ts           — NEW: listTransactions, searchTransactions,
                                            getTransaction, updateShipping, markComplete,
                                            markReverted, requestCancel, respondCancel,
                                            listEvents, getReceipt
src/pages/purchases/PurchaseHistory.tsx  — NEW: DataTable with date, description, amount,
                                            status badge. Search bar with debounced input.
                                            Status filter chips (all, pending, completed,
                                            cancelled, reverted). Load-more pagination.
src/pages/purchases/PurchasesPage.tsx    — NEW: PageHeader + PurchaseHistory (single tab
                                            for now; detail added in Step 2)
src/App.tsx                              — Add lazy `/purchases` route
src/components/layout/Sidebar.tsx        — Add "Orders" nav item under Commerce group
src/components/layout/AppShell.tsx       — Add "Orders" to mobile sidebar nav
src/components/layout/Header.tsx         — Add "Orders" to search palette
```

**UI details:**
- Status badges: `pending` → yellow, `completed` → green, `cancelled` → grey,
  `reverted` → red. Use `StatusBadge` component.
- Amount formatted as currency with `Intl.NumberFormat`.
- Search input with 300ms debounce. Switches between `listTransactions` and
  `searchTransactions` based on whether query is present.
- Empty state: Package icon, "No orders yet", link to Shop.

---

## Step 2 — Purchase History: Transaction Detail & Actions

**Goal:** Full order detail view with shipping timeline, receipt, cancellation.

**Backend endpoints wired:**
- `GET /ui/purchase-history/transactions/{txn_id}` — full detail
- `PUT /ui/purchase-history/transactions/{txn_id}/shipping` — update shipping
- `POST /ui/purchase-history/transactions/{txn_id}/complete` — mark complete
- `POST /ui/purchase-history/transactions/{txn_id}/revert` — revert
- `POST /ui/purchase-history/transactions/{txn_id}/cancel/request` — request cancel
- `POST /ui/purchase-history/transactions/{txn_id}/cancel/respond` — respond to cancel
- `GET /ui/purchase-history/transactions/{txn_id}/events` — audit trail
- `GET /ui/purchase-history/transactions/{txn_id}/receipt` — receipt link

**Files created/modified:**
```
src/pages/purchases/TransactionDetail.tsx — NEW: Summary card (amount, status, dates,
                                             merchant), shipping timeline component,
                                             events audit trail as vertical timeline,
                                             receipt download button, action buttons
                                             (complete, revert, cancel request)
src/pages/purchases/ShippingTimeline.tsx  — NEW: Visual stepper showing order status
                                             flow: Pending → Shipped → Delivered → Completed
                                             with branching for cancelled/reverted
src/pages/purchases/CancelDialog.tsx     — NEW: Cancel request dialog with reason input,
                                             cancel respond dialog (approve/deny)
src/pages/purchases/PurchasesPage.tsx    — Add route handling: list view + detail view
                                             (click row navigates to detail, or use
                                             sheet/drawer)
src/App.tsx                              — Add `/purchases/:txnId` route
```

**UI details:**
- Shipping timeline: Horizontal stepper with icons for each status. Current step
  highlighted. Branching path for cancelled state.
- Events timeline: Vertical list with timestamp, event type badge, description.
  Collapsible if >10 events.
- Receipt: "Download Receipt" button that fetches receipt link and opens in new tab.
- Cancel flow: "Request Cancellation" → reason dialog → POST. If cancel pending,
  show "Approve/Deny" buttons for the respond endpoint.

---

## Step 3 — Subscription Plans & Management

**Goal:** Browse subscription plans, subscribe, manage active subscriptions.

**Backend endpoints wired:**
- `GET /api/creators/{creator_id}/plans` — list plans
- `POST /api/plans/{plan_id}/subscribe` — subscribe
- `GET /api/subscriptions` — my subscriptions
- `GET /api/subscriptions/{sub_id}/invoices` — invoices
- `GET /api/subscriptions/{sub_id}/summary` — summary
- `POST /api/subscriptions/{sub_id}/cancel` — cancel
- `POST /api/subscriptions/{sub_id}/resume` — resume
- `POST /api/subscriptions/{sub_id}/change-plan` — upgrade/downgrade
- `POST /api/subscriptions/{sub_id}/renewal` — update renewal settings

**Types to add in `src/api/types.ts`:**
```typescript
interface SubscriptionPlan {
  plan_id: string; creator_id: string; name: string; description?: string;
  amount_cents: number; currency: string; interval: string; interval_count: number;
  trial_days?: number; features?: string[]; status: string; created_at: number;
}
interface SubscriptionDetail {
  subscription_id: string; plan_id: string; plan?: SubscriptionPlan;
  subscriber_id: string; status: string; current_period_start?: number;
  current_period_end?: number; cancel_at_period_end?: boolean;
  trial_end?: number; created_at: number;
}
interface SubscriptionInvoice {
  invoice_id: string; amount_cents: number; currency: string;
  status: string; period_start: number; period_end: number; paid_at?: number;
}
interface SubscribeReq { discount_code?: string; }
interface SubscriptionCancelReq { reason?: string; at_period_end?: boolean; }
interface SubscriptionResumeReq { }
interface SubscriptionChangePlanReq { new_plan_id: string; }
```

**Files created/modified:**
```
src/api/endpoints/subscriptions.ts        — NEW: listPlans, subscribe, listSubscriptions,
                                             getSubscriptionSummary, listInvoices,
                                             cancelSubscription, resumeSubscription,
                                             changePlan, updateRenewal
src/pages/subscriptions/PlanBrowser.tsx   — NEW: Grid of pricing cards. Each card shows
                                             plan name, price/cycle, trial badge, feature
                                             bullets, "Subscribe" CTA. Discount code input
                                             field with inline validation.
src/pages/subscriptions/MySubscriptions.tsx — NEW: Card list of active subs. Each card:
                                              plan name, status badge, next billing date,
                                              price/cycle. Actions: Pause/Resume, Cancel
                                              (ConfirmDialog), Change Plan dropdown.
                                              Expandable invoice history per subscription.
src/pages/subscriptions/SubscriptionsPage.tsx — NEW: PageHeader + Tabs (Browse Plans |
                                                 My Subscriptions)
src/App.tsx                               — Add lazy `/subscriptions` route
src/components/layout/Sidebar.tsx         — Add "Subscriptions" nav item under Commerce
src/components/layout/AppShell.tsx        — Add to mobile sidebar
src/components/layout/Header.tsx          — Add to search palette
```

**UI details:**
- Plan cards: Highlighted "Popular" badge on middle plan. Price formatted as
  "$X.XX / month". Trial shown as "Free for N days" badge.
- Discount code: Input + "Apply" button → validates via API → shows green check
  with adjusted price or red error.
- Cancel dialog: Radio choice "Cancel immediately" vs "Cancel at period end".
  Reason textarea. Destructive confirm button.

---

## Step 4 — Messaging: Presence, Typing & User Search

**Goal:** Add real-time presence indicators, typing animations, and user discovery.

**Backend endpoints wired:**
- `POST /messaging/presence/heartbeat` — send heartbeat
- `GET /messaging/users/{user_id}/presence` — get presence
- `POST /messaging/conversations/{id}/typing` — send typing signal
- `GET /messaging/conversations/{id}/typing` — get typers
- `GET /messaging/users/search` — search users

**Files created/modified:**
```
src/api/endpoints/messaging.ts            — Add: sendHeartbeat, getPresence, sendTyping,
                                             getTyping, searchUsers
src/api/types.ts                          — Add: PresenceStatus { user_id, online, last_seen },
                                             TypingUser { user_id, started_at },
                                             UserSearchResult { user_id, display_name? }
src/hooks/usePresence.ts                  — NEW: Sends heartbeat every 30s while app is
                                             active. Exposes usePresenceStatus(userId) that
                                             polls every 15s and returns online/offline.
src/pages/messages/PresenceDot.tsx        — NEW: Small green/grey circle component.
                                             Props: userId. Uses usePresenceStatus hook.
src/pages/messages/TypingIndicator.tsx    — NEW: "User is typing..." with animated dots.
                                             Polls getTyping every 3s for active convo.
                                             Sends typing signal on textarea keypress
                                             (debounced 2s).
src/pages/messages/UserSearch.tsx         — NEW: Combobox with debounced search. Shows
                                             user results with avatar + name. Select →
                                             starts new conversation via existing startConversation.
src/pages/messages/MessagesPage.tsx       — Integrate PresenceDot on conversation list
                                             avatars and chat header. Add TypingIndicator
                                             below message list. Replace "New conversation"
                                             input with UserSearch combobox.
```

**UI details:**
- Presence dot: 8px circle positioned absolute on bottom-right of avatar.
  Green with subtle pulse for online, grey for offline.
- Typing indicator: Positioned below last message, above composer. Three bouncing
  dots with CSS animation. Shows "Alice is typing..." or "2 people typing...".
- User search: Opens in the existing new-conversation flow. Replaces plain text
  input with combobox that searches on keystroke.

---

## Step 5 — Messaging: Files, Forwarding & Group Management

**Goal:** Rich message types, forwarding, read receipts, group management panel.

**Backend endpoints wired:**
- `POST /messaging/messages/{id}/file` — send file message
- `POST /messaging/messages/{id}/forward` — forward message
- `POST /messaging/messages/{id}/view` — mark viewed
- `GET /messaging/messages/{id}/views` — get viewers
- `POST /messaging/conversations/{id}/participants` — add participant
- `POST /messaging/conversations/{id}/participants/{pid}/role` — change role

**Files created/modified:**
```
src/api/endpoints/messaging.ts            — Add: sendFileMessage, forwardMessage,
                                             markViewed, getViewers, addParticipants,
                                             updateParticipantRole
src/api/types.ts                          — Add: MessageViewer, ForwardMessageReq,
                                             AddParticipantsReq, UpdateRoleReq
src/pages/messages/FileMessageCard.tsx   — NEW: Renders file messages as card with icon
                                             (based on extension), filename, size, download
                                             button. Upload via drag-and-drop or paperclip
                                             button in composer.
src/pages/messages/ForwardDialog.tsx      — NEW: Dialog with conversation list picker.
                                             Search filter. Select conversation → confirm →
                                             forward with "[Forwarded from User]" prefix.
src/pages/messages/ReadReceipts.tsx       — NEW: Row of small avatars below last message
                                             each viewer has seen. Tooltip "Seen by Alice,
                                             Bob". Calls markViewed on message render via
                                             IntersectionObserver.
src/pages/messages/ParticipantsPanel.tsx  — NEW: Sheet/slide-out panel for group convos.
                                             Shows participant list with avatar, name, role
                                             badge. "Add participant" with UserSearch.
                                             Role dropdown (admin/member). Remove button.
src/pages/messages/MessagesPage.tsx       — Add paperclip attachment button in composer.
                                             Add "..." menu on messages (forward, delete).
                                             Add group info icon → opens ParticipantsPanel.
                                             Wire ReadReceipts component. Render
                                             FileMessageCard for file-kind messages.
```

**UI details:**
- File upload: Paperclip icon next to send button. Click opens file picker.
  Drag-and-drop onto message area highlights drop zone. Shows upload progress
  inline before sending.
- Forward: "..." menu on message → "Forward" → ForwardDialog. Shows forwarded
  message preview in the dialog.
- Read receipts: Tiny (20px) overlapping avatars. Max 5 shown, "+N" for overflow.
  Only shown on user's own sent messages.
- Group panel: Slides in from right on desktop, bottom sheet on mobile. "Manage
  Group" header. Participants sorted by role (admins first).

---

## Step 6 — Feed: Post & Comment Management

**Goal:** Edit, delete, and hide posts and comments. Actions menu on all content.

**Backend endpoints wired:**
- `GET /posts/{post_id}` — get single post
- `PATCH /posts/{post_id}` — edit post
- `DELETE /posts/{post_id}` — delete post
- `PATCH /posts/{post_id}/comments/{cid}` — edit comment
- `DELETE /posts/{post_id}/comments/{cid}` — delete comment
- `POST /hides` — hide post from feed

**Types to add in `src/api/types.ts`:**
```typescript
interface EditPostReq { body: string; }
interface EditCommentReq { body: string; }
interface HidePostReq { post_id: string; }
```

**Files created/modified:**
```
src/api/endpoints/newsfeed.ts             — Add: getPost, editPost, deletePost,
                                             editComment, deleteComment, hidePost
src/pages/feed/PostActions.tsx            — NEW: DropdownMenu component for post "..."
                                             button. Own posts: Edit, Delete. Others'
                                             posts: Hide, Report (placeholder/no-op).
src/pages/feed/EditPostDialog.tsx         — NEW: Dialog with pre-filled textarea.
                                             "Save" calls editPost, shows "(edited)"
                                             label on post. Cancel discards changes.
src/pages/feed/PostCard.tsx               — Add PostActions "..." menu in header.
                                             Show "(edited)" text if post has been edited.
                                             After hide, remove from local query cache.
src/pages/feed/CommentsThread.tsx         — Add "..." menu on own comments (Edit, Delete).
                                             Inline edit: replaces comment text with input.
                                             Delete: ConfirmDialog with destructive variant.
```

**UI details:**
- Actions menu: "..." button (MoreHorizontal icon) in top-right of PostCard header.
  Opens dropdown with contextual items based on ownership.
- Edit dialog: Pre-fills textarea with current body. Character count. "Save Changes"
  button disabled until content differs from original.
- Delete: ConfirmDialog "Delete this post? This cannot be undone." with red button.
  On success, removes post from feed query cache optimistically.
- Hide: Instant removal from local feed + API call. Toast "Post hidden" with
  "Undo" action button (re-fetches feed).
- Comments: Inline edit turns comment text into a small form. "Save" / "Cancel"
  buttons appear below.

---

## Step 7 — Feed: Image Upload & Tipping

**Goal:** Image posts via presigned upload, and monetary tipping for posts.

**Backend endpoints wired:**
- `POST /presign-upload` — get presigned S3 URL for image
- `POST /posts/{post_id}/tip` — send tip

**Types to add in `src/api/types.ts`:**
```typescript
interface PresignUploadReq { filename: string; content_type: string; }
interface PresignUploadResp { upload_url: string; public_url: string; }
interface TipReq { amount_cents: number; }
```

**Files created/modified:**
```
src/api/endpoints/newsfeed.ts             — Add: presignUpload (POST /presign-upload),
                                             fix tipPost to use correct path
src/pages/feed/CreatePost.tsx             — Add image attachment: camera icon button →
                                             file picker (accept image/*) → presign upload →
                                             preview thumbnail → includes image_url in
                                             createPost body. Progress indicator during
                                             upload.
src/pages/feed/TipDialog.tsx              — NEW: Dialog with dollar amount input (preset
                                             buttons: $1, $5, $10, custom). Calls tipPost.
                                             Success toast. Disabled while pending.
src/pages/feed/PostCard.tsx               — Add "Tip" button in action row (dollar sign
                                             icon). Opens TipDialog. Show tip total if
                                             available.
src/pages/feed/PostCard.tsx               — Improve image rendering: lightbox on click
                                             (full-screen overlay with close button).
```

**UI details:**
- Image upload: Camera/Image icon next to "Post" button. Preview shows as
  rounded thumbnail below textarea with "X" to remove. Upload to presigned URL
  with progress bar. On success, `image_url` added to post body.
- Tip dialog: Dollar sign icon in post action row. Dialog shows post preview
  snippet, preset amount buttons ($1, $5, $10) + custom input. "Send Tip" CTA.
  Success shows toast "Tip of $X sent!"
- Image lightbox: Clicking post image opens full-screen overlay with dark backdrop,
  image centered, close button and click-outside-to-dismiss.

---

## Step 8 — File Manager: Preview, Thumbnails & Shared With Me

**Goal:** In-browser file preview, image thumbnails, and shared-with-me view.

**Backend endpoints wired:**
- `GET /v1/fs/preview` — file preview URL
- `GET /v1/fs/thumbnail` — image thumbnail URL
- `GET /v1/fs/search-text` — full-text content search
- `GET /v1/fs/shared-with-me` — files shared with current user
- `GET /v1/fs/shared-list` — list shared folder contents
- `GET /v1/fs/shared-download` — download shared file

**Files created/modified:**
```
src/api/endpoints/files.ts                — Add: getPreviewUrl, getThumbnailUrl,
                                             searchText, getSharedWithMe,
                                             listSharedFolder, downloadSharedFile
src/pages/files/FilePreview.tsx           — NEW: Dialog/modal with preview content.
                                             Images: <img> tag. PDFs: <iframe>.
                                             Text: <pre> code block. Download button
                                             in header. Navigate prev/next with arrows.
src/pages/files/SharedWithMe.tsx          — NEW: Same DataTable layout as main files
                                             but different columns: name, shared by,
                                             permission (read/write badge), shared date.
                                             Click to preview/download.
src/pages/files/FilesPage.tsx             — Add tabs: "My Files" | "Shared With Me".
                                             Add search mode toggle: filename vs content.
                                             Click file row → opens FilePreview modal
                                             instead of navigating.
```

**UI details:**
- Preview modal: Full-width dialog. Header with filename, file type icon, size,
  "Download" button, close. Body: content-type-aware rendering. Keyboard: Esc
  to close, left/right arrows for prev/next file.
- Thumbnails: In table view, image files show 32x32 thumbnail instead of generic
  file icon. Lazy-loaded with Skeleton placeholder.
- Content search: Toggle pill "Name" / "Content" next to search bar. Content
  search results show matching text snippet with highlighted keywords.
- Shared With Me: Separate tab, separate API. Shows sharer's name, permission
  level, shared date. Actions: preview, download.

---

## Step 9 — File Manager: Bulk Actions & Advanced Uploads

**Goal:** Multi-select files, ZIP operations, presigned uploads, move files.

**Backend endpoints wired:**
- `POST /v1/fs/download-zip` — download multiple files as ZIP
- `POST /v1/fs/upload-zip` — upload and extract ZIP
- `POST /v1/fs/presign-upload` — presigned upload URL
- `POST /v1/fs/complete-upload` — complete presigned upload
- `POST /v1/fs/move` — move file to new path
- `POST /v1/fs/purge-deleted` — empty trash

**Files created/modified:**
```
src/api/endpoints/files.ts                — Add: downloadZip, uploadZip,
                                             presignUpload, completeUpload,
                                             moveFile (if not already), purgeDeleted
src/pages/files/BulkActions.tsx           — NEW: Toolbar that appears when files are
                                             selected. Buttons: "Download ZIP",
                                             "Delete Selected", "Move to...". File count
                                             badge. "Select All" checkbox in table header.
src/pages/files/MoveDialog.tsx            — NEW: Folder tree browser dialog. Select
                                             target folder → move selected files.
                                             Shows current location, prevents moving to
                                             same folder.
src/pages/files/FilesPage.tsx             — Add checkbox column to DataTable for
                                             multi-select. Show BulkActions toolbar when
                                             selection is non-empty. Upgrade upload to
                                             use presigned URL for files >5MB with progress
                                             toast. Add "Upload ZIP" option in upload
                                             dropdown.
```

**UI details:**
- Bulk selection: Checkbox column in table. Header checkbox toggles select-all.
  Selected count shown in toolbar: "3 items selected".
- Download ZIP: Calls downloadZip with selected paths. Returns download URL.
  Opens in new tab or triggers browser download.
- Move dialog: Tree view of folders (fetched from listFiles for each level).
  Expand/collapse. "Move here" button on each folder. Breadcrumb shows target path.
- Upload improvements: For large files, use presigned upload with progress bar
  in a toast. "Upload ZIP" option in upload dropdown → extracts to current folder.

---

## Step 10 — Calendar: Sharing & Conflict Detection

**Goal:** Share calendars with other users and show scheduling conflicts.

**Backend endpoints wired:**
- `POST /ui/calendars/{cid}/shares` — share calendar
- `GET /ui/calendars/{cid}/shares` — list shares
- `DELETE /ui/calendars/{cid}/shares/{uid}` — remove share
- `POST /ui/calendars/{cid}/events/conflicts` — preview conflicts
- `POST /ui/calendars/{cid}/events/suggestions` — suggest available slots
- `POST /ui/calendars/availability` — team availability

**Types to add in `src/api/types.ts`:**
```typescript
interface CalendarShare { user_sub: string; role: string; created_at: string; }
interface ShareCalendarReq { user_sub: string; role?: string; }
interface ConflictResult { conflicts: CalendarEvent[]; }
interface SlotSuggestion { start_utc: string; end_utc: string; score?: number; }
interface AvailabilityReq { calendar_ids: string[]; start_utc: string; end_utc: string; }
```

**Files created/modified:**
```
src/api/endpoints/calendar.ts             — Add: shareCalendar, getCalendarShares,
                                             removeCalendarShare, previewConflicts,
                                             suggestSlots, getTeamAvailability
src/pages/calendar/CalendarSharing.tsx    — NEW: Card with share list (user, role badge,
                                             remove button). "Add collaborator" input
                                             with user ID + role selector.
src/pages/calendar/ConflictBanner.tsx     — NEW: Yellow warning banner shown in
                                             EventDialog when conflicts detected.
                                             "N conflicts found" with expandable list
                                             showing conflicting event names and times.
src/pages/calendar/SlotSuggestions.tsx    — NEW: "Find a time" button → fetches suggestions
                                             → shows list of available slots with
                                             "Select" button that auto-fills event times.
src/pages/calendar/EventDialog.tsx        — Integrate ConflictBanner (check on date change).
                                             Add SlotSuggestions button.
src/pages/calendar/CalendarPage.tsx       — Add "Sharing" tab with CalendarSharing.
```

**UI details:**
- Sharing panel: Simple card. "Share with" input + "Add" button. List of shares
  with avatar, user ID, role dropdown, remove (trash icon with ConfirmDialog).
- Conflict banner: Appears dynamically in EventDialog when user picks a time.
  Debounced 500ms check on start/end change. Yellow bg, warning icon, expandable
  conflict list.
- Slot suggestions: Modal or inline panel. Shows 5-10 suggested time slots.
  Each slot: formatted date/time range + "Use this slot" button. Clicking fills
  EventDialog start/end fields.

---

## Step 11 — Calendar: Settings, Working Hours & Booking Links

**Goal:** Calendar CRUD, working hours editor, recurrence overrides, server-side booking links.

**Backend endpoints wired:**
- `PATCH /ui/calendars/{cid}` — update calendar settings
- `DELETE /ui/calendars/{cid}` — delete calendar
- `GET /ui/calendars/{cid}/openings` — available openings
- `GET /ui/calendars/{cid}/booking_links` — list booking links (server)
- `POST /ui/calendars/{cid}/events/{eid}/occurrences/{os}/exclude` — exclude occurrence
- `POST /ui/calendars/{cid}/events/{eid}/occurrences/{os}/override` — override occurrence
- `DELETE /ui/calendars/{cid}/events/{eid}/occurrences/{os}` — clear override
- `GET /booking/{link_id}` — public booking page
- `GET /booking/{link_id}/openings` — public openings
- `POST /booking/{link_id}/reserve` — reserve slot

**Files created/modified:**
```
src/api/endpoints/calendar.ts             — Add: updateCalendar, deleteCalendar,
                                             getOpenings, listBookingLinks (list endpoint),
                                             excludeOccurrence, overrideOccurrence,
                                             clearOccurrenceOverride, getPublicBookingLink,
                                             getPublicOpenings, reserveBookingSlot
src/pages/calendar/CalendarSettings.tsx   — NEW: Calendar name/timezone edit form.
                                             Working hours editor: 7-row grid (Mon-Sun),
                                             each row: toggle enabled + start/end time
                                             inputs. Buffer minutes before/after inputs.
                                             Delete calendar with ConfirmDialog.
src/pages/calendar/CalendarView.tsx       — Add recurrence context menu on recurring
                                             events: "Edit this occurrence" (override),
                                             "Skip this occurrence" (exclude), "Edit all".
                                             Visual indicator for overridden/excluded
                                             occurrences (strikethrough or different color).
src/pages/calendar/BookingLinks.tsx       — Replace local state with useQuery fetching
                                             from listBookingLinks endpoint. Add "View
                                             openings" button that shows available slots.
src/pages/calendar/CalendarPage.tsx       — Add "Settings" tab with CalendarSettings.
```

**UI details:**
- Working hours editor: Compact 7-row grid. Each row: day name, enabled switch,
  start time input, "to" label, end time input. Disabled rows greyed out.
  "Save" button at bottom.
- Recurrence override: Right-click or "..." on a recurring event occurrence →
  context menu with "Edit this one", "Skip this one", "Edit all future".
  Excluded occurrences shown with dashed border and strikethrough.
- Booking links: Fetched from server. Card list with link name, duration, calendar,
  public URL with copy button. "View openings" expands to show available slots.

---

## Step 12 — WebAuthn Security Keys & Passwordless Login

**Goal:** FIDO2 security key management and magic link passwordless login.

**Backend endpoints wired:**
- `POST /ui/webauthn/register/begin` — start registration
- `POST /ui/webauthn/register/finish` — complete registration
- `POST /ui/webauthn/authenticate/begin` — start authentication
- `POST /ui/webauthn/authenticate/finish` — complete authentication
- `POST /ui/passwordless/start` — send magic link
- `POST /ui/passwordless/verify` — verify magic link token

**Types to add in `src/api/types.ts`:**
```typescript
interface WebAuthnRegisterBeginReq { label?: string; }
interface WebAuthnRegisterBeginResp { options: Record<string, unknown>; }
interface WebAuthnRegisterFinishReq { credential: Record<string, unknown>; label?: string; }
interface WebAuthnRegisterFinishResp { ok: boolean; credential_id: string; }
interface WebAuthnAuthBeginReq { challenge_id?: string; }
interface WebAuthnAuthBeginResp { options: Record<string, unknown>; }
interface WebAuthnAuthFinishReq { credential: Record<string, unknown>; challenge_id?: string; }
interface WebAuthnAuthFinishResp { status: string; session_id?: string; }
interface PasswordlessStartReq { email: string; }
interface PasswordlessStartResp { status: string; }
interface PasswordlessVerifyReq { token: string; }
interface PasswordlessVerifyResp { status: string; session_id?: string; }
```

**Files created/modified:**
```
src/api/endpoints/webauthn.ts             — NEW: registerBegin, registerFinish,
                                             authenticateBegin, authenticateFinish
src/api/endpoints/auth.ts                 — Add: passwordlessStart, passwordlessVerify
src/pages/security/WebAuthnDevices.tsx    — NEW: Card with "Security Keys" section.
                                             Device list (label, registered date).
                                             "Add Security Key" → triggers navigator.
                                             credentials.create() → finish → success.
                                             Remove button per key.
src/pages/security/SecurityPage.tsx       — Add "Security Keys" tab
src/pages/Login.tsx                       — Add "Sign in with email link" toggle/tab.
                                             Email input → "Send magic link" → success
                                             message. Add "Use security key" button in
                                             MFA challenge screen.
src/pages/MagicLinkVerify.tsx             — NEW: Landing page for /magic-link-verify.
                                             Reads token from URL params → auto-calls
                                             verify → redirects to dashboard on success,
                                             shows error on failure.
src/App.tsx                               — Add `/magic-link-verify` route (lazy)
```

**UI details:**
- WebAuthn registration: "Add Security Key" button → calls registerBegin →
  passes options to `navigator.credentials.create()` → sends response to
  registerFinish → label input → success toast.
- WebAuthn login: "Use security key" button during MFA → calls authenticateBegin →
  `navigator.credentials.get()` → authenticateFinish → session established.
- Magic link: Clean email input with "Send link" button. Success state: envelope
  icon with "Check your email" message. Verify page: full-screen loading spinner
  → auto-redirect or error message.

---

## Step 13 — Push Notifications & Catalog Admin

**Goal:** Push device management and catalog item/category CRUD for admin users.

**Backend endpoints wired (Push):**
- `GET /ui/push/devices` — list devices
- `POST /ui/push/register` — register device
- `POST /ui/push/revoke` — unregister device
- `POST /ui/push/test` — test notification

**Backend endpoints wired (Catalog Admin):**
- `POST /ui/catalog/categories` — create category
- `DELETE /ui/catalog/categories/{cid}` — delete category
- `POST /ui/catalog/categories/{cid}/items` — create item
- `PATCH /ui/catalog/categories/{cid}/items/{iid}` — update item
- `DELETE /ui/catalog/categories/{cid}/items/{iid}` — delete item
- `POST /ui/catalog/categories/{cid}/items/{iid}/images/upload` — upload image

**Backend endpoint wired (Profile Audit):**
- `GET /ui/profile/audit` — profile change history

**Files created/modified:**
```
src/api/endpoints/push.ts                 — NEW: listPushDevices, registerPush,
                                             revokePush, testPush
src/pages/alerts/PushDevices.tsx          — NEW: Card with push device list (type, date,
                                             test/remove buttons). "Enable Notifications"
                                             button triggers browser permission + register.
src/pages/alerts/AlertsPage.tsx           — Add "Push Devices" tab
src/pages/shop/ItemEditor.tsx             — NEW: Form with name, description, price,
                                             currency, attributes (dynamic key-value),
                                             image upload with preview. Create/edit mode.
src/pages/shop/AdminCatalog.tsx           — NEW: Category list with "Add Category" button.
                                             Item grid per category with edit/delete buttons.
                                             Delete category/item with ConfirmDialog.
src/pages/shop/CatalogPage.tsx            — Add "Manage" tab (only shown in admin context)
                                             with AdminCatalog.
src/pages/settings/ProfileAudit.tsx       — NEW: Vertical timeline of profile changes.
                                             Each entry: timestamp, field name, old → new
                                             value. Filterable by field dropdown.
src/pages/settings/ProfilePage.tsx        — Add "Activity" tab with ProfileAudit.
```

**UI details:**
- Push: "Enable Push Notifications" → checks `Notification.permission` → if
  "default", calls `Notification.requestPermission()` → on grant, registers
  with backend. "Test" button sends test push. Device list shows type + date.
- Catalog admin: Toggle via "Manage Catalog" button in CatalogPage header.
  Category CRUD: create dialog, delete confirmation. Item CRUD: full form in
  dialog with image upload. Edit clicks pre-fill the form.
- Profile audit: Timeline component with circle connectors. Each event: badge
  with field name, timestamp, "Changed from X to Y" description.

---

## Step 14 — Design System: Animations, Skeletons & Polish

**Goal:** Page transitions, standardized skeleton loading, micro-interactions, color/type audit.

**Dependencies:** Install `framer-motion` for page animations.

**Files created/modified:**
```
package.json                              — Add framer-motion dependency
src/components/shared/PageTransition.tsx  — NEW: Wrapper component using framer-motion
                                             AnimatePresence + motion.div with fade +
                                             subtle slide-up (y: 8px → 0, opacity: 0 → 1).
                                             Applied in AppShell around <Outlet />.
src/components/shared/ContentSkeleton.tsx — NEW: Reusable skeleton patterns: CardSkeleton,
                                             ListSkeleton, TableSkeleton, FormSkeleton.
                                             Used across all pages for consistent loading.
src/index.css                             — Refine custom CSS: add animation keyframes
                                             for micro-interactions (card-hover-lift,
                                             button-press, bell-shake). Audit color variables
                                             for WCAG AA contrast. Add semantic color
                                             utilities: text-success, text-warning, bg-info.
src/components/layout/AppShell.tsx        — Wrap Outlet in PageTransition.
src/components/layout/Header.tsx          — Add bell-shake animation on new alert.
                                             Ensure all icon buttons have focus-visible ring.
src/components/ui/button.tsx              — Add subtle scale transform on active press
                                             (active:scale-[0.98]) to all variants.
src/components/ui/card.tsx                — Add hover:shadow-md transition for interactive
                                             cards (opt-in via className).
```

**UI details:**
- Page transitions: 150ms fade + 8px slide-up on route change. Exit: fade out.
  Uses AnimatePresence with `mode="wait"`.
- Skeleton patterns: CardSkeleton (rounded rect with header + body bars),
  ListSkeleton (N rows of avatar + text bars), TableSkeleton (header + rows).
  Pulse animation. Replace all `<Loader2>` spinners with content-shaped skeletons.
- Micro-interactions: Cards lift slightly on hover (shadow-md). Buttons scale
  down 2% on press. Toggle switches spring animate. Alert bell shakes briefly
  when unread count increments.
- Color audit: Ensure all text/background combinations meet WCAG AA (4.5:1 for
  normal text, 3:1 for large text) in both light and dark themes.

---

## Step 15 — Responsive Polish, Error Handling & Onboarding

**Goal:** Mobile-optimised layouts, offline detection, error pages, and new-user onboarding.

**Files created/modified:**
```
src/pages/messages/MessagesPage.tsx       — Mobile layout: show conversation list OR chat
                                             (not both). Tap conversation → full-screen chat.
                                             Back arrow returns to list. Use CSS/state toggle
                                             at md breakpoint.
src/pages/files/FilesPage.tsx             — Mobile: stack toolbar buttons vertically.
                                             Hide size/date columns on small screens
                                             (hidden md:table-cell).
src/pages/calendar/CalendarView.tsx       — Mobile: default to day view. Detect screen
                                             width and auto-select. Swipe-friendly layout.
src/components/shared/DataTable.tsx       — Wrap table in overflow-x-auto container.
                                             Add responsive column hiding support.
src/components/shared/OfflineBanner.tsx   — NEW: Sticky banner at top of viewport.
                                             "You're offline" with yellow bg. Auto-detects
                                             via navigator.onLine + online/offline events.
                                             Auto-dismisses when connectivity returns.
src/components/shared/ErrorPage.tsx       — NEW: Full-page error states: 403 (lock icon +
                                             "Permission Denied"), 404 (compass icon +
                                             "Page Not Found"), generic error. "Go Home"
                                             button.
src/api/client.ts                         — Enhanced error interceptor: on 401, attempt
                                             silent refresh. If refresh fails, redirect to
                                             /login?redirect=<current_path>. On 403, show
                                             permission denied state. On network error,
                                             show toast with "Retry" button.
src/components/shared/OnboardingChecklist.tsx — NEW: Dashboard widget for new users.
                                                Checklist: "Complete your profile",
                                                "Add a payment method", "Set up MFA",
                                                "Send your first message". Progress bar.
                                                Tracks via localStorage. Dismissable with
                                                "X" button that persists dismissal.
src/pages/Dashboard.tsx                   — Add OnboardingChecklist at top (conditionally
                                             shown for new users). Responsive card grid:
                                             1 col mobile, 2 col tablet, 3 col desktop.
src/components/layout/AppShell.tsx        — Add OfflineBanner above Header. Ensure all
                                             dialogs render as bottom sheets on mobile
                                             (document this pattern for future use).
src/App.tsx                               — Add catch-all route for 404 ErrorPage.
```

**UI details:**
- Mobile messages: State variable `activeConversation`. On mobile (`< md`):
  if null, show conversation list full-width. If set, show chat full-width with
  back arrow. On desktop: side-by-side as current.
- Offline banner: Full-width, fixed top, z-50. Yellow background with wifi-off
  icon. Slides down with animation.
- Onboarding checklist: Card with progress bar (N/4 complete). Each item: checkbox,
  label, "Go" link to relevant page. When all done, card shows "All set!" and
  auto-dismisses.
- 404 page: Compass icon, "Page not found", description, "Back to Dashboard" button.
- Error client: Intercept fetch errors. 401 → try refresh → if fails, redirect.
  403 → toast "Permission denied". Network error → toast with retry callback.

---

## Summary Table

| Step | Theme | New Files | Modified Files | Key Deliverables |
|------|-------|-----------|---------------|------------------|
| 1 | Purchase History: List | 3 | 4 | API client, transaction list with search, nav |
| 2 | Purchase History: Detail | 3 | 2 | Detail view, shipping timeline, receipt, cancel |
| 3 | Subscriptions | 4 | 4 | Plan browser, my subs, cancel/pause/resume |
| 4 | Messaging: Presence | 4 | 2 | Presence dots, typing indicator, user search |
| 5 | Messaging: Rich Features | 4 | 2 | File messages, forwarding, read receipts, groups |
| 6 | Feed: Content Management | 2 | 3 | Edit/delete posts+comments, hide, actions menu |
| 7 | Feed: Media & Tipping | 2 | 2 | Image upload, tipping dialog, lightbox |
| 8 | Files: Preview & Shared | 3 | 2 | Preview modal, thumbnails, shared-with-me |
| 9 | Files: Bulk & Upload | 3 | 2 | Multi-select, ZIP ops, presigned upload, move |
| 10 | Calendar: Collaboration | 4 | 2 | Sharing, conflicts, slot suggestions |
| 11 | Calendar: Advanced | 1 | 4 | Settings, working hours, recurrence, booking |
| 12 | Auth: WebAuthn & Magic Link | 3 | 3 | Security keys, passwordless login, verify page |
| 13 | Push, Admin & Audit | 5 | 3 | Push devices, catalog CRUD, profile audit |
| 14 | Design Polish | 3 | 5 | Page transitions, skeletons, micro-interactions |
| 15 | Responsive & Error Handling | 4 | 6 | Mobile layouts, offline banner, onboarding |
