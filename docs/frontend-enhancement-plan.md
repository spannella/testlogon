# Frontend Enhancement Plan — Full Backend Coverage & Beautiful UI

> Generated from a comprehensive audit of all 300+ backend API endpoints across 27 routers
> and the current 15-step frontend implementation.

---

## Executive Summary

The current frontend covers the **core CRUD** for most feature areas but leaves significant
backend capabilities unexposed. This plan adds the missing feature coverage, introduces
visual polish, and delivers a production-grade experience. Organised into themed phases
so each phase produces a shippable increment.

---

## Phase 1 — Purchase History & Subscription Management

**Why first:** Commerce features directly impact revenue. The backend has a full purchase
history system and subscription server that the frontend never exposes.

### 1A. Purchase History Page (`src/pages/purchases/`)

**Backend endpoints used:**
| Method | Path | Notes |
|--------|------|-------|
| GET | `/ui/purchase-history/transactions` | List with pagination |
| GET | `/ui/purchase-history/transactions/search` | Search by keyword/date |
| GET | `/ui/purchase-history/transactions/{txn_id}` | Full detail |
| PUT | `/ui/purchase-history/transactions/{txn_id}/shipping` | Update shipping info |
| POST | `/ui/purchase-history/transactions/{txn_id}/complete` | Mark complete |
| POST | `/ui/purchase-history/transactions/{txn_id}/revert` | Revert transaction |
| POST | `/ui/purchase-history/transactions/{txn_id}/cancel/request` | Request cancellation |
| POST | `/ui/purchase-history/transactions/{txn_id}/cancel/respond` | Respond to cancel |
| GET | `/ui/purchase-history/transactions/{txn_id}/events` | Audit trail |
| GET | `/ui/purchase-history/transactions/{txn_id}/receipt` | Download receipt |

**New files:**
```
src/api/endpoints/purchases.ts          — API client functions
src/pages/purchases/PurchaseHistory.tsx  — Transaction list with search & filters
src/pages/purchases/TransactionDetail.tsx — Detail view with shipping, events, receipt
src/pages/purchases/PurchasesPage.tsx    — Page shell with tabs (Orders | Receipts)
```

**UI spec:**
- **Order list** — DataTable with columns: date, description, amount, status badge,
  actions dropdown (view, cancel, receipt). Infinite scroll or load-more.
- **Search bar** — debounced keyword search + date range picker + status filter chips
  (pending, completed, cancelled, reverted).
- **Detail drawer/page** — Order summary card, shipping timeline (carrier, tracking
  number, shipped/delivered dates), events audit trail as vertical timeline, receipt
  download button, cancellation request dialog with reason input.
- **Status flow** — Visual status stepper: Pending → Shipped → Delivered → Completed,
  with branching for cancelled/reverted states.

### 1B. Subscription Management (`src/pages/subscriptions/`)

**Backend endpoints used:**
| Method | Path | Notes |
|--------|------|-------|
| GET | `/subscriptions/plans` | Browse available plans |
| GET | `/subscriptions/plans/{plan_id}` | Plan details |
| POST | `/subscriptions/subscribe` | Subscribe |
| GET | `/subscriptions/subscriptions` | My subscriptions |
| GET | `/subscriptions/subscriptions/{sub_id}` | Sub details |
| POST | `/subscriptions/subscriptions/{sub_id}/cancel` | Cancel sub |
| POST | `/subscriptions/subscriptions/{sub_id}/pause` | Pause sub |
| POST | `/subscriptions/subscriptions/{sub_id}/resume` | Resume sub |
| POST | `/subscriptions/discounts` | Create discount code (admin) |
| GET | `/subscriptions/discounts/{code}` | Validate discount |

**New files:**
```
src/api/endpoints/subscriptions.ts       — API client
src/api/types.ts                         — Add SubscriptionPlan, SubscriptionDetail, Discount types
src/pages/subscriptions/PlanBrowser.tsx   — Plan cards grid with pricing
src/pages/subscriptions/MySubscriptions.tsx — Active subs list with actions
src/pages/subscriptions/SubscriptionsPage.tsx — Tabs: Browse Plans | My Subscriptions
```

**UI spec:**
- **Plan browser** — Grid of pricing cards with plan name, price/cycle, feature bullet
  list, "Subscribe" CTA. Discount code input that validates and shows adjusted price.
- **My subscriptions** — Cards showing plan name, status badge, next billing date,
  price. Action buttons: Pause (yellow), Resume (green), Cancel (red with ConfirmDialog).
  Subscription detail panel with billing history link.
- **Plan comparison** — Optional toggle to table view comparing plan features side-by-side.

### 1C. Route & Nav Updates

- Add `/purchases` and `/subscriptions` routes in App.tsx (lazy-loaded).
- Add "Orders" and "Subscriptions" to Sidebar under new "Commerce" group (alongside
  Shop, Cart, Billing).
- Add to mobile nav and search command palette.

---

## Phase 2 — Messaging & Feed Enhancements

**Why second:** These are high-engagement features. The backend supports rich messaging
(typing indicators, presence, forwarding, file/image messages, reactions) and social
features (tipping, hiding, editing, deleting, notifications) that the UI doesn't expose.

### 2A. Messaging Enhancements

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| POST | `/messaging/messages/{id}/forward` | Forward to another conversation |
| POST | `/messaging/messages/{id}/file` | Send file message |
| POST | `/messaging/messages/{id}/view` | Mark as viewed (read receipts) |
| GET | `/messaging/messages/{id}/views` | Get viewers list |
| POST | `/messaging/presence/heartbeat` | Online presence |
| GET | `/messaging/users/{id}/presence` | Get user online status |
| POST | `/messaging/conversations/{id}/typing` | Typing indicator |
| GET | `/messaging/conversations/{id}/typing` | Get who's typing |
| POST | `/messaging/conversations/{id}/participants` | Add participants |
| POST | `/messaging/conversations/{id}/participants/{pid}/role` | Change role |
| GET | `/messaging/users/search` | Search for users |

**Files to modify/create:**
```
src/api/endpoints/messaging.ts           — Add missing endpoint functions
src/api/types.ts                         — Add PresenceStatus, TypingIndicator types
src/pages/messages/TypingIndicator.tsx   — "User is typing..." animation
src/pages/messages/PresenceDot.tsx       — Green/grey online indicator
src/pages/messages/ForwardDialog.tsx     — Forward message to conversation picker
src/pages/messages/ParticipantsPanel.tsx — Group member list with role management
src/pages/messages/UserSearch.tsx        — Search and start conversations
src/pages/messages/MessagesPage.tsx      — Integrate new sub-components
src/hooks/usePresence.ts                 — Heartbeat interval + presence polling
```

**UI spec:**
- **Typing indicator** — Animated "..." dots below message list when someone is typing.
  Poll typing endpoint every 3s while conversation is active.
- **Presence dots** — Green (online), grey (offline) dot on avatar in conversation
  list and chat header. Send heartbeat every 30s.
- **Forward message** — Right-click or "..." menu on message → "Forward" → conversation
  picker dialog → sends forwarded message with attribution.
- **Read receipts** — Small avatars beneath last-read message showing who's seen it.
  "Seen by N" tooltip.
- **File messages** — Drag-and-drop or attachment button → file upload → renders as
  file card with name, size, download link.
- **Group management panel** — Slide-out panel showing participants, their roles,
  "Add participant" search input, role dropdown (admin/member), remove button.
- **User search** — Combobox search to find users and start new conversations.

### 2B. Feed Enhancements

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| GET | `/posts/{post_id}` | Get single post |
| PATCH | `/posts/{post_id}` | Edit post |
| DELETE | `/posts/{post_id}` | Delete post |
| PATCH | `/posts/{post_id}/comments/{cid}` | Edit comment |
| DELETE | `/posts/{post_id}/comments/{cid}` | Delete comment |
| POST | `/posts/{post_id}/tip` | Send tip to post |
| POST | `/hides` | Hide a post |
| POST | `/presign-upload` | Upload images for posts |
| GET | `/notifications` | Feed notification SSE |

**Files to modify/create:**
```
src/api/endpoints/newsfeed.ts            — Add missing functions (editPost, deletePost,
                                            editComment, deleteComment, hidePost,
                                            presignUpload, tipPost fix)
src/api/types.ts                         — Add EditPostReq, TipReq types
src/pages/feed/PostCard.tsx              — Add "..." menu (edit/delete/hide/tip)
src/pages/feed/CreatePost.tsx            — Add image upload via presigned URL
src/pages/feed/TipDialog.tsx             — Tip amount input dialog
src/pages/feed/EditPostDialog.tsx        — Edit post body dialog
src/pages/feed/CommentsThread.tsx        — Add edit/delete on own comments
```

**UI spec:**
- **Post actions menu** — "..." dropdown on own posts: Edit, Delete. On others' posts:
  Hide, Report (placeholder). Tip button with amount input dialog.
- **Image posts** — Camera icon in CreatePost → presign upload → attach image URL to
  post. Image preview before posting.
- **Edit post** — Opens dialog with pre-filled textarea. "Save" replaces body, shows
  "(edited)" label.
- **Delete post/comment** — ConfirmDialog with destructive variant.
- **Tip dialog** — Dollar amount input → calls tip endpoint → success toast with
  confetti animation.
- **Hide post** — Removes post from local feed view + calls hide endpoint.

---

## Phase 3 — File Manager & Calendar Enhancements

### 3A. File Manager Enhancements

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| GET | `/v1/fs/search-text` | Full-text content search |
| GET | `/v1/fs/preview` | In-browser file preview |
| GET | `/v1/fs/thumbnail` | Image thumbnails |
| POST | `/v1/fs/download-zip` | Download multiple as ZIP |
| POST | `/v1/fs/upload-zip` | Upload and extract ZIP |
| GET | `/v1/fs/shared-with-me` | Files others shared with me |
| POST | `/v1/fs/move` | Move files between folders |
| POST | `/v1/fs/presign-upload` | Large file presigned upload |
| POST | `/v1/fs/complete-upload` | Complete presigned upload |
| GET | `/v1/fs/shared-list` | Browse shared folders |
| GET | `/v1/fs/shared-download` | Download shared file |
| POST | `/v1/fs/purge-deleted` | Empty trash |

**Files to modify/create:**
```
src/api/endpoints/files.ts               — Add missing functions
src/pages/files/FilePreview.tsx          — Modal with preview iframe/image
src/pages/files/SharedWithMe.tsx         — Grid/list of files shared by others
src/pages/files/FilesPage.tsx            — Add tabs: My Files | Shared With Me
                                           Add toolbar: ZIP download, text search
```

**UI spec:**
- **File preview modal** — Click file → modal with preview (images rendered inline,
  PDFs in iframe, text files in code block). Download button in header.
- **Image thumbnails** — Grid view option showing thumbnails instead of file table rows.
  Lazy-loaded via `/v1/fs/thumbnail`.
- **Shared With Me tab** — Second tab showing files others have shared. Same table
  layout but with "Shared by" column instead of "Owner".
- **Bulk actions** — Checkbox selection → toolbar with "Download ZIP", "Delete",
  "Move to" actions.
- **Content search** — Toggle from filename search to full-text content search.
  Results show matching snippet with keyword highlighting.
- **Drag-and-drop move** — Drag files onto folder entries in the table to move them.
- **Large file upload** — For files >5MB, use presigned upload with progress bar in
  a toast notification.

### 3B. Calendar Enhancements

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| POST | `/ui/calendars/{cid}/shares` | Share calendar |
| GET | `/ui/calendars/{cid}/shares` | List shares |
| DELETE | `/ui/calendars/{cid}/shares/{uid}` | Remove share |
| POST | `/ui/calendars/{cid}/events/conflicts` | Conflict detection |
| POST | `/ui/calendars/{cid}/events/suggestions` | Slot suggestions |
| POST | `/ui/calendars/{cid}/events/{eid}/occurrences/{os}/exclude` | Exclude recurrence |
| POST | `/ui/calendars/{cid}/events/{eid}/occurrences/{os}/override` | Override occurrence |
| GET | `/ui/calendars/{cid}/openings` | Available openings |
| GET | `/ui/calendars/{cid}/booking_links` | List booking links (vs current local state) |
| PATCH | `/ui/calendars/{cid}` | Update calendar settings |
| DELETE | `/ui/calendars/{cid}` | Delete calendar |
| GET | `/booking/{link_id}` | Public booking page |
| GET | `/booking/{link_id}/openings` | Public openings |
| POST | `/booking/{link_id}/reserve` | Public reservation |
| POST | `/ui/calendars/availability` | Team availability |

**Files to modify/create:**
```
src/api/endpoints/calendar.ts            — Add missing functions
src/api/types.ts                         — Add CalendarShare, ConflictResult, Suggestion types
src/pages/calendar/CalendarSharing.tsx   — Share management panel
src/pages/calendar/ConflictChecker.tsx   — Visual conflict indicator
src/pages/calendar/SlotSuggestions.tsx   — AI-suggested meeting times
src/pages/calendar/CalendarSettings.tsx  — Calendar CRUD + working hours editor
src/pages/calendar/CalendarView.tsx      — Integrate conflict warnings, recurrence overrides
src/pages/calendar/BookingLinks.tsx      — Replace local state with server-fetched list
src/pages/calendar/CalendarPage.tsx      — Add Settings + Sharing tabs
```

**UI spec:**
- **Calendar sharing panel** — User search → add collaborator with role → list current
  shares with remove button.
- **Conflict detection** — When creating/editing an event, show yellow warning banner
  if conflicts detected. "Show conflicts" link opens detail.
- **Slot suggestions** — "Find a time" button → shows list of suggested available slots.
  Click to auto-fill event start/end.
- **Working hours editor** — Per-day toggles with start/end time pickers. Compact
  week grid layout.
- **Recurrence overrides** — Click individual occurrence → options: "Edit this
  occurrence", "Delete this occurrence", "Edit all future".
- **Booking links** — Fetch from server instead of local state. Copy public URL.
  Optional: preview booking page inline.

---

## Phase 4 — Authentication & Security Enhancements

### 4A. WebAuthn / Security Keys

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| POST | `/ui/webauthn/register/begin` | Start security key registration |
| POST | `/ui/webauthn/register/finish` | Complete registration |
| POST | `/ui/webauthn/authenticate/begin` | Start authentication |
| POST | `/ui/webauthn/authenticate/finish` | Complete authentication |

**New files:**
```
src/api/endpoints/webauthn.ts            — API client
src/api/types.ts                         — WebAuthnRegistrationOptions, etc.
src/pages/security/WebAuthnDevices.tsx   — Security key management
src/pages/security/SecurityPage.tsx      — Add WebAuthn tab
src/pages/Login.tsx                      — Add "Use security key" option
```

**UI spec:**
- **Registration flow** — "Add Security Key" button → browser WebAuthn prompt →
  success with device label input → shows in device list.
- **Device list** — Shows registered security keys with label, registration date,
  last used. Remove button with ConfirmDialog.
- **Login integration** — "Use security key" button on login page → triggers
  WebAuthn authentication flow as MFA factor.

### 4B. Passwordless / Magic Link Login

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| POST | `/ui/passwordless/start` | Send magic link |
| POST | `/ui/passwordless/verify` | Verify token from link |

**Files to modify/create:**
```
src/api/endpoints/auth.ts                — Add passwordless functions
src/pages/Login.tsx                      — Add "Sign in with email" tab/toggle
src/pages/MagicLinkVerify.tsx            — Landing page for magic link clicks
src/App.tsx                              — Add /magic-link-verify route
```

**UI spec:**
- **Login page** — Tab or link: "Sign in with email link" → email input → "Send link"
  → success message "Check your inbox".
- **Verify page** — `/magic-link-verify?token=...` → auto-verifies → redirects to
  dashboard on success, error message on failure.

### 4C. Push Notification Management

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| GET | `/ui/push/devices` | List registered push devices |
| POST | `/ui/push/register` | Register device for push |
| POST | `/ui/push/revoke` | Unregister device |
| POST | `/ui/push/test` | Send test notification |

**New files:**
```
src/api/endpoints/push.ts               — API client
src/pages/alerts/PushDevices.tsx         — Push device management
src/pages/alerts/AlertsPage.tsx          — Add Push Devices tab
```

**UI spec:**
- **Push device list** — Cards showing device type, registration date, last push.
  "Test" button sends test notification. "Remove" button with confirmation.
- **Enable push** — "Enable Push Notifications" button → triggers browser permission
  request → registers service worker → registers device with backend.

---

## Phase 5 — Visual Polish & UX Refinements

### 5A. Design System Refinements

**Files to modify:**
```
src/index.css                            — Refined color palette, spacing, animations
src/components/ui/*.tsx                  — Custom variants for visual consistency
```

**Spec:**
- **Page transitions** — Fade + slide-up animation on route changes using
  `framer-motion` `AnimatePresence`.
- **Skeleton loading** — Replace all `isLoading` spinners with content-shaped skeleton
  screens (already done in some pages, standardize everywhere).
- **Micro-interactions** — Button press scale, card hover lift shadow, toggle switch
  spring animation, notification bell shake on new alert.
- **Toast refinements** — Consistent position (bottom-right), action buttons in
  toasts (e.g., "Undo" on delete), progress bar for uploads.
- **Color palette refinement** — Ensure WCAG AA contrast in both themes. Consistent
  use of semantic colors: success (green), warning (amber), error (red), info (blue).
- **Typography scale** — Audit all text sizes for hierarchy consistency. Ensure headings,
  body, captions, and labels follow a clear scale.

### 5B. Responsive Polish

**Files to modify:**
```
src/pages/messages/MessagesPage.tsx      — Mobile: conversation list ↔ chat toggle
src/pages/files/FilesPage.tsx            — Mobile: stacked toolbar, fewer table columns
src/pages/calendar/CalendarView.tsx      — Mobile: default to day view
src/components/layout/AppShell.tsx       — Refine mobile sheet transitions
src/components/shared/DataTable.tsx      — Horizontal scroll wrapper on narrow screens
```

**Breakpoint targets:**
- **Mobile (375px):** Single-column layouts, bottom sheets instead of dialogs,
  hamburger menu, bottom navigation bar.
- **Tablet (768px):** Two-column where beneficial (messages), compact sidebar,
  reduced card grids.
- **Desktop (1280px+):** Full three-pane layouts, expanded sidebar, hover tooltips.

**Specific fixes:**
- Messages: On mobile, show only conversation list. Tapping opens full-screen chat.
  Back button returns to list.
- Calendar: Auto-switch to day view on mobile. Swipe gestures for day navigation.
- DataTable: Wrap in `overflow-x-auto` container. Priority columns stay, others
  hidden on mobile with `hidden md:table-cell`.
- Dialogs: Use `Sheet` with `side="bottom"` on mobile for all modal interactions.

### 5C. Empty States & Onboarding

**New files:**
```
src/components/shared/OnboardingChecklist.tsx — First-time user checklist
```

**Spec:**
- **Illustrated empty states** — Replace text-only empty states with SVG illustrations
  or larger icons with subtle gradient backgrounds.
- **Onboarding checklist** — Dashboard widget for new users: "Complete your profile",
  "Add a payment method", "Set up MFA", "Send your first message". Dismissable,
  tracks completion via local storage.
- **Contextual tips** — Tooltip-based hints on first use of complex features (calendar
  views, file sharing, booking links).

### 5D. Error Handling & Offline Support

**Files to modify:**
```
src/api/client.ts                        — Enhanced error interceptor
src/components/shared/ErrorBoundary.tsx  — Refined error UI
src/components/shared/OfflineBanner.tsx  — NEW: offline detection banner
```

**Spec:**
- **Network error toast** — On fetch failure, show toast with "Retry" button.
  Auto-retry once after 3s for GET requests.
- **401 handling** — On 401, attempt silent refresh. If refresh fails, redirect
  to login with `?redirect=` param to return after login.
- **403 page** — "Permission Denied" page with illustration and "Go Home" button.
- **Offline banner** — Sticky banner at top: "You're offline. Some features may be
  unavailable." Auto-dismisses when back online.

---

## Phase 6 — Admin & Advanced Features

### 6A. Catalog Administration

**Backend endpoints currently UNUSED by frontend (admin actions):**
| Method | Path | Notes |
|--------|------|-------|
| POST | `/ui/catalog/categories` | Create category |
| DELETE | `/ui/catalog/categories/{cid}` | Delete category |
| POST | `/ui/catalog/categories/{cid}/items` | Create item |
| PATCH | `/ui/catalog/categories/{cid}/items/{iid}` | Update item |
| DELETE | `/ui/catalog/categories/{cid}/items/{iid}` | Delete item |
| POST | `/ui/catalog/categories/{cid}/items/{iid}/images/upload` | Upload image |

**New files:**
```
src/pages/shop/AdminCatalog.tsx          — Category & item CRUD
src/pages/shop/ItemEditor.tsx            — Create/edit item form with image upload
src/pages/shop/CatalogPage.tsx           — Add "Admin" tab (conditionally shown)
```

**UI spec:**
- **Category management** — Create category dialog, delete with confirmation.
  Drag-and-drop reorder (visual only, server doesn't support ordering).
- **Item editor** — Form with name, description (rich text or markdown), price,
  currency, attributes (key-value pairs), image upload with preview. Multiple
  images with drag-to-reorder.
- **Admin toggle** — Admin mode toggle in catalog page header. When enabled,
  shows edit/delete buttons on items and categories.

### 6B. Profile Audit Log

**Backend endpoint:**
| Method | Path | Notes |
|--------|------|-------|
| GET | `/ui/profile/audit` | Profile change history |

**Files to modify:**
```
src/pages/settings/ProfilePage.tsx       — Add "Activity" tab
src/pages/settings/ProfileAudit.tsx      — Timeline of profile changes
```

**UI spec:**
- **Audit timeline** — Vertical timeline showing profile changes with timestamps,
  field changed, old → new values. Filterable by field.

### 6C. Billing Enhancements

**Backend endpoints currently UNUSED by frontend:**
| Method | Path | Notes |
|--------|------|-------|
| POST | `/ui/billing/charge-once` | One-time charge |
| POST | `/ui/billing/refund` | Process refund |
| POST | `/ui/billing/setup-intent/us-bank` | Bank account setup |
| POST | `/ui/billing/us-bank/verify-microdeposits` | Verify bank deposits |
| POST | `/ui/billing/checkout_session` | Create Stripe checkout |
| POST | `/ui/billing/_dev/add-charge` | Dev: test charge |

**Files to modify:**
```
src/pages/billing/PaymentMethods.tsx     — Add bank account setup flow
src/pages/billing/BillingOverview.tsx     — Add refund action, one-time charge
```

**UI spec:**
- **Bank account setup** — "Add Bank Account" option → micro-deposit verification
  flow with two-amount input.
- **Refund dialog** — On ledger entries, "Refund" button → amount input (partial
  or full) → confirmation.

---

## Implementation Priority & Sizing

| Phase | Theme | Estimated Files | Priority |
|-------|-------|----------------|----------|
| 1 | Purchase History & Subscriptions | ~12 new, ~3 modified | **High** — Revenue features |
| 2 | Messaging & Feed Enhancements | ~8 new, ~6 modified | **High** — Engagement |
| 3 | File Manager & Calendar Enhancements | ~5 new, ~8 modified | **Medium** — Feature completion |
| 4 | Auth & Security Enhancements | ~6 new, ~3 modified | **Medium** — Security coverage |
| 5 | Visual Polish & UX | ~3 new, ~15 modified | **High** — User experience |
| 6 | Admin & Advanced Features | ~5 new, ~5 modified | **Low** — Power users |

---

## Technical Notes

- All new pages must use `React.lazy()` (already set up in App.tsx).
- Follow established patterns: PageHeader, Tabs, RHF + Zod, useMutation + toast.
- Types go in `src/api/types.ts`, endpoints in `src/api/endpoints/`.
- Strict TypeScript: no unused vars/params, use `?.` for unchecked index access.
- Cannot use `.at()` (target lacks es2022). Must wrap mixed `??`/`||` in parens.
- EmptyState `icon` prop is `ReactNode` (pass `<Icon className="h-8 w-8" />`).
- EmptyState `action` prop is `{ label: string; onClick: () => void }`.
- All destructive actions use `ConfirmDialog` with `variant="danger"`.
- Mobile bottom padding on `<main>` already accounts for MobileNav bar.
