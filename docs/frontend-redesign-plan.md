# Frontend Redesign Plan

## 1. Current State Assessment

### What exists today
The current frontend is a **single static HTML page** (`app/static/index.html`, ~1,857 lines) with a monolithic JavaScript file (`app/static/main.js`, ~7,461 lines) and minimal CSS (`app/static/styles.css`, 71 lines). It serves as a developer-oriented "Control Panel" that exposes every API endpoint as raw form inputs and buttons on one scrolling page.

### Key limitations
- **No navigation or information hierarchy** — all 12+ feature sections are stacked vertically on a single page, requiring endless scrolling
- **No visual design system** — only 71 lines of CSS with basic card layout, no color palette, no typography scale, no spacing system
- **No responsive design** — cards use `min-width: 360px` with flexbox wrapping, but no true mobile layout
- **No component architecture** — 7,400 lines of imperative vanilla JS with `getElementById` calls, no reusable components
- **No state management** — data is fetched and painted directly into the DOM, no central store
- **No loading/error states** — sparse `.muted` status text, no skeletons, spinners, or error boundaries
- **No onboarding flow** — users land on a raw control panel with no guidance
- **Developer-tool aesthetic** — looks like an API test harness, not a product

### What the backend supports
The FastAPI backend provides **200+ REST endpoints** across 28 router files covering: authentication (Cognito JWT + MFA), messaging, billing (Stripe/PayPal/CCBill), file management, calendar/scheduling, shopping cart/catalog, newsfeed/social, alerts/notifications (SSE + WebSocket), user profiles, addresses, API keys, and account management. The backend is production-ready; the frontend needs to match it.

---

## 2. Technology Stack Recommendation

### Framework: React 18+ with Vite
- **Why React**: Largest ecosystem, best hiring pool, excellent for component-driven UIs with complex state. The app has ~12 major feature domains each needing their own views, forms, real-time updates (SSE/WebSocket), and modals — React's component model handles this naturally.
- **Why Vite**: Fast dev server with HMR, optimized production builds, first-class React support. Lighter than Next.js since this is an SPA that talks to an existing FastAPI backend (no SSR needed).

### Styling: Tailwind CSS 4 + shadcn/ui
- **Tailwind CSS**: Utility-first approach gives consistent spacing, colors, and typography without writing custom CSS. Produces small bundles via purging.
- **shadcn/ui**: Not a component library — it's a collection of copy-paste, fully customizable components built on Radix UI primitives. Provides accessible, well-designed building blocks (dialogs, dropdowns, tables, tabs, toasts, forms) that we own and can modify. No vendor lock-in.

### State & Data Fetching: TanStack Query (React Query) + Zustand
- **TanStack Query**: Handles server state (caching, background refetching, pagination, optimistic updates). Perfect for the 200+ API endpoints — each query is declarative and automatically handles loading/error/stale states.
- **Zustand**: Lightweight client-side state for UI concerns (sidebar open/closed, active conversation, selected cart, theme preference). Avoids Redux boilerplate.

### Routing: React Router v7
- Enables proper URL-based navigation between feature sections (e.g., `/messages`, `/billing`, `/files`) instead of one scrolling page.

### Forms: React Hook Form + Zod
- Many features require multi-field forms (profile editing, address management, calendar events, billing setup). React Hook Form is performant (uncontrolled inputs), and Zod provides schema validation that can mirror the backend's Pydantic models.

### Real-time: Native EventSource + WebSocket
- The backend already provides SSE endpoints (`/ui/alerts/stream`, `/messaging/events/stream`) and WebSocket support. Use native browser APIs wrapped in custom React hooks (`useAlertStream`, `useMessagingEvents`).

### Additional Libraries
| Concern | Library | Rationale |
|---|---|---|
| Icons | Lucide React | Clean, consistent icon set used by shadcn/ui |
| Date handling | date-fns | Lightweight, tree-shakeable (calendar events, timestamps) |
| Charts | Recharts | For billing ledger visualization, usage metrics |
| File uploads | Built-in (presigned URLs) | Backend uses S3 presigned URLs, no special library needed |
| Notifications | Sonner | Toast notification library that integrates with shadcn/ui |
| Payments | @stripe/react-stripe-js | Official Stripe Elements for PCI-compliant card forms |

---

## 3. Application Architecture

### Directory structure
```
frontend/
├── index.html
├── vite.config.ts
├── tailwind.config.ts
├── tsconfig.json
├── package.json
├── public/
│   └── favicon.svg
└── src/
    ├── main.tsx                    # React entry point
    ├── App.tsx                     # Root component with router + providers
    ├── api/
    │   ├── client.ts              # Axios/fetch wrapper with auth headers
    │   ├── types.ts               # TypeScript types mirroring backend models
    │   └── endpoints/
    │       ├── auth.ts            # Session, MFA, login API calls
    │       ├── messaging.ts       # Conversations, messages
    │       ├── billing.ts         # Stripe, PayPal, CCBill, ledger
    │       ├── files.ts           # File manager operations
    │       ├── calendar.ts        # Calendars, events, bookings
    │       ├── cart.ts            # Shopping cart + catalog
    │       ├── profile.ts         # Profile, addresses
    │       ├── alerts.ts          # Alerts, preferences
    │       ├── newsfeed.ts        # Posts, comments, follows
    │       └── account.ts         # API keys, account status
    ├── hooks/
    │   ├── useAuth.ts             # Auth context + token management
    │   ├── useAlertStream.ts      # SSE hook for real-time alerts
    │   ├── useMessagingStream.ts  # SSE hook for messaging events
    │   └── useMediaQuery.ts       # Responsive breakpoint hook
    ├── stores/
    │   ├── uiStore.ts             # Sidebar, theme, modals (Zustand)
    │   └── authStore.ts           # Token + session state (Zustand)
    ├── components/
    │   ├── ui/                    # shadcn/ui base components
    │   │   ├── button.tsx
    │   │   ├── input.tsx
    │   │   ├── dialog.tsx
    │   │   ├── dropdown-menu.tsx
    │   │   ├── table.tsx
    │   │   ├── tabs.tsx
    │   │   ├── card.tsx
    │   │   ├── badge.tsx
    │   │   ├── avatar.tsx
    │   │   ├── skeleton.tsx
    │   │   ├── toast.tsx
    │   │   └── ...
    │   ├── layout/
    │   │   ├── AppShell.tsx       # Sidebar + header + content area
    │   │   ├── Sidebar.tsx        # Navigation sidebar
    │   │   ├── Header.tsx         # Top bar with user menu
    │   │   └── MobileNav.tsx      # Bottom tab bar for mobile
    │   └── shared/
    │       ├── DataTable.tsx       # Reusable sortable/filterable table
    │       ├── EmptyState.tsx      # "No data" placeholder
    │       ├── LoadingScreen.tsx   # Full-page spinner
    │       ├── ErrorBoundary.tsx   # Error fallback UI
    │       ├── ConfirmDialog.tsx   # Reusable confirmation modal
    │       └── StatusBadge.tsx     # ok/warn/bad pill component
    └── pages/
        ├── Login.tsx              # Login + MFA challenge flow
        ├── Dashboard.tsx          # Overview/home page
        ├── messages/
        │   ├── MessagesLayout.tsx # Sidebar list + conversation pane
        │   ├── ConversationList.tsx
        │   ├── ConversationView.tsx
        │   ├── MessageBubble.tsx
        │   └── ComposeBar.tsx
        ├── billing/
        │   ├── BillingOverview.tsx # Balance, autopay, payment methods
        │   ├── PaymentMethods.tsx  # Add/remove cards, PayPal, CCBill
        │   ├── Ledger.tsx         # Transaction history table
        │   └── Subscriptions.tsx  # Active subscriptions
        ├── files/
        │   ├── FileManager.tsx    # Main file browser
        │   ├── FileTable.tsx      # File listing with sort/select
        │   ├── UploadZone.tsx     # Drag-and-drop upload area
        │   └── ShareDialog.tsx    # File sharing modal
        ├── calendar/
        │   ├── CalendarView.tsx   # Month/week/day calendar grid
        │   ├── EventDialog.tsx    # Create/edit event modal
        │   ├── BookingLinks.tsx   # Public booking link management
        │   └── Availability.tsx   # Working hours + openings
        ├── shop/
        │   ├── Catalog.tsx        # Product category browser
        │   ├── ProductDetail.tsx  # Single product with reviews
        │   ├── Cart.tsx           # Shopping cart view
        │   └── Checkout.tsx       # Checkout flow
        ├── feed/
        │   ├── NewsFeed.tsx       # Scrollable post feed
        │   ├── PostCard.tsx       # Individual post with actions
        │   ├── CreatePost.tsx     # Post composer
        │   └── CommentsThread.tsx # Nested comments
        ├── alerts/
        │   ├── AlertCenter.tsx    # Alert history + real-time
        │   └── AlertPrefs.tsx     # Channel preferences
        ├── security/
        │   ├── MfaDevices.tsx     # TOTP, SMS, Email devices
        │   ├── Sessions.tsx       # Active sessions
        │   ├── TrustedDevices.tsx # Device management
        │   ├── ApiKeys.tsx        # API key management
        │   └── Recovery.tsx       # Recovery codes + password reset
        └── settings/
            ├── Profile.tsx        # Profile editor
            ├── Addresses.tsx      # Address book
            └── Account.tsx        # Status, suspension, closure
```

---

## 4. Page-by-Page Design Plan

### 4.1 Layout Shell (AppShell)

**Desktop (>1024px):**
```
┌──────────────────────────────────────────────────┐
│  Header: Logo | Search | Alerts Bell | User Menu │
├────────┬─────────────────────────────────────────┤
│        │                                         │
│  Side  │           Main Content Area             │
│  bar   │                                         │
│        │                                         │
│  Nav   │                                         │
│  links │                                         │
│        │                                         │
│        │                                         │
└────────┴─────────────────────────────────────────┘
```

- **Sidebar** (240px, collapsible to 64px icon-only mode):
  - Logo/brand at top
  - Navigation grouped into sections:
    - **Main**: Dashboard, Messages, Feed
    - **Commerce**: Shop, Cart, Billing
    - **Productivity**: Files, Calendar
    - **Account**: Profile, Security, Settings
  - Active item highlighted with accent color + left border
  - Unread badges on Messages, Alerts
  - Collapse toggle at bottom

- **Header** (56px):
  - Global search (Cmd+K shortcut)
  - Alert bell with unread count (real-time via SSE)
  - User avatar + dropdown (profile, settings, logout)

**Mobile (<768px):**
- Sidebar becomes a slide-out drawer (hamburger menu)
- Bottom tab bar with 5 key icons: Dashboard, Messages, Files, Shop, More
- Header shrinks to logo + avatar only

### 4.2 Login / Authentication Page

**Layout:** Centered card on gradient background

**Flow:**
1. **Step 1 — Credentials**: Email/username + password form, "Sign in" button. Clean, focused.
2. **Step 2 — MFA Challenge**: After `POST /ui/session/start`, if `challenges_required` is returned, show the appropriate challenge UI:
   - TOTP: 6-digit code input with auto-focus between digits
   - SMS: Show masked phone number, "Code sent to •••1234", input field
   - Email: Show masked email, "Code sent to j•••@example.com", input field
   - Recovery: Single text input for recovery code
3. **Step 3 — Success**: Redirect to Dashboard

**Design details:**
- Animated gradient background (subtle, slow-moving)
- Card with soft shadow, rounded corners (16px)
- Brand logo centered above the card
- "Remember this device" toggle
- Error messages in-line below inputs (red text, shake animation)
- Loading state: button shows spinner, inputs disabled

### 4.3 Dashboard (Home)

**Purpose:** At-a-glance overview of all activity

**Layout:** Grid of summary cards

```
┌───────────────┬───────────────┬───────────────┐
│  Unread       │  Balance      │  Files        │
│  Messages: 3  │  $24.50       │  12 files     │
│               │  Autopay: ON  │  3.2 GB used  │
├───────────────┼───────────────┼───────────────┤
│  Upcoming     │  Recent       │  Cart         │
│  Events: 2    │  Alerts: 5    │  3 items      │
│  Next: 2pm    │  View all →   │  $59.97       │
├───────────────┴───────────────┴───────────────┤
│  Recent Activity Feed                         │
│  • New message from Alice (2m ago)            │
│  • Payment of $9.99 processed (1h ago)        │
│  • File "report.pdf" shared with you (3h ago) │
└───────────────────────────────────────────────┘
```

Each card is clickable, navigating to the relevant section. Cards show skeleton loaders while data fetches.

### 4.4 Messages

**Layout:** Master-detail split (similar to iMessage/Slack)

```
┌──────────────────┬───────────────────────────────┐
│  Search          │  Alice Chen              ○    │
│  ┌────────────┐  │                               │
│  │ Alice Chen │  │  ┌─────────────────┐          │
│  │ Hey, are.. │  │  │ Hi! How are you │  2:30 PM │
│  ├────────────┤  │  └─────────────────┘          │
│  │ Team Chat  │  │          ┌──────────────────┐  │
│  │ Bob: Let.. │  │  2:31 PM │ I'm great, you? │  │
│  ├────────────┤  │          └──────────────────┘  │
│  │ Carol D.   │  │                               │
│  │ Thanks!    │  │                               │
│  └────────────┘  ├───────────────────────────────┤
│                  │  [Type a message...]    📎 ▶  │
│  + New convo     │                               │
└──────────────────┴───────────────────────────────┘
```

**Features:**
- Conversation list on left (280px) with search, avatar, name, last message preview, timestamp, unread badge
- Message area on right with chat bubbles (own messages right-aligned, others left-aligned)
- Compose bar at bottom with text input, file attachment button, send button
- Message actions on hover: react (emoji picker), edit, forward
- Real-time updates via SSE (`/messaging/events/stream`)
- Group conversations show participant avatars stacked
- Image messages render inline with lightbox on click
- New conversation dialog: search contacts, select DM or group

### 4.5 Billing

**Layout:** Tabbed interface

**Tabs:** Overview | Payment Methods | Ledger | Subscriptions

**Overview tab:**
- Balance card (large number, accent color for positive/negative)
- Autopay status toggle
- "Pay balance" button (opens Stripe checkout)
- Quick stats: total spent this month, next billing date

**Payment Methods tab:**
- List of saved methods with card brand icon, last 4, expiry
- Default method badge
- "Add card" button → Stripe Elements form in a dialog
- "Add PayPal" button → PayPal flow
- Remove/set-default actions

**Ledger tab:**
- Filterable, sortable DataTable with columns: Date, Description, Amount, Status
- Date range picker filter
- Export to CSV button
- Color-coded amounts (green for credits, red for charges)

**Subscriptions tab:**
- Active subscription cards with plan name, price, next billing date
- Cancel/pause buttons
- Subscription history

### 4.6 File Manager

**Layout:** Familiar file browser (Google Drive-style)

```
┌─────────────────────────────────────────────────┐
│  📁 My Files > Documents > Reports              │
│  [Upload] [New Folder] [⬇ Download] [🗑 Delete] │
├─────────────────────────────────────────────────┤
│  🔍 Search files...                             │
├────┬───────────────┬──────┬──────────┬──────────┤
│ ☐  │ Name ▲        │ Type │ Size     │ Modified │
├────┼───────────────┼──────┼──────────┼──────────┤
│ ☐  │ 📁 Invoices   │ dir  │ —        │ Jan 15   │
│ ☐  │ 📄 report.pdf │ pdf  │ 2.4 MB   │ Jan 14   │
│ ☐  │ 🖼 photo.jpg  │ jpg  │ 850 KB   │ Jan 12   │
└────┴───────────────┴──────┴──────────┴──────────┘
```

**Features:**
- Breadcrumb navigation at top
- Drag-and-drop upload zone (dashed border area, or click to browse)
- Toolbar: Upload, New Folder, Download Selected (ZIP), Move, Delete
- File table with checkbox selection, sortable columns
- File type icons (folder, PDF, image, document, etc.)
- Right-click context menu: Download, Share, Move, Rename, Delete
- Share dialog: enter user ID, set permissions (read/write)
- "Shared with me" section at bottom or as a separate tab
- Upload progress shown as toast notifications with progress bars
- Image files show thumbnail previews on hover

### 4.7 Calendar

**Layout:** Calendar grid with event sidebar

**Views:** Month | Week | Day (tab toggle)

**Month view:**
```
┌──────────────────────────────────────────┐
│  ◀  January 2026  ▶    [Month|Week|Day]  │
├──────┬──────┬──────┬──────┬──────┬──────┤
│ Mon  │ Tue  │ Wed  │ Thu  │ Fri  │ Sat  │
├──────┼──────┼──────┼──────┼──────┼──────┤
│      │      │  1   │  2   │  3   │  4   │
│      │      │      │Team  │      │      │
│      │      │      │mtg   │      │      │
├──────┼──────┼──────┼──────┼──────┼──────┤
│  5   │  6   │  7   │  8   │  9   │  10  │
│      │Design│      │      │Demo  │      │
│      │rev.  │      │      │day   │      │
└──────┴──────┴──────┴──────┴──────┴──────┘
```

**Features:**
- Click a day to create event (opens dialog)
- Click an event to view/edit (opens dialog)
- Event dialog: title, description, date/time, recurrence rule, calendar selection
- Color-coded events per calendar
- Working hours shading (gray out non-working hours in week/day view)
- Booking links management page
- Availability checker

### 4.8 Shop / Catalog

**Layout:** Category sidebar + product grid

```
┌──────────┬──────────────────────────────────┐
│Categories│  Electronics  (24 items)          │
│          │  ┌──────┐ ┌──────┐ ┌──────┐      │
│ ▸ Electr │  │ 🖼   │ │ 🖼   │ │ 🖼   │      │
│   Books  │  │Laptop│ │Phone │ │Watch │      │
│   Home   │  │$999  │ │$699  │ │$299  │      │
│   Sports │  │★★★★☆ │ │★★★★★ │ │★★★☆☆ │      │
│          │  └──────┘ └──────┘ └──────┘      │
└──────────┴──────────────────────────────────┘
```

**Product detail page:**
- Image gallery
- Name, description, price
- "Add to cart" button with quantity selector
- Reviews section with star ratings
- Write a review form

**Cart page:**
- Line items with quantity adjusters and remove buttons
- Running total
- "Proceed to checkout" button

### 4.9 Newsfeed / Social

**Layout:** Centered content feed (Twitter/LinkedIn style)

```
┌───────────────────────────────────────┐
│  ┌─────────────────────────────────┐  │
│  │ What's on your mind?      [Post]│  │
│  └─────────────────────────────────┘  │
│  ┌─────────────────────────────────┐  │
│  │ 👤 Alice Chen · 2h ago          │  │
│  │ Just shipped the new feature!   │  │
│  │ ♥ 12  💬 3  ↗ Share   💰 Tip   │  │
│  └─────────────────────────────────┘  │
│  ┌─────────────────────────────────┐  │
│  │ 👤 Bob Smith · 5h ago           │  │
│  │ 🔒 Unlock this post ($2.99)    │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
```

**Features:**
- Post composer at top
- Feed cards with author avatar, name, timestamp, content
- Like, comment, share, tip actions
- Locked posts with unlock-to-view
- Infinite scroll with "Load more" fallback
- Comment threads expand inline
- Follow/unfollow buttons
- Real-time new post notifications via SSE

### 4.10 Alerts

**Layout:** Notification center dropdown + full page

**Dropdown (from bell icon):**
- Last 10 alerts with title, detail snippet, timestamp
- Unread items have blue dot
- "Mark all read" button
- "View all" link → full page

**Full page:**
- Filterable list by alert type
- Bulk "mark as read" with checkboxes
- Alert preferences panel: toggle channels (email, SMS, push, toast, webhook) per event type
- Real-time new alerts via SSE stream

### 4.11 Security

**Tabs:** MFA Devices | Sessions | Trusted Devices | API Keys | Recovery

**MFA Devices tab:**
- Three sub-sections: TOTP, SMS, Email
- Each shows a list of devices with label, status badge, last used date
- "Add device" button per type opens enrollment wizard:
  - TOTP: QR code display → 6-digit confirmation
  - SMS: Phone number input → verification code
  - Email: Email input → verification code
- Remove device (with re-authentication)

**Sessions tab:**
- List of active sessions with: browser/OS, IP, location, last active, "current" badge
- "Revoke" button per session
- "Revoke all other sessions" bulk action

**API Keys tab:**
- List with label, created date, last 8 chars of key, expiry
- "Create key" button → dialog with generated key (show once)
- IP allowlist management per key

### 4.12 Settings

**Tabs:** Profile | Addresses | Account

**Profile tab:**
- Avatar upload with circular crop preview
- Cover photo upload
- Form fields: display name, first/last name, bio, location, email, phone
- Language list with proficiency levels
- Save button with optimistic update

**Addresses tab:**
- List of saved addresses with labels
- "Add address" dialog with form
- Set primary address toggle
- Edit/delete actions

**Account tab:**
- Account status badge (active/suspended/closed)
- Suspension/reactivation controls
- Account closure workflow (confirmation dialogs)
- Audit log viewer

---

## 5. Design System

### Color Palette
```
Primary:       #2563EB (blue-600)     — CTAs, active states, links
Primary hover: #1D4ED8 (blue-700)     — Button hover
Secondary:     #6366F1 (indigo-500)   — Accent elements
Success:       #16A34A (green-600)    — Positive states, confirmations
Warning:       #D97706 (amber-600)    — Caution states
Danger:        #DC2626 (red-600)      — Destructive actions, errors
Background:    #F8FAFC (slate-50)     — Page background
Surface:       #FFFFFF                — Cards, modals
Border:        #E2E8F0 (slate-200)    — Card borders, dividers
Text primary:  #0F172A (slate-900)    — Headings, body text
Text secondary:#64748B (slate-500)    — Muted text, labels
Text on dark:  #F8FAFC (slate-50)     — Text on primary buttons
```

### Dark Mode
All colors have dark-mode counterparts using Tailwind's `dark:` variant:
```
Background:    #0F172A (slate-900)
Surface:       #1E293B (slate-800)
Border:        #334155 (slate-700)
Text primary:  #F1F5F9 (slate-100)
Text secondary:#94A3B8 (slate-400)
```
Theme toggle in header (system/light/dark).

### Typography
- **Font family**: Inter (Google Fonts) — clean, modern, excellent readability
- **Scale**:
  - Page title: 24px / semibold
  - Section heading: 18px / semibold
  - Card title: 16px / medium
  - Body: 14px / regular
  - Caption/label: 12px / medium, text-secondary color
  - Monospace: JetBrains Mono — API keys, code, IDs

### Spacing
Tailwind's default 4px grid: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64

### Border Radius
- Buttons: 8px (`rounded-lg`)
- Cards: 12px (`rounded-xl`)
- Modals: 16px (`rounded-2xl`)
- Avatars: full circle (`rounded-full`)
- Inputs: 8px (`rounded-lg`)

### Shadows
- Card: `shadow-sm` (subtle lift)
- Card hover: `shadow-md` (interactive feedback)
- Modal: `shadow-xl` (prominent elevation)
- Dropdown: `shadow-lg`

### Animations
- Page transitions: fade-in (150ms ease)
- Sidebar collapse: width transition (200ms ease)
- Loading skeletons: pulse animation
- Toast notifications: slide-in from top-right (200ms ease-out)
- Button press: subtle scale (0.98) on active
- List item appearance: stagger fade-in

---

## 6. Implementation Phases

### Phase 1 — Foundation (scaffold + auth + layout)
**Goal:** Working app shell with authentication

1. Initialize Vite + React + TypeScript project in `frontend/`
2. Install and configure Tailwind CSS, shadcn/ui
3. Set up React Router with route definitions
4. Build API client (`api/client.ts`) with interceptors for auth tokens, CSRF
5. Implement auth store and login page (session start + MFA challenge flow)
6. Build AppShell layout: sidebar, header, mobile nav
7. Add theme toggle (light/dark)
8. Create shared components: DataTable, EmptyState, ErrorBoundary, StatusBadge
9. Set up TanStack Query provider with default config
10. Configure Vite proxy to forward `/ui/*`, `/api/*`, `/v1/*`, `/messaging/*`, `/feed/*`, `/posts/*`, `/social/*` to FastAPI backend

### Phase 2 — Core Features (messages + files + profile)
**Goal:** The most-used daily features

1. Messages: conversation list, conversation view, compose bar, real-time SSE
2. File Manager: file table, breadcrumb nav, upload zone, folder creation
3. Profile: profile editor form, avatar upload, language management
4. Alerts: notification bell dropdown, alert center page, SSE integration
5. Dashboard: summary cards with data from multiple endpoints

### Phase 3 — Commerce (billing + shop + cart)
**Goal:** Revenue-generating features

1. Billing: overview, payment methods (Stripe Elements integration), ledger table
2. Shopping Cart: cart view, item management, checkout flow
3. Catalog: category browser, product grid, product detail, reviews
4. Subscriptions: active subscriptions, cancel/pause

### Phase 4 — Productivity (calendar + feed + security)
**Goal:** Remaining feature completeness

1. Calendar: month/week/day views, event creation, booking links
2. Newsfeed: post feed, post composer, comments, follow/unfollow, tips
3. Security: MFA device management, sessions, trusted devices, API keys, recovery
4. Settings: addresses, account status, suspension/closure

### Phase 5 — Polish
**Goal:** Production-ready quality

1. Responsive testing and fixes across breakpoints
2. Accessibility audit (keyboard nav, ARIA labels, focus management, screen reader testing)
3. Performance optimization (code splitting per route, lazy loading, image optimization)
4. Error handling audit (network failures, 401/403 handling, retry logic)
5. Loading state polish (skeletons everywhere, optimistic updates)
6. End-to-end testing with Playwright
7. PWA support (service worker, offline indicator)

---

## 7. Backend Integration Notes

### API Client Configuration
```typescript
// All requests include:
// - Cookie: ui_session (session ID)
// - Cookie: ui_csrf (CSRF token)
// - X-CSRF-Token header matching ui_csrf cookie
// - Authorization: Bearer <access_token> (for Cognito-validated endpoints)
```

### Key Integration Patterns

**Authentication flow:**
1. `POST /ui/session/start` with credentials → returns `challenges_required`
2. If challenges present, render MFA UI, then `POST /ui/session/finalize`
3. Store tokens in httpOnly cookies (set by backend), keep CSRF token in JS
4. `POST /ui/session/refresh` on 401 responses (interceptor)

**Real-time updates:**
- Alerts: `GET /ui/alerts/stream` (SSE) — update bell icon badge count
- Messaging: `GET /messaging/events/stream` (SSE) — update conversation list + active chat
- Use reconnecting logic with exponential backoff

**Pagination:**
- Most list endpoints support cursor-based pagination (`cursor` param)
- Use TanStack Query's `useInfiniteQuery` for "load more" patterns

**File uploads:**
- `POST /v1/fs/upload` with multipart form data
- Track progress with `XMLHttpRequest.upload.onprogress`
- Show toast with progress bar

### Backend Changes Needed
The backend currently serves the static frontend from `app/static/`. For the new React app:

1. **Development**: Vite dev server proxies API calls to FastAPI (no backend changes needed)
2. **Production**: Build the React app (`npm run build`), output to `frontend/dist/`, and either:
   - Option A: Serve from FastAPI using `StaticFiles(directory="frontend/dist")` (simple, single deploy)
   - Option B: Serve from a CDN/nginx and point API calls to the FastAPI backend (better for scale)
3. **CORS**: Already configured to allow all origins — no changes needed for development

---

## 8. Key Design Principles

1. **Progressive disclosure** — Show summary first, details on demand. Don't overwhelm with all 200+ API capabilities at once.
2. **Consistency** — Every list looks the same, every form behaves the same, every destructive action has the same red button + confirmation pattern.
3. **Responsiveness** — Desktop-first but mobile-usable. Messages and files are the most mobile-critical features.
4. **Real-time by default** — Alerts and messages update live. No "refresh" buttons needed (though available as fallback).
5. **Graceful degradation** — Show meaningful empty states, handle network errors with retry prompts, never show broken UI.
6. **Accessibility** — Keyboard navigation for all interactions, ARIA labels, focus trapping in modals, sufficient color contrast.
