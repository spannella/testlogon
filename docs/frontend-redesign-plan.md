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

## 6. Implementation Steps (15 Steps)

Each step produces a working, testable increment. Steps 1-6 form the foundation, 7-13 build out every feature page, and 14-15 bring it to production quality.

---

### Step 1 — Project Scaffold
**Goal:** Empty React app builds, runs, and proxies to the FastAPI backend

**Deliverables:**
- Initialize `frontend/` with Vite + React 18 + TypeScript (`npm create vite@latest`)
- Install core dependencies: `react-router-dom`, `@tanstack/react-query`, `zustand`, `react-hook-form`, `zod`, `date-fns`, `lucide-react`, `sonner`
- Create `vite.config.ts` with proxy rules forwarding `/ui/*`, `/api/*`, `/v1/*`, `/messaging/*`, `/feed/*`, `/posts/*`, `/social/*` to `http://localhost:8000`
- Create `tsconfig.json` with path aliases (`@/` → `src/`)
- Create placeholder `src/main.tsx`, `src/App.tsx` with React Router skeleton (empty routes for all pages)
- Verify: `npm run dev` starts, shows "Hello World", API proxy works

**Files created:**
```
frontend/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
└── src/
    ├── main.tsx
    └── App.tsx
```

---

### Step 2 — Design System & UI Primitives
**Goal:** Tailwind configured with the design tokens, shadcn/ui components installed, dark mode working

**Deliverables:**
- Install and configure Tailwind CSS 4 with the color palette, typography (Inter + JetBrains Mono), and spacing defined in Section 5
- Initialize shadcn/ui (`npx shadcn@latest init`) and install base components: `button`, `input`, `textarea`, `select`, `dialog`, `dropdown-menu`, `tabs`, `table`, `card`, `badge`, `avatar`, `skeleton`, `tooltip`, `separator`, `sheet`, `popover`, `command`
- Install `sonner` toast integration via shadcn/ui's toaster component
- Set up CSS custom properties for light/dark themes
- Create `src/stores/uiStore.ts` (Zustand) with `theme` state (`system` | `light` | `dark`) persisted to `localStorage`
- Create a `ThemeProvider` component that applies `dark` class to `<html>`
- Verify: Toggle between light/dark, all shadcn components render correctly in both

**Files created:**
```
src/
├── components/ui/          # ~16 shadcn/ui component files
├── stores/uiStore.ts
├── lib/utils.ts            # cn() helper from shadcn
└── globals.css             # Tailwind directives + design tokens
```

---

### Step 3 — API Client & TypeScript Types
**Goal:** Typed API layer that handles auth headers, CSRF, token refresh, and error handling

**Deliverables:**
- Create `src/api/client.ts`: fetch wrapper that:
  - Reads `access_token` from the auth store and sets `Authorization: Bearer <token>`
  - Reads CSRF token from `ui_csrf` cookie and sets `X-CSRF-Token` header
  - Sends credentials (`credentials: 'include'`) for session cookies
  - On 401 response: calls `POST /ui/session/refresh`, retries original request once
  - Throws typed errors for 4xx/5xx responses
- Create `src/api/types.ts`: TypeScript interfaces mirroring the backend Pydantic models in `app/models.py` (~860 lines). Key types:
  - Auth: `SessionStartReq`, `SessionStartResp`, `SessionFinalizeReq`, `MfaChallenge`
  - Messaging: `Conversation`, `Message`, `MessageSendReq`
  - Billing: `PaymentMethod`, `LedgerEntry`, `BalanceInfo`, `SubscriptionInfo`
  - Files: `FileEntry`, `FolderEntry`, `UploadResp`
  - Calendar: `Calendar`, `CalendarEvent`, `RecurrenceRule`, `BookingLink`
  - Commerce: `CatalogCategory`, `CatalogItem`, `CartItem`, `CartTotal`
  - Social: `Post`, `Comment`, `FeedItem`
  - Profile: `UserProfile`, `Address`, `Language`
  - Alerts: `Alert`, `AlertPreferences`
  - Account: `ApiKey`, `SessionInfo`, `AccountStatus`
- Create `src/api/endpoints/` with one file per domain, each exporting typed async functions. Example:
  ```typescript
  // src/api/endpoints/auth.ts
  export const sessionStart = (body: SessionStartReq): Promise<SessionStartResp> => ...
  export const sessionFinalize = (body: SessionFinalizeReq): Promise<SessionFinalizeResp> => ...
  ```
- Create `src/stores/authStore.ts` (Zustand): stores `userId`, `accessToken`, `isAuthenticated`, `login()`, `logout()` actions

**Files created:**
```
src/
├── api/
│   ├── client.ts
│   ├── types.ts
│   └── endpoints/
│       ├── auth.ts
│       ├── messaging.ts
│       ├── billing.ts
│       ├── files.ts
│       ├── calendar.ts
│       ├── cart.ts
│       ├── profile.ts
│       ├── alerts.ts
│       ├── newsfeed.ts
│       └── account.ts
└── stores/authStore.ts
```

---

### Step 4 — Login Page & Authentication Flow
**Goal:** Users can log in with credentials + MFA, get redirected to the app

**Deliverables:**
- Create `src/pages/Login.tsx`:
  - Centered card on a subtle gradient background (Tailwind gradient classes)
  - Step 1: Username + password form (React Hook Form + Zod validation)
  - Step 2: MFA challenge UI — conditionally render based on `challenges_required` from `POST /ui/session/start`:
    - TOTP: 6-digit OTP input (individual digit boxes with auto-advance)
    - SMS: masked phone display + code input
    - Email: masked email display + code input
    - Recovery code: single text input
  - Step 3: On success (`POST /ui/session/finalize`), update `authStore`, redirect to `/`
  - "Remember this device" checkbox
  - Loading states: button spinner, disabled inputs during submission
  - Error states: inline validation messages, API error display
- Create protected route wrapper: redirects to `/login` if `!isAuthenticated`
- Create `src/pages/PasswordRecovery.tsx`: start recovery, enter code + new password (mirrors existing password recovery section)

**Files created:**
```
src/pages/
├── Login.tsx
└── PasswordRecovery.tsx
```

---

### Step 5 — App Shell Layout (Sidebar + Header + Routing)
**Goal:** Full navigation structure — every page is reachable via sidebar, all routes defined

**Deliverables:**
- Create `src/components/layout/AppShell.tsx`: wraps all authenticated pages
  - Flex container: sidebar (left) + main content (right)
- Create `src/components/layout/Sidebar.tsx`:
  - 240px wide, collapsible to 64px (icon-only) with smooth transition
  - Logo/brand at top
  - Nav groups with section labels: **Main** (Dashboard, Messages, Feed), **Commerce** (Shop, Cart, Billing), **Productivity** (Files, Calendar), **Account** (Profile, Security, Settings)
  - Each item: icon (Lucide) + label, active state with blue left border + blue background tint
  - Unread count badges on Messages and Alerts (placeholder, wired in Step 11)
  - Collapse toggle button at bottom
  - Collapse state stored in `uiStore`
- Create `src/components/layout/Header.tsx`:
  - 56px height
  - Left: hamburger (mobile) or page breadcrumb (desktop)
  - Center: global search button (Cmd+K visual hint) — opens `Command` dialog (shadcn)
  - Right: theme toggle (sun/moon icon), alert bell icon (placeholder badge), user avatar dropdown (profile, settings, logout)
- Create `src/components/layout/MobileNav.tsx`:
  - Fixed bottom tab bar on screens < 768px
  - 5 icons: Dashboard, Messages, Files, Shop, More (opens sheet with remaining links)
- Update `src/App.tsx`:
  - TanStack Query `QueryClientProvider` with defaults (staleTime: 30s, retry: 1)
  - `ThemeProvider`
  - `Toaster` (sonner)
  - React Router with nested routes under `AppShell` layout
  - All 12 page routes defined (render placeholder components for now)

**Files created:**
```
src/components/layout/
├── AppShell.tsx
├── Sidebar.tsx
├── Header.tsx
└── MobileNav.tsx
```

---

### Step 6 — Shared Components
**Goal:** Reusable building blocks used across all feature pages

**Deliverables:**
- `DataTable.tsx`: Generic sortable, filterable table built on shadcn `Table`. Props: `columns` definition, `data` array, `onSort`, `onRowClick`, optional checkbox selection, optional pagination footer ("Load more" or page numbers). Used by: Files, Billing Ledger, Cart items, Sessions, API Keys.
- `EmptyState.tsx`: Centered icon + title + description + optional CTA button. Used when lists are empty.
- `ErrorBoundary.tsx`: React error boundary with fallback UI ("Something went wrong" + retry button).
- `LoadingScreen.tsx`: Full-page centered spinner for route-level loading.
- `StatusBadge.tsx`: Small pill/badge component with variants: `success` (green), `warning` (amber), `danger` (red), `info` (blue), `neutral` (gray). Replaces all `.pill.ok/.warn/.bad` from old CSS.
- `ConfirmDialog.tsx`: Reusable confirmation modal (shadcn `AlertDialog`) with title, description, confirm/cancel buttons. `danger` variant turns confirm button red. Used for: delete file, revoke session, close account, remove payment method, etc.
- `PageHeader.tsx`: Consistent page title + description + action buttons layout for top of every page.

**Files created:**
```
src/components/shared/
├── DataTable.tsx
├── EmptyState.tsx
├── ErrorBoundary.tsx
├── LoadingScreen.tsx
├── StatusBadge.tsx
├── ConfirmDialog.tsx
└── PageHeader.tsx
```

---

### Step 7 — Dashboard Page
**Goal:** Home page with summary cards pulling data from multiple endpoints

**Deliverables:**
- Create `src/pages/Dashboard.tsx`:
  - 3-column responsive grid (`grid-cols-1 md:grid-cols-2 lg:grid-cols-3`)
  - Summary cards (shadcn `Card`), each with:
    - **Messages**: unread count, "View messages" link → `/messages`
    - **Balance**: current balance from `GET /ui/billing/balance`, autopay status
    - **Files**: file count from `GET /v1/fs/list`, storage used
    - **Calendar**: next upcoming event from `GET /ui/calendars/{id}/events`
    - **Alerts**: unread alert count from `GET /ui/alerts`, "View all" link
    - **Cart**: active cart item count + total from `GET /ui/shoppingcart/carts/{id}/total`
  - Each card uses `useQuery` with skeleton loading state
  - Cards are clickable (navigate to relevant page)
  - Recent Activity section below cards: last 5 alerts rendered as a timeline
- Verify: Dashboard renders with real or mock data, all links navigate correctly

**Files created:**
```
src/pages/Dashboard.tsx
```

---

### Step 8 — Messages Page
**Goal:** Full messaging experience with real-time updates

**Deliverables:**
- Create `src/pages/messages/MessagesLayout.tsx`: master-detail split layout
  - Left panel (280px, full height): `ConversationList`
  - Right panel (flex-1): `ConversationView` or empty state
  - On mobile: show only list OR conversation (back button to switch)
- Create `src/pages/messages/ConversationList.tsx`:
  - Search input at top (filters locally + calls `POST /messaging/contacts/search`)
  - List of conversations from `GET /messaging/conversations`
  - Each item: avatar, name, last message preview (truncated), timestamp, unread badge
  - "New conversation" button at bottom → opens dialog (DM or group, participant search)
  - Selected conversation highlighted
- Create `src/pages/messages/ConversationView.tsx`:
  - Header: conversation name/participants, online status indicator
  - Scrollable message area (auto-scroll to bottom on new messages)
  - Messages from `GET /messaging/conversations/{id}/messages` with `useInfiniteQuery` for "load older"
  - Each message: `MessageBubble` component
- Create `src/pages/messages/MessageBubble.tsx`:
  - Own messages: right-aligned, blue background
  - Others: left-aligned, gray background
  - Shows: sender name (group only), message text, timestamp, delivery status (sent/delivered/read)
  - Image messages: inline thumbnail, click for lightbox
  - Hover actions: react (emoji picker popover), edit, forward
- Create `src/pages/messages/ComposeBar.tsx`:
  - Text input (auto-growing textarea)
  - File attachment button (opens file picker, calls `POST /messaging/conversations/{id}/messages/image`)
  - Send button (calls `POST /messaging/conversations/{id}/messages`)
  - Optional link preview fields (collapsible)
- Create `src/hooks/useMessagingStream.ts`:
  - SSE hook connecting to `GET /messaging/events/stream`
  - On new message event: invalidate conversation query, append to active chat
  - Reconnect with exponential backoff on disconnect

**Files created:**
```
src/
├── pages/messages/
│   ├── MessagesLayout.tsx
│   ├── ConversationList.tsx
│   ├── ConversationView.tsx
│   ├── MessageBubble.tsx
│   └── ComposeBar.tsx
└── hooks/useMessagingStream.ts
```

---

### Step 9 — File Manager Page
**Goal:** Google Drive-style file browser with upload, download, share, and search

**Deliverables:**
- Create `src/pages/files/FileManager.tsx`:
  - Breadcrumb navigation at top (clickable path segments)
  - Toolbar row: Upload button, New Folder button, Download Selected (ZIP), Move Selected, Delete Selected (danger)
  - Drag-and-drop upload zone (dashed border overlay on drag-enter)
  - `FileTable` below toolbar
  - Search bar with prefix search (`GET /v1/fs/search`) and full-text search
  - Sort controls: name / updated / size, ascending/descending toggle
  - Pagination: "Load more" button with page size selector
  - "Shared with me" section (collapsible) or tab
- Create `src/pages/files/FileTable.tsx`:
  - Uses `DataTable` component
  - Columns: checkbox, file icon (by type), Name, Type, Size (human-readable), Modified date
  - Folder rows are clickable (navigate into folder)
  - File rows have action dropdown: Download, Share, Move, Rename, Delete
  - Double-click file to download
- Create `src/pages/files/UploadZone.tsx`:
  - Visual drop target that appears on drag-enter
  - Calls `POST /v1/fs/upload` with multipart form data
  - Tracks upload progress with `XMLHttpRequest.upload.onprogress`
  - Shows upload progress toasts (via Sonner) with file name + progress bar
  - Supports multiple simultaneous uploads
- Create `src/pages/files/ShareDialog.tsx`:
  - Modal: enter user ID, select permission level (read/write)
  - Calls `POST /v1/fs/share`
  - Shows current share list for the file

**Files created:**
```
src/pages/files/
├── FileManager.tsx
├── FileTable.tsx
├── UploadZone.tsx
└── ShareDialog.tsx
```

---

### Step 10 — Profile & Settings Pages
**Goal:** User can view/edit profile, manage addresses, and control account status

**Deliverables:**
- Create `src/pages/settings/Profile.tsx`:
  - Profile photo: circular avatar preview + upload button (calls profile photo upload endpoint)
  - Cover photo: wide preview + upload button
  - Form (React Hook Form + Zod): display_name, title, first_name, middle_name, last_name, birthday, gender (select), location, email, phone, description (textarea)
  - Mailing address sub-form: line1, line2, city, state, postal_code, country
  - Languages section: list with add/remove, each has name + proficiency level
  - "Save" button → `PATCH /ui/profile` (optimistic update via TanStack Query mutation)
  - Audit log section: expandable list from profile audit endpoint
- Create `src/pages/settings/Addresses.tsx`:
  - List of saved addresses from `GET /ui/addresses`
  - Each address card: label, formatted address, "Primary" badge if applicable
  - "Add address" button → dialog with form
  - Edit/delete actions per address
  - "Set as primary" toggle → `POST /ui/addresses/primary`
- Create `src/pages/settings/Account.tsx`:
  - Account status badge (`StatusBadge` component)
  - Suspension section: "Suspend account" (danger button + `ConfirmDialog`)
  - Reactivation section: "Reactivate" button
  - Account closure section: two-step flow (start → finalize) with strong confirmation dialogs

**Files created:**
```
src/pages/settings/
├── Profile.tsx
├── Addresses.tsx
└── Account.tsx
```

---

### Step 11 — Alerts & Notifications System
**Goal:** Real-time alert bell in header, full alert center page, and preference management

**Deliverables:**
- Create `src/hooks/useAlertStream.ts`:
  - SSE hook connecting to `GET /ui/alerts/stream`
  - On new alert: increment unread count in store, show toast notification, invalidate alert query
  - Reconnect with exponential backoff
- Update `Header.tsx`:
  - Alert bell icon shows real unread count (from `useAlertStream` or `GET /ui/alerts` query)
  - Click bell → popover dropdown with last 10 alerts
  - Each alert: title, detail snippet, relative timestamp, blue dot if unread
  - "Mark all read" button → `POST /ui/alerts/mark_read`
  - "View all" link → `/alerts`
- Create `src/pages/alerts/AlertCenter.tsx`:
  - Full page alert list from `GET /ui/alerts` with `useInfiniteQuery`
  - Filter by alert type (dropdown or tabs)
  - Bulk selection + "Mark as read" action
  - Each alert: expandable card with full details
  - Search by title/details
- Create `src/pages/alerts/AlertPrefs.tsx`:
  - Grid of toggles: rows = event types, columns = channels (email, SMS, toast, push, webhook)
  - Webhook URL configuration field
  - Calls alert preference update endpoints on toggle

**Files created:**
```
src/
├── hooks/useAlertStream.ts
└── pages/alerts/
    ├── AlertCenter.tsx
    └── AlertPrefs.tsx
```

---

### Step 12 — Billing Pages
**Goal:** Full billing management with Stripe Elements, ledger, and subscriptions

**Deliverables:**
- Create `src/pages/billing/BillingOverview.tsx`:
  - Large balance display card (green for credit, red for owed)
  - Autopay toggle → `POST /ui/billing/autopay`
  - "Pay balance" button → calls `POST /ui/billing/pay-balance`
  - Billing config summary from `GET /ui/billing/config`
  - Quick links to other billing tabs
- Create `src/pages/billing/PaymentMethods.tsx`:
  - List of saved payment methods from `POST /ui/billing/payment-methods`
  - Each method: card brand icon (Visa/MC/Amex), masked number, expiry, "Default" badge
  - "Add card" button → dialog with Stripe Elements (`@stripe/react-stripe-js` `CardElement`)
    - Calls `POST /ui/billing/setup-intent/card` to create SetupIntent
    - Confirms with Stripe.js, then stores method
  - "Add PayPal" button → calls `POST /api/billing/payment-methods/paypal/setup-token`, redirects
  - Remove method: `ConfirmDialog` → remove endpoint
  - Set default method action
- Create `src/pages/billing/Ledger.tsx`:
  - `DataTable` with columns: Date, Description, Amount, Status
  - Date range filter (two date inputs)
  - Amount color-coded: green for credits, red for charges
  - "Export CSV" button
  - Pagination via cursor
- Create `src/pages/billing/Subscriptions.tsx`:
  - Active subscriptions from subscriptions endpoint
  - Each: plan name, price, billing cycle, next billing date, status badge
  - Actions: Cancel, Pause
  - Subscription history below

**Files created:**
```
src/pages/billing/
├── BillingOverview.tsx
├── PaymentMethods.tsx
├── Ledger.tsx
└── Subscriptions.tsx
```

---

### Step 13 — Shopping Cart & Catalog Pages
**Goal:** Browsable product catalog, cart management, and checkout

**Deliverables:**
- Create `src/pages/shop/Catalog.tsx`:
  - Left sidebar: category list from `GET /ui/catalog/categories`
  - Main area: product grid (responsive, 2-4 columns)
  - Each product card: image placeholder, name, price (formatted from cents), star rating average
  - Click card → navigate to product detail
  - Search/filter within category
- Create `src/pages/shop/ProductDetail.tsx`:
  - Product info: name, description, price, attributes
  - Image gallery (if available) or placeholder
  - Quantity selector + "Add to cart" button → `POST /ui/shoppingcart/carts/{id}/items`
  - Reviews section: list of reviews with star ratings, author, text
  - "Write a review" form (star selector + textarea) → `POST /ui/catalog/items/{id}/reviews`
- Create `src/pages/shop/Cart.tsx`:
  - Cart selector dropdown (if multiple carts)
  - Line items table: SKU, name, quantity (adjustable), unit price, line total, remove button
  - Cart total from `GET /ui/shoppingcart/carts/{id}/total`
  - "Start new cart" button, "Delete cart" (danger)
  - "Proceed to checkout" button
- Create `src/pages/shop/Checkout.tsx`:
  - Order summary (read-only cart items + total)
  - Payment method selection (from saved methods)
  - "Place order" button → `POST /ui/shoppingcart/carts/{id}/purchase`
  - Success/failure state with order confirmation

**Files created:**
```
src/pages/shop/
├── Catalog.tsx
├── ProductDetail.tsx
├── Cart.tsx
└── Checkout.tsx
```

---

### Step 14 — Calendar & Newsfeed Pages
**Goal:** Calendar with month/week/day views, and social newsfeed with posts/comments

**Deliverables:**
- Create `src/pages/calendar/CalendarView.tsx`:
  - View toggle: Month / Week / Day (shadcn `Tabs`)
  - Month view: 7-column grid, days with event dots/titles
  - Week view: 7-column time grid (hours on Y axis), events as colored blocks
  - Day view: single column time grid with event blocks
  - Navigation: previous/next arrows, "Today" button
  - Click empty slot → create event dialog
  - Click event → view/edit event dialog
- Create `src/pages/calendar/EventDialog.tsx`:
  - Form: title, description, start datetime, end datetime, all-day toggle
  - Calendar selector (which calendar this event belongs to)
  - Recurrence rule builder: frequency (daily/weekly/monthly), interval, end condition
  - Save → `POST /ui/calendars/{id}/events`
  - Edit → `PUT` equivalent, Delete with confirmation
- Create `src/pages/calendar/BookingLinks.tsx`:
  - List of booking links with copy-to-clipboard
  - "Create booking link" form: title, duration, calendar, availability window
- Create `src/pages/calendar/Availability.tsx`:
  - Working hours configuration per day of week
  - Visual availability grid
  - Team availability checker
- Create `src/pages/feed/NewsFeed.tsx`:
  - `CreatePost` composer at top: textarea + optional unlock price + "Post" button
  - Feed of posts from `GET /feed` with infinite scroll (`useInfiniteQuery`)
  - Each post: `PostCard` component
  - SSE connection for real-time new posts
- Create `src/pages/feed/PostCard.tsx`:
  - Author avatar + name + relative timestamp
  - Post body (pre-wrap text)
  - Locked posts: blurred content + "Unlock for $X" button
  - Action row: like (heart icon + count), comment (speech bubble + count), share, tip
  - Click comment → expand `CommentsThread` inline
- Create `src/pages/feed/CommentsThread.tsx`:
  - Nested comment list with author, text, timestamp
  - "Add comment" textarea + send button
  - "Load more comments" for pagination
- Follow/unfollow: button on post cards or user profiles

**Files created:**
```
src/pages/
├── calendar/
│   ├── CalendarView.tsx
│   ├── EventDialog.tsx
│   ├── BookingLinks.tsx
│   └── Availability.tsx
└── feed/
    ├── NewsFeed.tsx
    ├── PostCard.tsx
    ├── CreatePost.tsx
    └── CommentsThread.tsx
```

---

### Step 15 — Security Pages, Responsive Polish & Testing
**Goal:** Complete feature coverage, production-quality UI across all breakpoints, and test suite

**Deliverables — Security pages:**
- Create `src/pages/security/MfaDevices.tsx`:
  - Three sections: TOTP, SMS, Email devices
  - Each section: device list (label, enabled badge, last used) + "Add device" button
  - TOTP enrollment wizard: QR code display → 6-digit confirmation input
  - SMS enrollment: phone number input → verification code
  - Email enrollment: email input → verification code
  - Remove device with re-authentication (`ConfirmDialog`)
- Create `src/pages/security/Sessions.tsx`:
  - Active sessions list from `GET /ui/sessions`
  - Each: browser/OS info, IP address, last active timestamp, "current" badge for this session
  - "Revoke" button per session → `POST /ui/sessions/revoke`
  - "Revoke all other sessions" button → `POST /ui/sessions/revoke_others`
- Create `src/pages/security/TrustedDevices.tsx`:
  - Device list with trust status
  - Revoke trust per device
- Create `src/pages/security/ApiKeys.tsx`:
  - Key list: label, created date, last 8 characters, expiry date
  - "Create key" → dialog showing generated key (copy button, "shown once" warning)
  - Revoke key with confirmation
  - IP allowlist management per key: add/remove CIDR rules in sub-panel
- Create `src/pages/security/Recovery.tsx`:
  - View/regenerate recovery codes
  - Password recovery flow (start → code → new password)

**Deliverables — Responsive polish:**
- Test every page at 3 breakpoints: mobile (375px), tablet (768px), desktop (1280px)
- Messages: conversation list ↔ conversation view toggle on mobile
- Sidebar: drawer mode on mobile with `Sheet` component
- File manager: stack toolbar buttons, reduce table columns on mobile
- Calendar: default to day view on mobile
- DataTable: horizontal scroll wrapper on narrow screens
- All modals: full-screen on mobile (`Sheet` with `side="bottom"`)

**Deliverables — Accessibility:**
- Keyboard navigation: all interactive elements reachable via Tab
- Focus trapping in all modals/dialogs (Radix handles this)
- ARIA labels on icon-only buttons (sidebar collapse, theme toggle, alert bell)
- Skip-to-content link
- Sufficient color contrast (WCAG AA) in both themes
- Screen reader announcements for toast notifications

**Deliverables — Performance & testing:**
- Code splitting: `React.lazy()` + `Suspense` for every page route
- Image lazy loading for file thumbnails, avatars, catalog images
- TanStack Query cache tuning: appropriate `staleTime` per endpoint
- Error handling audit: network error toasts, 401 → redirect to login, 403 → permission denied state
- Write Playwright E2E tests for critical flows: login, send message, upload file, add to cart, create event
- Bundle analysis with `vite-plugin-visualizer` to verify tree shaking

**Files created:**
```
src/pages/security/
├── MfaDevices.tsx
├── Sessions.tsx
├── TrustedDevices.tsx
├── ApiKeys.tsx
└── Recovery.tsx
```

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
