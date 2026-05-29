# BCAST-007: Broadcast Sidebar Navigation + Routes

## 1. Overview & Motivation

### Problem Statement

The broadcast management backend is fully implemented (`app/routers/broadcast.py` with
profile CRUD, session lifecycle, playback URL minting, and audit log endpoints), and the
frontend Broadcaster Dashboard (BCAST-001) and Live Player (BCAST-002) page components are
planned at `frontend/src/pages/broadcaster/BroadcasterPage.tsx` and
`frontend/src/pages/broadcast/LivePlayer.tsx` respectively. However, there is currently
**no routing, no sidebar navigation entry, and no mobile navigation** wiring that connects
these pages to the application shell. Users cannot reach the broadcast system through
normal app navigation -- the only existing UI touchpoint is the admin-gated dev-tools page
at `/broadcast-devtools` which is unlinked from the sidebar.

This ticket bridges that gap by registering React Router routes, adding sidebar entries,
wiring mobile navigation, configuring the Vite proxy, and adding a feature flag to gate
visibility.

### User Stories

1. **As a broadcaster**, I want to see a "Broadcast" link in the sidebar so I can navigate
   to my session management dashboard without memorizing URLs.
2. **As a viewer**, I want to access a live stream page (`/live/:sessionId`) so I can watch
   a broadcast shared via link.
3. **As a mobile user**, I want to find "Broadcast" in the "More" sheet at the bottom of
   the screen so I can manage sessions from my phone.
4. **As an admin**, I want the sidebar entry to show a visual indicator when a broadcast
   session is currently live so I can monitor active streams at a glance.
5. **As a platform operator**, I want a feature flag to hide broadcast navigation when the
   feature is disabled in a given environment (e.g., tenants without streaming entitlements).
6. **As an unauthenticated user** visiting `/live/:sessionId`, I want to be redirected to
   login if the stream requires authentication.

### Navigation UX Requirements

- Sidebar entry should live in a new **"Media"** group (placed between "Productivity" and
  "Account") to accommodate future media features (VOD, recordings).
- The sidebar badge should show a pulsing green dot when at least one session owned by the
  user is in `live` status.
- Direct URL navigation to `/broadcast` or `/live/:sessionId` must work (deep-linking).
- Back/forward browser history must work correctly between broadcast and other pages.
- The `live/:sessionId` route is nested inside the AppShell (auth-gated); public/anonymous
  viewing is out of scope for this ticket (deferred to BCAST-010).

---

## 2. Current State Analysis

### 2.1 Existing Route Structure (`frontend/src/App.tsx`)

Routes are split into two groups:

1. **Public routes** (no AppShell wrapper): `/login`, `/register`, `/password-recovery`,
   `/magic-link-verify`, `/event/:calendarId/:eventId`, `/questionnaires/published/:publishedSlug/respond`,
   and the optional `/u/:identifier` profile route.
2. **Protected routes** (inside `<ProtectedRoute><AppShell /></ProtectedRoute>`): all
   authenticated pages (dashboard, messages, files, billing, etc.).

All protected-route pages are lazy-loaded via `React.lazy()` with a shared `<Suspense>`
wrapper providing a `<Loader2>` spinner fallback.

Pattern for adding a new protected route:
```typescript
const PageComponent = lazy(() => import("@/pages/<domain>/<PageComponent>"));
// inside the ProtectedRoute element:
<Route path="<path-segment>" element={<PageComponent />} />
```

Feature-flagged routes use conditional rendering:
```typescript
{showVncRemoteDesktop && <Route path="remote-desktop" element={<RemoteDesktopPage />} />}
```

### 2.2 Sidebar Groups (`frontend/src/components/layout/Sidebar.tsx`)

The sidebar is structured as an array of `NavGroup` objects with `title` and `items`:

| Group | Items |
|-------|-------|
| Main | Dashboard, Messages, Contacts, Helpdesk, Feed |
| Commerce | Shop, Cart, Billing, Orders, Subscriptions |
| Productivity | Files, Projects, Calendar, Signing |
| Account | Profile, Security, Alerts, Tickets, Ticket Spaces, Remote Desktop, Settings, Role Mgmt, Moderation Board, Payment Incidents |

Each item has `{ label, path, icon, badge? }`. Icons are imported from `lucide-react` and
rendered inline as `<IconName className="h-5 w-5" />`.

Role-based visibility is handled by filtering items in the render loop:
```typescript
const items = group.items.filter((item) => {
  if (item.path === "/root/roles") return showRootRoleManagement;
  if (item.path === "/remote-desktop") return isVncRemoteDesktopEnabled();
  if (item.path === "/admin/moderation") return showModerationBoard;
  if (item.path === "/admin/payment-incidents") return showPaymentIncidents;
  return true;
});
```

If all items in a group are filtered out, the entire group section is hidden (`if (items.length === 0) return null`).

Badge rendering: the Messages item has dynamic badge support via the `totalUnread` counter
from a React Query `["conversations"]` query. Other items use the static `item.badge` field.

### 2.3 MobileSidebar (`frontend/src/components/layout/AppShell.tsx`)

The `MobileSidebar` component (defined at the bottom of `AppShell.tsx`) uses a separate
`MOBILE_NAV_GROUPS` array with a slightly different format -- icons are referenced as
component constructors (e.g., `icon: MessageSquare`) rather than JSX elements, and rendered
as `<item.icon className="h-5 w-5 shrink-0" />`.

Currently has the same 4 groups (Main, Commerce, Productivity, Account) with a subset of
items (e.g., no Helpdesk, no Contacts, no Projects in the mobile sidebar).

### 2.4 MobileNav Bottom Tab Bar (`frontend/src/components/layout/MobileNav.tsx`)

Two-level navigation:

1. **PRIMARY_TABS** (always visible bottom bar): Home, Messages, Files, Shop
2. **MORE_LINKS** (shown in a bottom Sheet when "More" is tapped): Feed, Cart, Billing,
   Calendar, Signing, Profile, Security, Alerts, Tickets, Ticket Spaces, Remote Desktop,
   Settings, Role Mgmt, Moderation Board

Same filtering pattern for role-gated items. Icons referenced as constructors. Each MORE
link renders as a `Button variant="ghost"` in a 4-column grid.

### 2.5 Vite Proxy Configuration (`frontend/vite.config.ts`)

The dev server proxies these path prefixes to `http://localhost:8000`:
- Simple pass-through: `/ui`, `/api`, `/v1`, `/messaging`, `/posts`, `/social`, `/uploads`,
  `/sse`, `/notifications`, `/mock`, `/calendar/public`, `/internal`
- Bypass-pattern (serve `index.html` for HTML requests, proxy API calls): `/feed`,
  `/tickets`, `/ticket-spaces`

**Missing**: `/broadcast` is not proxied. The broadcast backend router is mounted at
`prefix="/broadcast"` (line 26 of `app/routers/broadcast.py`), so a new proxy entry is
required.

### 2.6 Available Lucide Icons for Broadcast

Relevant icons from `lucide-react` that are NOT already used in the sidebar:

| Icon | Visual | Best fit for |
|------|--------|--------------|
| `Radio` | Radio tower with signal waves | Live broadcast/streaming |
| `Video` | Video camera | Video content |
| `Tv` | Television screen | Viewing/playback |
| `Cast` | Chromecast-style icon | Casting/streaming |
| `Signal` | Signal strength bars | Live signal |
| `Antenna` | Broadcast antenna | Transmission |
| `Podcast` | Microphone with waves | Audio streaming |
| `CircleDot` | Target/record dot | Recording indicator |
| `RadioTower` | Radio tower (taller) | Broadcasting |

**Recommendation**: `Radio` (from lucide-react) -- matches the ticket description's
suggestion of "Radio/Video icon" and visually conveys live broadcasting without ambiguity.
It is not currently imported anywhere in the layout components.

### 2.7 Backend Endpoint Prefixes

The broadcast router uses prefix `/broadcast` (not `/ui/broadcast` or `/api/broadcast`).
All endpoints:
- `POST /broadcast/profiles`
- `POST /broadcast/sessions`
- `GET /broadcast/sessions/{id}`
- `POST /broadcast/sessions/{id}/start`
- `POST /broadcast/sessions/{id}/stop`
- `DELETE /broadcast/sessions/{id}`
- `POST /broadcast/sessions/{id}/playback-url`
- `GET /broadcast/admin/audit`
- `GET /broadcast/playback/verify`

The Vite proxy must handle `/broadcast` carefully because the frontend route `/broadcast`
would also match. The same bypass pattern used for `/feed` and `/tickets` is needed.

---

## 3. Technical Design

### 3.1 Route Hierarchy

```
/ (AppShell - ProtectedRoute)
├── broadcast                    → BroadcasterPage (dashboard)
├── live/:sessionId              → LivePlayer (viewer)
└── ... (existing routes)
```

Both routes are protected (inside `ProtectedRoute`). The `live/:sessionId` path uses a
different prefix than `broadcast` to clearly separate the "manage" vs "watch" concerns and
avoid conflicting with the `/broadcast` API proxy.

### 3.2 Lazy Loading

```typescript
// New lazy imports in App.tsx
const BroadcasterPage = lazy(() => import("@/pages/broadcaster/BroadcasterPage"));
const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"));
```

These follow the established pattern where each page is a default export from its module.
The code-split boundary ensures the HLS.js library (heavy dependency for LivePlayer) is
not loaded on non-broadcast pages.

### 3.3 Feature Flag

Add a new feature flag to `frontend/src/lib/featureFlags.ts`:

```typescript
export const broadcastNavigationEnabled = toBool(env.VITE_BROADCAST_NAVIGATION_ENABLED, true);
export const broadcastNavigationKillSwitch = toBool(env.VITE_BROADCAST_NAVIGATION_KILL_SWITCH, false);
export const isBroadcastNavigationEnabled = () =>
  broadcastNavigationEnabled && !broadcastNavigationKillSwitch;
```

Default is `true` in dev mode. Production deployments can set
`VITE_BROADCAST_NAVIGATION_ENABLED=0` to hide the feature entirely.

The route itself should still be registered (to support direct URL access for users who
have the URL), but the sidebar/mobile nav entries are gated by the flag. This prevents
404s for bookmarked URLs while allowing operators to hide the feature from discovery.

### 3.4 Icon Selection

**Primary icon**: `Radio` from `lucide-react`

- Used in: desktop Sidebar, MobileSidebar, MobileNav MORE_LINKS
- Consistent with the platform's monochrome icon style (all icons use `h-5 w-5` sizing)
- Distinct from all other sidebar icons (no collision)

### 3.5 Sidebar Badge -- Live Indicator

The sidebar entry should show a pulsing green dot (not a numeric badge) when the user has
at least one active `live` session. Implementation approach:

```typescript
// In Sidebar.tsx, alongside the existing conversations query:
const { data: broadcastData } = useQuery({
  queryKey: ["broadcast", "sessions", "live-count"],
  queryFn: () => api.get<{ items: { status: string }[] }>("/broadcast/sessions?status=live"),
  staleTime: 15_000,
  refetchInterval: 15_000,
  enabled: isBroadcastNavigationEnabled(),
});
const hasLiveBroadcast = (broadcastData?.items?.length ?? 0) > 0;
```

The badge renders as a small pulsing dot using Tailwind animation classes:
```html
<span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-green-500 animate-pulse" />
```

This mirrors the unread-count badge pattern but uses a dot instead of a number.

### 3.6 Role-Based Visibility

The broadcast sidebar entry should be visible to ALL authenticated users (not admin-only).
Any user can view live streams and manage their own sessions. Admin-only operations
(start/stop/delete) are enforced at the API layer by `_require_operator_role`.

The sidebar filter function needs one new entry:
```typescript
if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
```

### 3.7 Vite Proxy Configuration

The `/broadcast` path is shared between:
- Frontend SPA route: `/broadcast` (browser navigation, `Accept: text/html`)
- Backend API calls: `/broadcast/profiles`, `/broadcast/sessions/...` (XHR/fetch, `Accept: application/json`)

Use the bypass pattern (same as `/feed` and `/tickets`):

```typescript
"/broadcast": {
  target: "http://localhost:8000",
  bypass: (req) => {
    const accept = req.headers["accept"] ?? "";
    if (typeof accept === "string" && accept.includes("text/html")) {
      return "/index.html";
    }
    return null; // proxy to backend
  },
},
```

The `/live` route does NOT need a proxy entry because there is no backend endpoint at
`/live/*` -- all playback API calls go through `/broadcast/sessions/{id}/playback-url`.

### 3.8 Navigation Group Placement

Create a new **"Media"** group between "Productivity" and "Account":

```typescript
{
  title: "Media",
  items: [
    { label: "Broadcast", path: "/broadcast", icon: <Radio className="h-5 w-5" /> },
  ],
}
```

Rationale for a new group rather than adding to "Productivity":
1. Future tickets (VOD-008, CALL-004) will add more media entries (Videos, Recordings)
2. Broadcasting is conceptually distinct from document productivity tools
3. A dedicated group makes the media ecosystem discoverable

### 3.9 Active State Detection

The `isActive` function in `Sidebar.tsx` uses `location.pathname.startsWith(path)`:
- `/broadcast` matches both `/broadcast` itself and any sub-routes
- `/live` would only highlight when on a live player page

Since the sidebar entry points to `/broadcast`, the live player page (`/live/:sessionId`)
will NOT highlight the "Broadcast" sidebar item. This is acceptable because viewers may
arrive at the live player from an external link, not necessarily through the sidebar.
If desired, the `isActive` check could be extended:
```typescript
if (path === "/broadcast") return location.pathname.startsWith("/broadcast") || location.pathname.startsWith("/live");
```

This is an optional enhancement -- not required for the initial implementation.

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Change |
|------|--------|
| `frontend/src/App.tsx` | Add lazy imports + 2 route entries |
| `frontend/src/components/layout/Sidebar.tsx` | Import `Radio`; add "Media" group to `NAV_GROUPS`; add feature-flag filter; add live-badge query |
| `frontend/src/components/layout/AppShell.tsx` | Import `Radio`; add "Media" group to `MOBILE_NAV_GROUPS`; add feature-flag filter |
| `frontend/src/components/layout/MobileNav.tsx` | Import `Radio`; add "Broadcast" to `MORE_LINKS`; add feature-flag filter |
| `frontend/src/lib/featureFlags.ts` | Add `broadcastNavigationEnabled`, `broadcastNavigationKillSwitch`, `isBroadcastNavigationEnabled` |
| `frontend/vite.config.ts` | Add `/broadcast` proxy with bypass |
| `frontend/.env.local.example` | Add `VITE_BROADCAST_NAVIGATION_ENABLED=true` |

### 4.2 Files to Create (Stubs)

| File | Purpose |
|------|---------|
| `frontend/src/pages/broadcaster/BroadcasterPage.tsx` | Minimal page stub (to be filled by BCAST-001) |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Minimal page stub (to be filled by BCAST-002) |
| `frontend/e2e/broadcast-navigation.spec.ts` | E2E tests for navigation behavior |

The page stubs export a minimal component with a heading so routes resolve without error:

```typescript
// BroadcasterPage.tsx stub
export default function BroadcasterPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold">Broadcaster</h1>
      <p className="text-muted-foreground mt-2">Broadcast management coming soon.</p>
    </div>
  );
}
```

```typescript
// LivePlayer.tsx stub
import { useParams } from "react-router-dom";

export default function LivePlayer() {
  const { sessionId } = useParams<{ sessionId: string }>();
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold">Live Stream</h1>
      <p className="text-muted-foreground mt-2">Session: {sessionId}</p>
    </div>
  );
}
```

### 4.3 Step-by-Step Implementation

**Step 1: Feature flag (5 min)**

Add to `frontend/src/lib/featureFlags.ts`:
```typescript
export const broadcastNavigationEnabled = toBool(env.VITE_BROADCAST_NAVIGATION_ENABLED, true);
export const broadcastNavigationKillSwitch = toBool(env.VITE_BROADCAST_NAVIGATION_KILL_SWITCH, false);
export const isBroadcastNavigationEnabled = () =>
  broadcastNavigationEnabled && !broadcastNavigationKillSwitch;
```

**Step 2: Vite proxy (5 min)**

Add to `frontend/vite.config.ts` proxy section (after the `/ticket-spaces` entry):
```typescript
"/broadcast": {
  target: "http://localhost:8000",
  bypass: (req) => {
    const accept = req.headers["accept"] ?? "";
    if (typeof accept === "string" && accept.includes("text/html")) {
      return "/index.html";
    }
    return null;
  },
},
```

**Step 3: Page stubs (10 min)**

Create `frontend/src/pages/broadcaster/BroadcasterPage.tsx` and
`frontend/src/pages/broadcast/LivePlayer.tsx` with minimal content.

**Step 4: Route registration (10 min)**

In `frontend/src/App.tsx`:
1. Add lazy imports at the top (after existing lazy imports):
   ```typescript
   const BroadcasterPage = lazy(() => import("@/pages/broadcaster/BroadcasterPage"));
   const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"));
   ```
2. Add routes inside the `ProtectedRoute` element (before the catch-all `*`):
   ```typescript
   {isBroadcastNavigationEnabled() && <Route path="broadcast" element={<BroadcasterPage />} />}
   <Route path="live/:sessionId" element={<LivePlayer />} />
   ```
   Note: The `live/:sessionId` route is always registered (not feature-flag gated) because
   it may be accessed via shared links even when the sidebar entry is hidden.

3. Import the feature flag function:
   ```typescript
   import { ..., isBroadcastNavigationEnabled } from "@/lib/featureFlags";
   ```

**Step 5: Desktop sidebar (15 min)**

In `frontend/src/components/layout/Sidebar.tsx`:
1. Add `Radio` to the lucide-react import statement.
2. Import `isBroadcastNavigationEnabled` from `@/lib/featureFlags`.
3. Insert a new "Media" group between "Productivity" and "Account" in `NAV_GROUPS`:
   ```typescript
   {
     title: "Media",
     items: [
       { label: "Broadcast", path: "/broadcast", icon: <Radio className="h-5 w-5" /> },
     ],
   },
   ```
4. Add filter condition in the items filter function:
   ```typescript
   if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
   ```
5. (Optional) Add live-session badge query and render the pulsing dot for the Broadcast
   item when a live session exists.

**Step 6: Mobile sidebar (10 min)**

In `frontend/src/components/layout/AppShell.tsx`:
1. Add `Radio` to the lucide-react import.
2. Import `isBroadcastNavigationEnabled` from `@/lib/featureFlags`.
3. Insert "Media" group in `MOBILE_NAV_GROUPS` between Productivity and Account:
   ```typescript
   {
     title: "Media",
     items: [
       { label: "Broadcast", path: "/broadcast", icon: Radio },
     ],
   },
   ```
4. Add filter: `if (item.path === "/broadcast") return isBroadcastNavigationEnabled();`

**Step 7: Mobile bottom nav (10 min)**

In `frontend/src/components/layout/MobileNav.tsx`:
1. Add `Radio` to the lucide-react import.
2. Import `isBroadcastNavigationEnabled` from `@/lib/featureFlags`.
3. Add entry to `MORE_LINKS` (after "Signing", keeping media adjacent to productivity):
   ```typescript
   { label: "Broadcast", path: "/broadcast", icon: Radio },
   ```
4. Add filter: `if (item.path === "/broadcast") return isBroadcastNavigationEnabled();`

**Step 8: Environment file update (2 min)**

Add to `frontend/.env.local.example`:
```
VITE_BROADCAST_NAVIGATION_ENABLED=true
VITE_BROADCAST_NAVIGATION_KILL_SWITCH=false
```

### 4.4 Dependency Order

```
Step 1 (feature flag)
  └─► Step 2 (proxy) ─────────────────────────────────► Step 8 (env example)
  └─► Step 3 (stubs) ─► Step 4 (routes)
  └─► Step 5 (desktop sidebar)
  └─► Step 6 (mobile sidebar)
  └─► Step 7 (mobile bottom nav)
```

Steps 2, 3, 5, 6, 7, 8 can be done in parallel after Step 1. Step 4 depends on Step 3
(stubs must exist for the lazy imports to resolve).

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_navigation.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast007_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast007_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast007_resources` | List resources; verify pagination and filtering |
| `test_update_bcast007_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast007_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-nav.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for viewer operations; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource successfully | POST returns 200/201 with resource ID |
| 2 | API returns resource by ID | GET returns full resource with all expected fields |
| 3 | API lists resources with pagination | GET list returns array; supports cursor pagination |
| 4 | API updates resource fields | PATCH/PUT returns updated resource |
| 5 | API deletes resource | DELETE returns 200; subsequent GET returns 404 |
| 6 | UI page loads with expected heading | Navigate to page; heading visible |
| 7 | UI form creates new resource | Fill form; submit; resource appears in list |
| 8 | UI shows error for invalid input | Submit empty form; validation messages visible |
| 9 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 10 | Non-owner access returns 403 | Wrong user -> 403 |
| 11 | Non-existent resource returns 404 | GET invalid ID -> 404 |
| 12 | Duplicate creation returns 409 | Create same resource twice -> 409 or idempotent success |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 not found, 409 conflict/duplicate, 422 validation

**Edge cases**: Empty state (no resources), concurrent mutations, resource with max-length fields, Unicode content

### Test Data Requirements

Seed broadcast session in `beforeAll`. Create test resources via API with unique `Date.now()` suffixed names.

**Test users**: Root (ROOT, admin operations), Alice (USER, standard operations), Bob (USER, cross-user isolation)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe with unique resource names.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-001 | BroadcastPage component to route to | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Independent. Frontend-only changes to routing, sidebar, and mobile nav. No backend changes.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `frontend/src/components/layout/Sidebar.tsx` | 26, 60, 132, 217 | **ALREADY EXISTS** | Broadcast sidebar entry with Radio icon, gated by `isBroadcastNavigationEnabled()` |
| `frontend/src/App.tsx` | 56, 166 | **ALREADY EXISTS** | `/broadcast` route with feature flag gate |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | — | **ALREADY EXISTS** | Main broadcast page |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | — | **ALREADY EXISTS** | Live player component |
| `frontend/src/lib/featureFlags.ts` | — | EXISTS | `isBroadcastNavigationEnabled` feature flag |

### Key Discrepancies
- This ticket describes adding broadcast to sidebar/nav, but the broadcast sidebar entry, route, and feature flag gate ALREADY EXIST in the codebase
