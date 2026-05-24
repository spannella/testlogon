# VOD-009: Video Management Routes and Sidebar Navigation

**Ticket**: VOD-009
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Problem Statement

The video management backend (VOD-001 through VOD-006) exposes a full CRUD API for video
assets at `/ui/videos` and `/ui/videos/{videoId}`, and the frontend page components are
delivered by VOD-007 (`VideosPage.tsx` -- upload, library grid, status tracking) and VOD-008
(`VideoPlayer.tsx` -- HLS.js playback, DRM, metadata display). However, none of these pages
are wired into the application's routing tree or navigation chrome. Users cannot reach the
video management UI without manually typing a URL, and even that would result in a 404 because
no React Router `<Route>` definition exists for the `/videos` or `/videos/:videoId` paths.

This ticket closes the gap by:

1. Registering React Router routes for the video listing and video player pages inside the
   authenticated `AppShell` layout.
2. Adding a "Videos" entry to the desktop sidebar, mobile sidebar drawer, and mobile bottom
   nav "More" sheet so users can discover and navigate to their video library from any screen.
3. Ensuring the Vite dev proxy forwards `/ui/videos` API calls to the backend (already
   covered by the existing `/ui` proxy rule, but the SPA route `/videos` must not collide
   with any backend path).
4. Confirming that unauthenticated users are redirected to `/login` when accessing video
   routes directly.

### User Stories

1. **As a creator**, I want to see a "Videos" link in the sidebar so I can navigate to my
   video library without remembering the URL.
2. **As a creator on mobile**, I want to find "Videos" in the bottom nav "More" menu and in
   the hamburger drawer so the feature is discoverable on small screens.
3. **As a creator**, I want to click a video thumbnail in my library to navigate to
   `/videos/:videoId` and see the player page, with a breadcrumb or back link to `/videos`.
4. **As a visitor**, I want unauthenticated access to `/videos` to redirect me to `/login`
   so that video content is protected behind authentication.
5. **As a power user**, I want to type `/videos` or `/videos/abc123` directly into my
   browser address bar and land on the correct page (deep-link support).

### Navigation UX Goals

- **Discoverability**: The sidebar entry should use a recognizable icon (`Film` from
  lucide-react) and sit inside a new "Media" nav group alongside the existing Broadcaster
  entry (if present) or as the founding member of a future Media group.
- **Consistency**: Follow the same lazy-loading, `ProtectedRoute` wrapping, sidebar group
  structure, and mobile nav patterns used by every other feature page.
- **Minimal scope**: This ticket does NOT add new UI components, API endpoints, or business
  logic. It purely wires existing (or in-progress) page components into the navigation
  skeleton. The `VideosPage` and `VideoPlayer` components are delivered by VOD-007 and
  VOD-008 respectively.

---

## 2. Current State Analysis

### 2.1 Route Definitions (`frontend/src/App.tsx`)

Routes are defined in a single `<Routes>` block inside `App.tsx`. The structure is:

```
<Routes>
  {/* Public routes (no shell) */}
  <Route path="/login" ... />
  <Route path="/register" ... />
  ...

  {/* Protected routes inside AppShell layout */}
  <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
    <Route index element={<Dashboard />} />
    <Route path="messages" element={<MessagesPage />} />
    <Route path="files" element={<FilesPage />} />
    ...
    <Route path="*" element={<ErrorPage status={404} />} />
  </Route>

  {/* Catch-all 404 */}
  <Route path="*" element={<ErrorPage status={404} />} />
</Routes>
```

Key patterns:
- **Lazy loading**: Every page is imported via `const XPage = lazy(() => import("@/pages/x/XPage"))` at the top of the file.
- **Auth guard**: All protected routes are children of `<ProtectedRoute><AppShell /></ProtectedRoute>`. `ProtectedRoute` (`frontend/src/components/ProtectedRoute.tsx`) checks `useAuthStore((s) => s.isAuthenticated)` and redirects to `/login` with the current location stored in `state.from`.
- **Nested routes**: Features with sub-pages use multiple `<Route>` entries (e.g., `projects` and `projects/:projectId`, `tickets` and `tickets/spaces` and `tickets/spaces/:spaceId`).
- **Feature flags**: Some routes are conditionally rendered (e.g., `showVncRemoteDesktop && <Route path="remote-desktop" ...>`).

There are currently **47 lazy imports** and **30 protected route entries** inside the `AppShell` layout. The video pages will add 2 lazy imports and 2 route entries.

### 2.2 Desktop Sidebar (`frontend/src/components/layout/Sidebar.tsx`)

The sidebar is organized into four `NavGroup` sections defined in the `NAV_GROUPS` array:

| Group | Items |
|-------|-------|
| Main | Dashboard, Messages, Contacts, Helpdesk, Feed |
| Commerce | Shop, Cart, Billing, Orders, Subscriptions |
| Productivity | Files, Projects, Calendar, Signing |
| Account | Profile, Security, Alerts, Tickets, Ticket Spaces, Remote Desktop, Settings, Role Management, Moderation Board, Payment Incidents |

Each item has `{ label, path, icon }` where `icon` is a JSX element (`<IconName className="h-5 w-5" />`). The sidebar supports:
- **Collapsed mode**: Shows only icons with tooltips.
- **Active highlighting**: `isActive(path)` uses `location.pathname.startsWith(path)` (with special-case for `/` requiring exact match).
- **Permission gating**: Items are filtered via `group.items.filter(...)` checking `showRootRoleManagement`, `isVncRemoteDesktopEnabled()`, `showModerationBoard`, `showPaymentIncidents`.
- **Unread badge**: The Messages item shows an unread count badge from React Query.

There is no "Media" group. The ticket specifies placing "Videos" with a `Film` icon. The logical home is a new "Media" group positioned between "Main" and "Commerce" (or between "Productivity" and "Account"). Alternatively, it could be appended to "Productivity". The ticket description says "in Media group", so a new group will be created.

### 2.3 Mobile Sidebar Drawer (`frontend/src/components/layout/AppShell.tsx`)

The `MobileSidebar` component is defined at the bottom of `AppShell.tsx`. It has its own `MOBILE_NAV_GROUPS` array with the same group structure but uses component references for icons (e.g., `icon: FolderOpen`) instead of JSX elements. It has 4 groups (Main, Commerce, Productivity, Account) mirroring the desktop sidebar but with fewer items (no Contacts, Helpdesk, Payment Incidents, Remote Desktop). The filtering logic for admin-gated items is the same pattern.

### 2.4 Mobile Bottom Nav (`frontend/src/components/layout/MobileNav.tsx`)

The mobile bottom tab bar has two tiers:
- **PRIMARY_TABS** (always visible): Home, Messages, Files, Shop -- plus a "More" button.
- **MORE_LINKS** (shown in a bottom Sheet): Feed, Cart, Billing, Calendar, Signing, Profile, Security, Alerts, Tickets, Ticket Spaces, Remote Desktop, Settings, Role Mgmt, Moderation Board.

The "More" sheet renders as a 4-column grid of icon buttons. Items are filtered by the same permission checks. The "Videos" entry belongs in `MORE_LINKS`.

### 2.5 Vite Dev Proxy (`frontend/vite.config.ts`)

The Vite dev server proxies certain path prefixes to `http://localhost:8000`. Relevant existing rules:

| Pattern | Behavior |
|---------|----------|
| `/ui` | Proxy to backend (covers `/ui/videos/*`) |
| `/api` | Proxy to backend |
| `/feed` | Bypass function: HTML requests serve SPA `index.html`; API calls proxy |
| `/tickets` | Bypass function: same SPA/API split |
| `/ticket-spaces` | Bypass function: same SPA/API split |

The video API endpoints live under `/ui/videos/*`, which is already covered by the `/ui` proxy rule. The SPA route `/videos` does NOT collide with any backend path prefix (the backend uses `/ui/videos`, not `/videos`), so no bypass rule is needed. Vite's default behavior for unmatched paths is to serve `index.html` (the SPA entry point), which is correct for client-side routing.

### 2.6 Existing Video Page Components (from VOD-007 and VOD-008)

Per the ticket dependency chain:
- **VOD-007** produces `frontend/src/pages/videos/VideosPage.tsx` -- the video library with upload, progress tracking, and grid view.
- **VOD-008** produces `frontend/src/pages/videos/VideoPlayer.tsx` -- the HLS.js player with DRM support and metadata display.

Neither component exists yet (they are in-progress deliverables from prior tickets). This specification defines the routing and navigation wiring that will connect them once they land.

---

## 3. Technical Design

### 3.1 Route Hierarchy

Two new routes will be added inside the `ProtectedRoute > AppShell` layout group:

```
/videos          -> VideosPage      (video library + upload)
/videos/:videoId -> VideoPlayer     (single video playback)
```

Both routes are:
- **Authenticated**: Wrapped by `ProtectedRoute`, which redirects to `/login` if not authenticated.
- **Inside AppShell**: The sidebar, header, mobile nav, impersonation banner, and offline banner are all rendered around the page content via `<Outlet />`.
- **Lazy-loaded**: Code-split via `React.lazy()` to avoid increasing the initial bundle.
- **Ungated by feature flag**: No feature flag gates video routes. Unlike VNC Remote Desktop (gated by `isVncRemoteDesktopEnabled()`), video management is a core feature available to all authenticated users. If a feature flag is desired later, the pattern is established: wrap the `<Route>` in a conditional (`{showVideos && <Route ...>}`), add a filter in the sidebar item list, and add a filter in `MobileNav`.

### 3.2 Lazy Loading

Add two lazy imports at the top of `App.tsx`, following the existing alphabetical grouping:

```typescript
const VideosPage = lazy(() => import("@/pages/videos/VideosPage"));
const VideoPlayer = lazy(() => import("@/pages/videos/VideoPlayer"));
```

These imports are deferred until the user first navigates to `/videos` or `/videos/:videoId`. The global `<Suspense fallback={<PageSpinner />}>` wrapper in `App.tsx` handles the loading spinner during chunk fetch.

### 3.3 Sidebar Placement and Icon Choice

The ticket specifies: *"Sidebar: 'Videos' item with Film icon in Media group"*.

**New "Media" nav group**: A new group titled "Media" will be inserted into `NAV_GROUPS` between the "Main" and "Commerce" groups. This group starts with a single item ("Videos") and provides a natural home for future media-related entries (Broadcaster from BCAST-001, Podcasts, Live Streams, etc.).

```typescript
{
  title: "Media",
  items: [
    { label: "Videos", path: "/videos", icon: <Film className="h-5 w-5" /> },
  ],
},
```

**Icon**: `Film` from `lucide-react`. This is a film-strip icon that clearly communicates video/media content. It is already available in the project's `lucide-react` dependency (confirmed via `node_modules/lucide-react/dist/esm/icons/film.js`). Alternative candidates considered:
- `Video` -- a video camera icon; good but less distinct from the existing `MonitorSmartphone` (Remote Desktop).
- `Play` / `CirclePlay` -- ambiguous (could mean audio, live stream, or general media).
- `ListVideo` -- too specific (implies a playlist rather than a library).
- `Film` -- winner: immediately recognizable, distinct from all existing sidebar icons.

**Active state behavior**: The existing `isActive(path)` function uses `location.pathname.startsWith(path)`. For `/videos`, this means both `/videos` (library) and `/videos/abc123` (player) will highlight the "Videos" sidebar entry, which is the desired behavior (same as `/tickets` highlighting for `/tickets/spaces/:spaceId`).

### 3.4 Mobile Sidebar Drawer Update

The `MOBILE_NAV_GROUPS` array in `AppShell.tsx` will get a new "Media" group matching the desktop sidebar. The mobile sidebar uses component references for icons (not JSX), so the entry is:

```typescript
{
  title: "Media",
  items: [
    { label: "Videos", path: "/videos", icon: Film },
  ],
},
```

This group will be inserted between "Main" and "Commerce" to match the desktop sidebar ordering.

### 3.5 Mobile Bottom Nav Update

Add "Videos" to the `MORE_LINKS` array in `MobileNav.tsx`:

```typescript
{ label: "Videos", path: "/videos", icon: Film },
```

Position: Insert near the top of `MORE_LINKS`, after "Feed" and before "Cart". This groups content-consumption features (Feed, Videos) together, separated from transactional features (Cart, Billing). The "More" sheet renders items in a 4-column grid, so ordering matters for scannability.

### 3.6 Breadcrumb / Back Navigation

The `VideoPlayer` page (`/videos/:videoId`) should provide a way to navigate back to the video library. This is the responsibility of VOD-008 (the player page component), not this routing ticket. However, the route structure enables standard patterns:

- **React Router `useNavigate(-1)`**: Browser back button or an explicit "Back" button using `navigate(-1)`.
- **Explicit link**: `<Link to="/videos">Back to Videos</Link>` in the player page header.
- **Sidebar highlight**: Both `/videos` and `/videos/:videoId` highlight the same "Videos" sidebar entry, providing persistent navigation context.

No breadcrumb component is needed at the routing level. The `PageHeader` component (`frontend/src/components/shared/PageHeader.tsx`) used by most pages supports a `title` and optional `description`/`actions` but does not have built-in breadcrumb support. If breadcrumbs are desired, the player page can implement them inline (as `FilesPage.tsx` does with its custom breadcrumb bar at line 937).

### 3.7 Permission Gating

Video routes are **not gated** by role or feature flag in this initial implementation. All authenticated users can access `/videos` and `/videos/:videoId`. Rationale:

- The video library is a user-scoped view (users see only their own videos via the backend's `GET /ui/videos` endpoint, which filters by `user_sub`).
- No admin-only operations are exposed on the video listing page.
- The player page respects playback entitlements (via the backend's entitlement token system from VOD-006), so access control is handled at the API layer, not the route layer.

If a feature flag is needed later (e.g., for gradual rollout), add:
1. A `VITE_VIDEO_MANAGEMENT_ENABLED` env var and `isVideoManagementEnabled()` flag in `featureFlags.ts`.
2. A conditional wrapper around the `<Route>` elements in `App.tsx`.
3. Filter entries in `Sidebar.tsx`, `AppShell.tsx`, and `MobileNav.tsx` (same pattern as `isVncRemoteDesktopEnabled()`).

### 3.8 Deep Linking and Direct URL Access

When a user navigates directly to `http://localhost:3000/videos` or `http://localhost:3000/videos/abc123`:

1. **Vite dev server**: The path `/videos` does not match any proxy rule (`/ui`, `/api`, `/feed`, `/tickets`, etc.), so Vite serves `index.html` (the SPA entry point). This is correct behavior.
2. **React Router**: The SPA boots, `ProtectedRoute` checks auth, and if authenticated, renders the matching `<Route>` inside `AppShell`.
3. **Production (nginx/CloudFront)**: The standard SPA catch-all rule (`try_files $uri /index.html`) handles unmatched paths. No special nginx rule is needed for `/videos`.

No Vite proxy bypass rule is needed because the backend API path (`/ui/videos`) and the SPA route path (`/videos`) do not collide. This contrasts with `/feed` and `/tickets`, where the SPA route and backend API share the same path prefix, requiring a bypass function to distinguish HTML page requests from XHR API calls.

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Change | Lines Affected |
|------|--------|---------------|
| `frontend/src/App.tsx` | Add 2 lazy imports + 2 `<Route>` elements | ~4 new lines |
| `frontend/src/components/layout/Sidebar.tsx` | Import `Film`, add "Media" group to `NAV_GROUPS` | ~8 new lines |
| `frontend/src/components/layout/AppShell.tsx` | Import `Film`, add "Media" group to `MOBILE_NAV_GROUPS` | ~8 new lines |
| `frontend/src/components/layout/MobileNav.tsx` | Import `Film`, add entry to `MORE_LINKS` | ~2 new lines |

### 4.2 Files to Create (delivered by prior tickets, not this one)

| File | Ticket | Status |
|------|--------|--------|
| `frontend/src/pages/videos/VideosPage.tsx` | VOD-007 | Pending |
| `frontend/src/pages/videos/VideoPlayer.tsx` | VOD-008 | Pending |
| `frontend/src/api/endpoints/videos.ts` | VOD-007 | Pending |

This ticket does NOT create these files. It wires them into routing and navigation. If VOD-007/VOD-008 have not yet landed, the lazy imports will cause a chunk-load error when navigating to `/videos`. To unblock development, a placeholder can be committed:

```typescript
// frontend/src/pages/videos/VideosPage.tsx (placeholder)
export default function VideosPage() {
  return <div className="p-6"><h1 className="text-2xl font-semibold">Videos</h1><p className="text-muted-foreground">Coming soon.</p></div>;
}
```

### 4.3 Step-by-Step Implementation

**Step 1: Add lazy imports to `App.tsx`** (line ~44, after `SigningPage`)

```typescript
const VideosPage = lazy(() => import("@/pages/videos/VideosPage"));
const VideoPlayer = lazy(() => import("@/pages/videos/VideoPlayer"));
```

**Step 2: Add route definitions to `App.tsx`** (inside the `ProtectedRoute > AppShell` block, after the `signing` route at line 80)

```typescript
<Route path="videos" element={<VideosPage />} />
<Route path="videos/:videoId" element={<VideoPlayer />} />
```

Placement rationale: Group video routes near other content-management routes (`files`, `signing`). The `videos/:videoId` route must come after `videos` but React Router v6 handles specificity correctly (`:videoId` is a param segment, so `videos` alone matches the index and `videos/abc` matches the param route).

**Step 3: Add `Film` import to `Sidebar.tsx`** (line ~2, in the lucide-react import block)

Add `Film` to the existing multi-line import from `lucide-react`.

**Step 4: Add "Media" group to `NAV_GROUPS` in `Sidebar.tsx`** (after the "Main" group, before "Commerce")

```typescript
{
  title: "Media",
  items: [
    { label: "Videos", path: "/videos", icon: <Film className="h-5 w-5" /> },
  ],
},
```

**Step 5: Add `Film` import to `AppShell.tsx`** (line ~84, in the lucide-react import block)

Add `Film` to the existing multi-line import from `lucide-react`.

**Step 6: Add "Media" group to `MOBILE_NAV_GROUPS` in `AppShell.tsx`** (after "Main", before "Commerce")

```typescript
{
  title: "Media",
  items: [
    { label: "Videos", path: "/videos", icon: Film },
  ],
},
```

**Step 7: Add `Film` import to `MobileNav.tsx`** (line ~7, in the lucide-react import block)

Add `Film` to the existing multi-line import from `lucide-react`.

**Step 8: Add "Videos" to `MORE_LINKS` in `MobileNav.tsx`** (after the "Feed" entry at line 46)

```typescript
{ label: "Videos", path: "/videos", icon: Film },
```

### 4.4 Dependency Ordering

```
VOD-001 (metadata model)
  -> VOD-002 (upload endpoint)
    -> VOD-003 (transcode worker)
      -> VOD-004 (FFmpeg executor)
        -> VOD-005 (S3 upload + manifest)
  -> VOD-006 (listing/detail API)
    -> VOD-007 (VideosPage.tsx)     ─┐
    -> VOD-008 (VideoPlayer.tsx)     ├─> VOD-009 (routes + nav) [this ticket]
                                     ─┘
```

VOD-009 can be implemented in parallel with VOD-007 and VOD-008 by using placeholder page components. The placeholder approach allows:
- Navigation and routing to be tested immediately.
- Sidebar and mobile nav entries to be validated visually.
- E2E route guard tests to pass without real page content.

When VOD-007 and VOD-008 land, the placeholder files are replaced by the real implementations. No routing changes are needed at that point.

### 4.5 No Vite Proxy Changes Required

The existing `/ui` proxy rule in `vite.config.ts` already forwards all `/ui/*` requests (including `/ui/videos/*`) to the backend. The SPA route `/videos` does not collide with any backend prefix. No changes to `vite.config.ts` are needed.

Verification:
- `GET /videos` (browser navigation, `Accept: text/html`) -> Vite serves `index.html` -> SPA handles route.
- `GET /ui/videos` (XHR, `Accept: application/json`) -> Vite proxies to `http://localhost:8000/ui/videos` -> backend responds.
- `GET /ui/videos/abc123` (XHR) -> Vite proxies to backend.

---

## 5. Testing Strategy

### 5.1 E2E Test File: `frontend/e2e/video-routes-nav.spec.ts`

A dedicated E2E spec file validates routing, navigation, and auth guards. This file can run
without the full video pipeline (VOD-001 through VOD-008) because it tests navigation chrome
and route resolution, not video upload or playback.

### 5.2 Test Setup

```typescript
import { test, expect, type Page, type Browser } from "@playwright/test";

// Re-use session setup from e2e_session_setup.py / e2e_admin_session_setup.py
const sessions = JSON.parse(
  require("fs").readFileSync("../.e2e_sessions.json", "utf-8"),
);

type Identity = "alice" | "bob";

async function injectAuth(page: Page, identity: Identity) {
  const s = sessions[identity];
  await page.context().addCookies([
    { name: "ui_session", value: s.session_id, domain: "localhost", path: "/" },
    { name: "ui_csrf", value: s.csrf_token, domain: "localhost", path: "/" },
    { name: "ui_access_token", value: s.access_token, domain: "localhost", path: "/" },
  ]);
}
```

### 5.3 Test Sections

**Section 90: Route Resolution (5 tests)**

These tests verify that React Router resolves video paths correctly and renders the expected
page components inside the authenticated layout.

| # | Test | What it verifies |
|---|------|-----------------|
| 90.1 | `/videos` renders VideosPage inside AppShell | Route registered, lazy chunk loads, page renders within sidebar layout |
| 90.2 | `/videos/test-video-123` renders VideoPlayer inside AppShell | Parameterized route resolves, `:videoId` param is available to the component |
| 90.3 | `/videos` shows header and sidebar | AppShell layout wrapper is active (header visible, sidebar visible on desktop) |
| 90.4 | Navigating from `/videos` to `/videos/:id` preserves AppShell | No full page reload; layout remains stable during client-side navigation |
| 90.5 | Unknown nested path `/videos/foo/bar/baz` falls through to 404 | The catch-all `<Route path="*">` inside AppShell renders ErrorPage |

```typescript
test("90.1 /videos renders VideosPage inside AppShell", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  // VideosPage should render (check for heading or placeholder text)
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
  // AppShell sidebar should be present (desktop)
  await expect(page.locator("aside")).toBeVisible();
});

test("90.2 /videos/:videoId renders VideoPlayer", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos/test-video-123");
  // VideoPlayer should render (check for player container or heading)
  await expect(page.locator("[data-testid='video-player']")
    .or(page.getByRole("heading", { name: /video/i }))).toBeVisible();
});
```

**Section 91: Auth Guard (3 tests)**

These tests verify that unauthenticated access to video routes redirects to `/login`.

| # | Test | What it verifies |
|---|------|-----------------|
| 91.1 | Unauthenticated `/videos` redirects to `/login` | `ProtectedRoute` fires, `state.from` preserves original URL |
| 91.2 | Unauthenticated `/videos/abc` redirects to `/login` | Same guard for parameterized route |
| 91.3 | After login, redirect returns to `/videos` | `state.from` is used by the login page to redirect back |

```typescript
test("91.1 unauthenticated /videos redirects to /login", async ({ page }) => {
  // Do NOT inject auth cookies
  await page.goto("/videos");
  await expect(page).toHaveURL(/\/login/);
});

test("91.2 unauthenticated /videos/abc redirects to /login", async ({ page }) => {
  await page.goto("/videos/abc");
  await expect(page).toHaveURL(/\/login/);
});
```

**Section 92: Desktop Sidebar Navigation (5 tests)**

These tests verify the sidebar "Videos" entry renders correctly, is clickable, and highlights
on the active route.

| # | Test | What it verifies |
|---|------|-----------------|
| 92.1 | Sidebar shows "Media" group with "Videos" entry | New nav group renders with correct label |
| 92.2 | "Videos" sidebar link navigates to `/videos` | Click triggers client-side navigation |
| 92.3 | "Videos" entry is highlighted when on `/videos` | Active state CSS classes applied |
| 92.4 | "Videos" entry is highlighted when on `/videos/:videoId` | `startsWith("/videos")` matches sub-routes |
| 92.5 | Collapsed sidebar shows Film icon with tooltip "Videos" | Tooltip renders on hover when sidebar is collapsed |

```typescript
test("92.1 sidebar shows Media group with Videos entry", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/");
  // Check for the Media group label
  await expect(page.locator("aside").getByText("MEDIA", { exact: false })).toBeVisible();
  // Check for the Videos nav link
  await expect(page.locator("aside").getByText("Videos")).toBeVisible();
});

test("92.2 Videos sidebar link navigates to /videos", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/");
  await page.locator("aside").getByText("Videos").click();
  await expect(page).toHaveURL("/videos");
});

test("92.3 Videos entry highlighted on /videos", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  const videosLink = page.locator("aside a[href='/videos']");
  await expect(videosLink).toHaveClass(/text-primary/);
});

test("92.4 Videos entry highlighted on /videos/:videoId", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos/some-video-id");
  const videosLink = page.locator("aside a[href='/videos']");
  await expect(videosLink).toHaveClass(/text-primary/);
});
```

**Section 93: Mobile Sidebar Drawer Navigation (3 tests)**

These tests verify the mobile sidebar drawer (hamburger menu) contains the "Videos" entry.

| # | Test | What it verifies |
|---|------|-----------------|
| 93.1 | Mobile drawer shows "Media" group with "Videos" entry | Drawer nav group renders on small viewport |
| 93.2 | Clicking "Videos" in drawer navigates to `/videos` | Navigation works and drawer closes |
| 93.3 | Drawer closes after navigation | `onNavigate` callback fires, Sheet closes |

```typescript
test("93.1 mobile drawer shows Videos entry", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE
  await page.goto("/");
  // Open hamburger menu
  await page.getByRole("button", { name: /menu/i }).click();
  // Verify Videos entry in drawer
  await expect(page.locator("[role='dialog']").getByText("Videos")).toBeVisible();
});

test("93.2 clicking Videos in drawer navigates to /videos", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto("/");
  await page.getByRole("button", { name: /menu/i }).click();
  await page.locator("[role='dialog']").getByText("Videos").click();
  await expect(page).toHaveURL("/videos");
});
```

**Section 94: Mobile Bottom Nav "More" Sheet (3 tests)**

These tests verify the "Videos" entry appears in the mobile bottom nav "More" sheet.

| # | Test | What it verifies |
|---|------|-----------------|
| 94.1 | "More" sheet includes "Videos" button | Entry renders in the grid |
| 94.2 | Clicking "Videos" in More sheet navigates to `/videos` | Navigation works and sheet closes |
| 94.3 | "Videos" button shows Film icon | Icon renders correctly |

```typescript
test("94.1 More sheet includes Videos button", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto("/");
  // Tap "More" in bottom nav
  await page.locator("nav.fixed").getByText("More").click();
  // Verify Videos entry in the sheet
  await expect(page.getByRole("button", { name: /videos/i })).toBeVisible();
});

test("94.2 clicking Videos in More sheet navigates", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto("/");
  await page.locator("nav.fixed").getByText("More").click();
  await page.getByRole("button", { name: /videos/i }).click();
  await expect(page).toHaveURL("/videos");
});
```

### 5.4 Test Count Summary

| Section | Description | Tests |
|---------|-------------|-------|
| 90 | Route resolution | 5 |
| 91 | Auth guard | 3 |
| 92 | Desktop sidebar navigation | 5 |
| 93 | Mobile sidebar drawer | 3 |
| 94 | Mobile bottom nav "More" sheet | 3 |
| **Total** | | **19** |

### 5.5 Flakiness Mitigations

1. **Lazy chunk loading**: The first navigation to `/videos` triggers a dynamic import. In CI, this may take a few hundred milliseconds. Tests use `toBeVisible()` which auto-retries with Playwright's default timeout (30s). No explicit `waitForLoadState` is needed.

2. **Viewport size for mobile tests**: Mobile tests set `{ width: 375, height: 667 }` (iPhone SE) to trigger the responsive breakpoint (`md:hidden` / `hidden md:flex`). The sidebar is hidden below `md` (768px) and the bottom nav is shown.

3. **Sheet animation**: The "More" bottom sheet and hamburger drawer use Radix `Sheet` with CSS transitions. After clicking to open, `toBeVisible()` waits for the element to be in the DOM and visible, which accounts for animation. No explicit animation wait is needed.

4. **Sidebar collapsed state**: Test 92.5 (collapsed sidebar tooltip) requires the sidebar to be in collapsed state. Use the collapse toggle button: `page.getByRole("button", { name: /collapse/i }).click()` before asserting the tooltip.

5. **No backend dependency**: These tests do not call any video API endpoints. They only test navigation, routing, and UI chrome. They can run with placeholder page components and do not require the video pipeline or DynamoDB tables.

### 5.6 Manual Verification Checklist

Beyond automated E2E tests, the following should be manually verified during code review:

- [ ] Desktop sidebar: "Media" group appears between "Main" and "Commerce"
- [ ] Desktop sidebar: "Videos" entry uses the `Film` icon
- [ ] Desktop sidebar: Clicking "Videos" navigates without full page reload
- [ ] Desktop sidebar: Active highlight appears on `/videos` AND `/videos/:id`
- [ ] Desktop sidebar (collapsed): Film icon visible, tooltip shows "Videos" on hover
- [ ] Mobile hamburger drawer: "Media" group with "Videos" entry visible
- [ ] Mobile drawer: Clicking "Videos" navigates and closes the drawer
- [ ] Mobile bottom nav: "More" sheet includes "Videos" in the grid
- [ ] Mobile bottom nav: Clicking "Videos" navigates and closes the sheet
- [ ] Direct URL `/videos` with auth: renders page inside AppShell
- [ ] Direct URL `/videos` without auth: redirects to `/login`
- [ ] Direct URL `/videos/abc123` with auth: renders player page inside AppShell
- [ ] Browser back button from `/videos/abc123` returns to `/videos`
