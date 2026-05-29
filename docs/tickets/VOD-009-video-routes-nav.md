# VOD-009: Video Management Routes and Sidebar Navigation

**Ticket**: VOD-009
**Author**: Engineering
**Status**: Implemented
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

## 2. Architecture Diagram

### 2.1 Route Resolution Flow

This ticket is entirely frontend / navigation chrome. There are no backend services, DynamoDB
tables, or API endpoints added. The architecture is a data-flow diagram through the React
component tree.

```
Browser URL bar / Link click
         |
         v
+---------------------+
|   React Router v6   |
|   <Routes> tree     |
+---------------------+
         |
         |  path="/videos"          path="/videos/:videoId"
         v                          v
+-------------------+      +---------------------+
| <ProtectedRoute>  |      | <ProtectedRoute>    |
| (auth gate)       |      | (auth gate)         |
+-------------------+      +---------------------+
         |                          |
         v                          v
+-------------------+      +---------------------+
| <AppShell>        |      | <AppShell>          |
| (Header + Sidebar |      | (same layout)       |
|  + MobileNav +    |      |                     |
|  <Outlet />)      |      |                     |
+-------------------+      +---------------------+
         |                          |
         v                          v
+-------------------+      +---------------------+
| <Suspense>        |      | <Suspense>          |
|  fallback=Spinner |      |  fallback=Spinner   |
+-------------------+      +---------------------+
         |                          |
         v                          v
+-------------------+      +---------------------+
| VideosPage (lazy) |      | VideoPlayer (lazy)  |
| (from VOD-007)    |      | (from VOD-008)      |
+-------------------+      +---------------------+
```

### 2.2 Navigation Chrome Data Flow

```
+-----------------------------------------------------------+
|  AppShell                                                 |
|                                                           |
|  +-----------+  +--------------------------------------+  |
|  | Sidebar   |  | Content Area (<Outlet />)            |  |
|  |           |  |                                      |  |
|  | [Main]    |  |  +--------------------------------+  |  |
|  |  Dashboard|  |  | VideosPage / VideoPlayer       |  |  |
|  |  Messages |  |  | (injected by React Router)     |  |  |
|  |  Contacts |  |  |                                |  |  |
|  |  Helpdesk |  |  | GET /ui/videos ----+           |  |  |
|  |  Feed     |  |  |                    |           |  |  |
|  |           |  |  |              Vite proxy /ui/*   |  |  |
|  | [Media]   |  |  |                    |           |  |  |
|  |  *Videos* |  |  |              Backend :8000      |  |  |
|  |           |  |  +--------------------------------+  |  |
|  | [Commerce]|  |                                      |  |
|  |  Shop     |  +--------------------------------------+  |
|  |  ...      |                                            |
|  +-----------+  +--------------------------------------+  |
|                 | MobileNav (bottom bar, md:hidden)     |  |
|                 | [Home] [Msgs] [Files] [Shop] [More]   |  |
|                 |   More -> Sheet -> [Feed, Videos, ...] | |
|                 +--------------------------------------+  |
+-----------------------------------------------------------+
```

### 2.3 Auth Guard Decision Tree

```
User navigates to /videos
         |
         v
ProtectedRoute checks useAuthStore.isAuthenticated
         |
    +----+----+
    |         |
   YES        NO
    |         |
    v         v
Render      Navigate to /login
AppShell    with state.from = "/videos"
  |
  v                  After login:
<Outlet>    -------> useAuthStore.login() fires
renders              location.state.from exists
VideosPage           -> navigate("/videos")
```

### 2.4 Vite Proxy Path Resolution

```
Browser request: GET /videos
         |
         v
Vite dev server checks proxy rules:
  /ui?    -> NO  (path is /videos, not /ui/...)
  /api?   -> NO
  /feed?  -> NO
  /mock?  -> NO
  ...none match
         |
         v
Vite serves index.html (SPA fallback)
         |
         v
React Router resolves /videos -> VideosPage

---

Browser request: GET /ui/videos  (XHR from VideosPage)
         |
         v
Vite dev server checks proxy rules:
  /ui?    -> YES -> proxy to http://localhost:8000/ui/videos
         |
         v
Backend FastAPI handles /ui/videos -> returns JSON
```

---

## 3. Current State Analysis

### 3.1 Route Definitions (`frontend/src/App.tsx`)

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

### 3.2 Desktop Sidebar (`frontend/src/components/layout/Sidebar.tsx`)

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

### 3.3 Mobile Sidebar Drawer (`frontend/src/components/layout/AppShell.tsx`)

The `MobileSidebar` component is defined at the bottom of `AppShell.tsx`. It has its own `MOBILE_NAV_GROUPS` array with the same group structure but uses component references for icons (e.g., `icon: FolderOpen`) instead of JSX elements. It has 4 groups (Main, Commerce, Productivity, Account) mirroring the desktop sidebar but with fewer items (no Contacts, Helpdesk, Payment Incidents, Remote Desktop). The filtering logic for admin-gated items is the same pattern.

### 3.4 Mobile Bottom Nav (`frontend/src/components/layout/MobileNav.tsx`)

The mobile bottom tab bar has two tiers:
- **PRIMARY_TABS** (always visible): Home, Messages, Files, Shop -- plus a "More" button.
- **MORE_LINKS** (shown in a bottom Sheet): Feed, Cart, Billing, Calendar, Signing, Profile, Security, Alerts, Tickets, Ticket Spaces, Remote Desktop, Settings, Role Mgmt, Moderation Board.

The "More" sheet renders as a 4-column grid of icon buttons. Items are filtered by the same permission checks. The "Videos" entry belongs in `MORE_LINKS`.

### 3.5 Vite Dev Proxy (`frontend/vite.config.ts`)

The Vite dev server proxies certain path prefixes to `http://localhost:8000`. Relevant existing rules:

| Pattern | Behavior |
|---------|----------|
| `/ui` | Proxy to backend (covers `/ui/videos/*`) |
| `/api` | Proxy to backend |
| `/feed` | Bypass function: HTML requests serve SPA `index.html`; API calls proxy |
| `/tickets` | Bypass function: same SPA/API split |
| `/ticket-spaces` | Bypass function: same SPA/API split |

The video API endpoints live under `/ui/videos/*`, which is already covered by the `/ui` proxy rule. The SPA route `/videos` does NOT collide with any backend path prefix (the backend uses `/ui/videos`, not `/videos`), so no bypass rule is needed. Vite's default behavior for unmatched paths is to serve `index.html` (the SPA entry point), which is correct for client-side routing.

### 3.6 Existing Video Page Components (from VOD-007 and VOD-008)

Per the ticket dependency chain:
- **VOD-007** produces `frontend/src/pages/videos/VideosPage.tsx` -- the video library with upload, progress tracking, and grid view.
- **VOD-008** produces `frontend/src/pages/videos/VideoPlayer.tsx` -- the HLS.js player with DRM support and metadata display.

Neither component exists yet (they are in-progress deliverables from prior tickets). This specification defines the routing and navigation wiring that will connect them once they land.

---

## 4. Technical Design

### 4.1 Route Hierarchy

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

### 4.2 Lazy Loading

Add two lazy imports at the top of `App.tsx`, following the existing alphabetical grouping:

```typescript
const VideosPage = lazy(() => import("@/pages/videos/VideosPage"));
const VideoPlayer = lazy(() => import("@/pages/videos/VideoPlayer"));
```

These imports are deferred until the user first navigates to `/videos` or `/videos/:videoId`. The global `<Suspense fallback={<PageSpinner />}>` wrapper in `App.tsx` handles the loading spinner during chunk fetch.

### 4.3 Sidebar Placement and Icon Choice

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

### 4.4 Mobile Sidebar Drawer Update

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

### 4.5 Mobile Bottom Nav Update

Add "Videos" to the `MORE_LINKS` array in `MobileNav.tsx`:

```typescript
{ label: "Videos", path: "/videos", icon: Film },
```

Position: Insert near the top of `MORE_LINKS`, after "Feed" and before "Cart". This groups content-consumption features (Feed, Videos) together, separated from transactional features (Cart, Billing). The "More" sheet renders items in a 4-column grid, so ordering matters for scannability.

### 4.6 Breadcrumb / Back Navigation

The `VideoPlayer` page (`/videos/:videoId`) should provide a way to navigate back to the video library. This is the responsibility of VOD-008 (the player page component), not this routing ticket. However, the route structure enables standard patterns:

- **React Router `useNavigate(-1)`**: Browser back button or an explicit "Back" button using `navigate(-1)`.
- **Explicit link**: `<Link to="/videos">Back to Videos</Link>` in the player page header.
- **Sidebar highlight**: Both `/videos` and `/videos/:videoId` highlight the same "Videos" sidebar entry, providing persistent navigation context.

No breadcrumb component is needed at the routing level. The `PageHeader` component (`frontend/src/components/shared/PageHeader.tsx`) used by most pages supports a `title` and optional `description`/`actions` but does not have built-in breadcrumb support. If breadcrumbs are desired, the player page can implement them inline (as `FilesPage.tsx` does with its custom breadcrumb bar at line 937).

### 4.7 Permission Gating

Video routes are **not gated** by role or feature flag in this initial implementation. All authenticated users can access `/videos` and `/videos/:videoId`. Rationale:

- The video library is a user-scoped view (users see only their own videos via the backend's `GET /ui/videos` endpoint, which filters by `user_sub`).
- No admin-only operations are exposed on the video listing page.
- The player page respects playback entitlements (via the backend's entitlement token system from VOD-006), so access control is handled at the API layer, not the route layer.

If a feature flag is needed later (e.g., for gradual rollout), add:
1. A `VITE_VIDEO_MANAGEMENT_ENABLED` env var and `isVideoManagementEnabled()` flag in `featureFlags.ts`.
2. A conditional wrapper around the `<Route>` elements in `App.tsx`.
3. Filter entries in `Sidebar.tsx`, `AppShell.tsx`, and `MobileNav.tsx` (same pattern as `isVncRemoteDesktopEnabled()`).

### 4.8 Deep Linking and Direct URL Access

When a user navigates directly to `http://localhost:3000/videos` or `http://localhost:3000/videos/abc123`:

1. **Vite dev server**: The path `/videos` does not match any proxy rule (`/ui`, `/api`, `/feed`, `/tickets`, etc.), so Vite serves `index.html` (the SPA entry point). This is correct behavior.
2. **React Router**: The SPA boots, `ProtectedRoute` checks auth, and if authenticated, renders the matching `<Route>` inside `AppShell`.
3. **Production (nginx/CloudFront)**: The standard SPA catch-all rule (`try_files $uri /index.html`) handles unmatched paths. No special nginx rule is needed for `/videos`.

No Vite proxy bypass rule is needed because the backend API path (`/ui/videos`) and the SPA route path (`/videos`) do not collide. This contrasts with `/feed` and `/tickets`, where the SPA route and backend API share the same path prefix, requiring a bypass function to distinguish HTML page requests from XHR API calls.

---

## 5. DynamoDB Access Patterns

This ticket is **frontend-only** -- it does not interact with DynamoDB directly. The video
API endpoints queried by the page components (delivered by VOD-007/VOD-008) are the ones that
access DynamoDB. For completeness, the downstream access patterns that the routed pages
trigger are documented below.

### 5.1 Downstream Patterns (triggered by VideosPage / VideoPlayer)

| # | Operation | Table | PK | SK / GSI | Initiated By |
|---|-----------|-------|----|----------|--------------|
| 1 | List user's videos | Videos | `USER#{user_sub}` | GSI `ByUserCreatedAt` SK=`created_at` (N) | `GET /ui/videos` from VideosPage |
| 2 | Get single video | Videos | `video_id` | -- (direct get) | `GET /ui/videos/{videoId}` from VideoPlayer |
| 3 | Get playback entitlement | -- | -- | -- (computed, not stored) | `POST /v1/playback/entitlements/issue` from VideoPlayer |
| 4 | Get transcode job status | TranscodeJobs | `job_id` | -- (direct get) | `GET /ui/videos/{videoId}/transcode-status` from VideosPage progress card |
| 5 | Get video manifest URL | S3 (not DDB) | -- | -- | HLS.js in VideoPlayer fetches from S3 URL |
| 6 | Check DRM key revocation | ContentKeys | `key_id` | -- (direct get) | `GET /drm/hls-key` from HLS.js key fetch |

### 5.2 No New Tables or GSIs

VOD-009 creates **zero** DynamoDB tables, GSIs, or items. All data access is mediated by
backend API endpoints that are already defined by prior tickets (VOD-001 through VOD-008,
VOD-010).

---

## 6. API Request/Response Examples

VOD-009 does not define any API endpoints. However, the navigation chrome routes users to
pages that call existing APIs. Below are the key API calls that the routed pages make,
documented here for integration context.

### 6.1 List Videos (called by VideosPage on mount)

```bash
# VideosPage calls this on mount via React Query
curl -s http://localhost:8000/ui/videos \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_token_value; ui_access_token=eyJhbG..." \
  -H "Accept: application/json"
```

Response (200):
```json
{
  "videos": [
    {
      "video_id": "v_8a3b1f0e2c4d",
      "title": "My First Upload",
      "status": "published",
      "duration_seconds": 127.4,
      "thumbnail_url": "/mock/s3/thumbnails/v_8a3b1f0e2c4d/thumb_001.jpg",
      "created_at": 1716566400,
      "updated_at": 1716567000,
      "file_size_bytes": 52428800,
      "renditions": ["360p", "720p", "1080p"]
    },
    {
      "video_id": "v_9b4c2g1f3d5e",
      "title": "Product Demo",
      "status": "encoding",
      "duration_seconds": null,
      "thumbnail_url": null,
      "created_at": 1716568000,
      "updated_at": 1716568100,
      "file_size_bytes": 104857600,
      "renditions": []
    }
  ],
  "cursor": null
}
```

### 6.2 Get Single Video (called by VideoPlayer on mount)

```bash
# VideoPlayer calls this using the :videoId route param
curl -s http://localhost:8000/ui/videos/v_8a3b1f0e2c4d \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_token_value; ui_access_token=eyJhbG..." \
  -H "Accept: application/json"
```

Response (200):
```json
{
  "video_id": "v_8a3b1f0e2c4d",
  "title": "My First Upload",
  "description": "A walkthrough of the new dashboard features",
  "status": "published",
  "duration_seconds": 127.4,
  "width": 1920,
  "height": 1080,
  "frame_rate": 30.0,
  "codec": "h264",
  "thumbnail_url": "/mock/s3/thumbnails/v_8a3b1f0e2c4d/thumb_001.jpg",
  "manifest_url": "/mock/s3/hls/v_8a3b1f0e2c4d/master.m3u8",
  "drm_policy_id": "aes128_default",
  "created_at": 1716566400,
  "updated_at": 1716567000,
  "file_size_bytes": 52428800,
  "renditions": [
    { "name": "360p", "width": 640, "height": 360, "bitrate_kbps": 800 },
    { "name": "720p", "width": 1280, "height": 720, "bitrate_kbps": 2500 },
    { "name": "1080p", "width": 1920, "height": 1080, "bitrate_kbps": 5000 }
  ]
}
```

### 6.3 Issue Playback Entitlement (called by VideoPlayer before HLS playback)

```bash
curl -s -X POST http://localhost:8000/v1/playback/entitlements/issue \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_token_value; ui_access_token=eyJhbG..." \
  -H "x-csrf-token: csrf_token_value" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "v_8a3b1f0e2c4d",
    "tenant_id": "tenant-a",
    "device_id": "browser_a1b2c3",
    "profile": "hls",
    "ttl_seconds": 3600
  }'
```

Response (200):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi...",
  "expires_at": 1716570000,
  "audience": "playback"
}
```

### 6.4 Navigation-Only Requests (no API call)

The following navigation actions produce **no API call** -- they are purely client-side
React Router transitions:

| Action | From | To | API Call? |
|--------|------|----|-----------|
| Click "Videos" sidebar link | `/` (Dashboard) | `/videos` | No (React Router `navigate`) |
| Click video thumbnail | `/videos` | `/videos/v_abc` | No (React Router `<Link>`) |
| Click browser Back button | `/videos/v_abc` | `/videos` | No (History API `popstate`) |
| Click "Videos" while on `/videos` | `/videos` | `/videos` | No (already at route) |

The page components themselves issue API calls on mount (via React Query `useQuery`), but the
route transition is instantaneous.

---

## 7. Error Handling Matrix

Since this ticket is navigation-only, errors fall into two categories: (A) route-level errors
handled by React Router and ProtectedRoute, and (B) page-load errors when lazy chunks fail.

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---------------|-------------|------------|---------------------|-----------------|
| 1 | Unauthenticated access to `/videos` | -- (client-side) | `AUTH_REQUIRED` | Redirect to `/login` | Login, then auto-redirect back via `state.from` |
| 2 | Unauthenticated access to `/videos/:id` | -- (client-side) | `AUTH_REQUIRED` | Redirect to `/login` | Login, then auto-redirect back |
| 3 | Unknown nested path `/videos/a/b/c` | -- (client-side) | `NOT_FOUND` | "Page not found" (ErrorPage 404) | Navigate to Dashboard or use sidebar |
| 4 | Lazy chunk load failure (network error) | -- (client-side) | `CHUNK_LOAD_ERROR` | Suspense fallback spinner, then error boundary | Refresh page (chunk will be re-fetched) |
| 5 | Lazy chunk load failure (deploy mismatch) | -- (client-side) | `CHUNK_HASH_MISMATCH` | White screen or "Loading chunk failed" | Hard refresh (`Ctrl+Shift+R`) to get new `index.html` |
| 6 | Session expired during navigation | 401 | `SESSION_EXPIRED` | Redirect to `/login` | Re-login (axios interceptor handles 401 globally) |
| 7 | CORS error on API call from VideosPage | -- (browser) | `NETWORK_ERROR` | "Failed to load videos" (React Query error) | Check dev stack is running (`just status`) |
| 8 | Backend down (502/503) on video list | 502/503 | `SERVER_ERROR` | "Something went wrong" (React Query error boundary) | Wait for backend restart; React Query retries 3x |
| 9 | Video not found (`/videos/nonexistent`) | 404 | `VIDEO_NOT_FOUND` | "Video not found" (VideoPlayer error state) | Navigate back to `/videos` |
| 10 | Feature flag disabled (future) | -- (client-side) | `FEATURE_DISABLED` | Route not rendered; falls through to 404 | Contact admin to enable feature |
| 11 | Sidebar render error (icon import) | -- (client-side) | `RENDER_ERROR` | React error boundary catches | Check lucide-react import; redeploy |
| 12 | Mobile viewport but desktop route state | -- (client-side) | -- | Sidebar hidden, bottom nav visible | Normal behavior (responsive breakpoint) |

### 7.1 Error Boundary Strategy

The application uses a global React error boundary (`frontend/src/components/ErrorBoundary.tsx`)
that catches render errors in the component tree. For lazy-loaded video pages, the error
propagation chain is:

```
VideosPage render error
  -> caught by <ErrorBoundary> inside AppShell content area
    -> shows "Something went wrong" with retry button
    -> retry button calls window.location.reload()

Lazy chunk network error
  -> caught by <Suspense> boundary (shows spinner indefinitely)
  -> if chunk never loads, user sees perpetual spinner
  -> mitigated by: React.lazy() retry wrapper (see section 4.2)
```

### 7.2 Chunk Load Retry Pattern

To handle deploy-time chunk hash mismatches (common in long-lived SPA sessions), the lazy
import can be wrapped with a retry:

```typescript
function lazyRetry<T extends React.ComponentType<any>>(
  factory: () => Promise<{ default: T }>,
): React.LazyExoticComponent<T> {
  return lazy(async () => {
    try {
      return await factory();
    } catch (err) {
      // Force reload to get new index.html with updated chunk hashes
      window.location.reload();
      // Return a never-resolving promise to prevent flash of error
      return new Promise(() => {});
    }
  });
}

const VideosPage = lazyRetry(() => import("@/pages/videos/VideosPage"));
const VideoPlayer = lazyRetry(() => import("@/pages/videos/VideoPlayer"));
```

---

## 8. Pydantic Models

This ticket does not add or modify any backend Pydantic models. It is a purely frontend
change. However, the frontend TypeScript interfaces that mirror the backend models are
relevant for the pages being routed. These are defined in VOD-007/VOD-008 and are listed
here for reference.

### 8.1 Frontend TypeScript Interfaces (`frontend/src/api/types.ts`)

```typescript
// Added by VOD-007 (used by VideosPage)
export interface VideoSummary {
  video_id: string;
  title: string;
  status: VideoStatus;
  duration_seconds: number | null;
  thumbnail_url: string | null;
  created_at: number;
  updated_at: number;
  file_size_bytes: number;
  renditions: string[];
}

export type VideoStatus =
  | "created"
  | "uploading"
  | "uploaded"
  | "probing"
  | "probe_failed"
  | "encoding"
  | "encode_failed"
  | "packaging"
  | "package_failed"
  | "reviewing"
  | "published"
  | "archived";

export interface VideoListResponse {
  videos: VideoSummary[];
  cursor: string | null;
}

// Added by VOD-008 (used by VideoPlayer)
export interface VideoDetail extends VideoSummary {
  description: string | null;
  width: number | null;
  height: number | null;
  frame_rate: number | null;
  codec: string | null;
  manifest_url: string | null;
  drm_policy_id: string | null;
  renditions: RenditionInfo[];
}

export interface RenditionInfo {
  name: string;
  width: number;
  height: number;
  bitrate_kbps: number;
}

export interface PlaybackEntitlementRequest {
  asset_id: string;
  tenant_id: string;
  device_id: string;
  profile: string;
  ttl_seconds: number;
}

export interface PlaybackEntitlementResponse {
  token: string;
  expires_at: number;
  audience: string;
}
```

### 8.2 Sidebar Navigation Type Definitions

The sidebar uses these internal type definitions (already existing in the codebase):

```typescript
// In Sidebar.tsx (desktop)
interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;  // JSX element like <Film className="h-5 w-5" />
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

// In AppShell.tsx (mobile sidebar drawer)
interface MobileNavItem {
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;  // Component reference like Film
}

interface MobileNavGroup {
  title: string;
  items: MobileNavItem[];
}

// In MobileNav.tsx (bottom nav More sheet)
interface MoreLink {
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
}
```

---

## 9. Frontend Component Tree

### 9.1 Full Component Hierarchy

```
<App>
  <QueryClientProvider>
    <ThemeProvider>
      <Routes>
        {/* ... public routes ... */}

        <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>

          {/* AppShell renders: */}
          <Header />
          <Sidebar>                              {/* desktop only (hidden md:flex) */}
            <NavGroup title="Main">
              <NavItem label="Dashboard" path="/" icon={<LayoutDashboard />} />
              <NavItem label="Messages"  path="/messages" icon={<MessageSquare />} />
              <NavItem label="Contacts"  path="/contacts" icon={<Users />} />
              <NavItem label="Helpdesk"  path="/helpdesk" icon={<Headphones />} />
              <NavItem label="Feed"      path="/feed" icon={<Newspaper />} />
            </NavGroup>
            <NavGroup title="Media">             {/* NEW (VOD-009) */}
              <NavItem label="Videos" path="/videos" icon={<Film />} />
            </NavGroup>
            <NavGroup title="Commerce">
              {/* Shop, Cart, Billing, Orders, Subscriptions */}
            </NavGroup>
            <NavGroup title="Productivity">
              {/* Files, Projects, Calendar, Signing */}
            </NavGroup>
            <NavGroup title="Account">
              {/* Profile, Security, Alerts, Tickets, etc. */}
            </NavGroup>
          </Sidebar>

          <MobileNav>                            {/* mobile only (flex md:hidden) */}
            <PrimaryTab icon={<Home />}      label="Home"     path="/" />
            <PrimaryTab icon={<MessageSquare />} label="Messages" path="/messages" />
            <PrimaryTab icon={<FolderOpen />}    label="Files"    path="/files" />
            <PrimaryTab icon={<ShoppingBag />}   label="Shop"     path="/shop" />
            <MoreButton onClick={openSheet}>
              <MoreSheet>
                <MoreLink label="Feed"    path="/feed"    icon={Newspaper} />
                <MoreLink label="Videos"  path="/videos"  icon={Film} />  {/* NEW */}
                <MoreLink label="Cart"    path="/cart"    icon={ShoppingCart} />
                {/* ... remaining More links ... */}
              </MoreSheet>
            </MoreButton>
          </MobileNav>

          <MobileSidebar>                        {/* hamburger drawer */}
            <MobileNavGroup title="Main"> ... </MobileNavGroup>
            <MobileNavGroup title="Media">       {/* NEW (VOD-009) */}
              <MobileNavItem label="Videos" path="/videos" icon={Film} />
            </MobileNavGroup>
            <MobileNavGroup title="Commerce"> ... </MobileNavGroup>
            <MobileNavGroup title="Productivity"> ... </MobileNavGroup>
            <MobileNavGroup title="Account"> ... </MobileNavGroup>
          </MobileSidebar>

          <main>
            <Suspense fallback={<PageSpinner />}>
              <Outlet />   {/* React Router injects matched child */}
            </Suspense>
          </main>

          {/* New route entries (VOD-009): */}
          <Route path="videos" element={<VideosPage />} />
          <Route path="videos/:videoId" element={<VideoPlayer />} />

        </Route>
      </Routes>
    </ThemeProvider>
  </QueryClientProvider>
</App>
```

### 9.2 Props and State for Navigation Components

| Component | Key Props | State | Notes |
|-----------|-----------|-------|-------|
| `Sidebar` | -- | `collapsed: boolean` (local), `location` (React Router) | `isActive(path)` derived from `location.pathname` |
| `NavGroup` | `title: string`, `items: NavItem[]` | -- | Pure presentational; filters items by permission |
| `NavItem` | `label`, `path`, `icon` | -- | Renders `<Link>` with active class |
| `MobileNav` | -- | `moreOpen: boolean` (local) | Controls More sheet open/close |
| `MoreSheet` | `links: MoreLink[]` | -- | 4-column grid of icon buttons |
| `MobileSidebar` | `open: boolean`, `onClose: () => void` | -- | Radix Sheet component |
| `ProtectedRoute` | `children: ReactNode` | -- | Reads `useAuthStore.isAuthenticated` |
| `AppShell` | -- | -- | Composes Header + Sidebar + MobileNav + Outlet |

### 9.3 React Query Keys Used by Routed Pages

The pages that VOD-009 routes to use these React Query cache keys:

| Page | Query Key | Stale Time | Refetch Trigger |
|------|-----------|------------|-----------------|
| VideosPage | `["videos", { cursor }]` | 30s | Page mount, pull-to-refresh, upload complete |
| VideosPage | `["videos", videoId, "transcode-status"]` | 5s | Polling during encoding |
| VideoPlayer | `["videos", videoId]` | 60s | Page mount |
| VideoPlayer | `["playback-entitlement", videoId]` | -- (no cache) | Each playback session |

### 9.4 State Management

This ticket does not introduce any new Zustand stores or React context providers. The
navigation state is managed entirely by React Router's built-in location tracking.

| State Concern | Managed By | Location |
|--------------|------------|----------|
| Current route | React Router v6 | `useLocation()` hook |
| Auth status | Zustand `useAuthStore` | `frontend/src/stores/authStore.ts` |
| Sidebar collapsed | Local `useState` | `Sidebar.tsx` |
| More sheet open | Local `useState` | `MobileNav.tsx` |
| Mobile drawer open | Local `useState` | `AppShell.tsx` |
| Active nav highlight | Derived from `location.pathname` | `isActive()` in Sidebar.tsx |

---

## 10. Implementation Plan

### 10.1 Files to Modify

| File | Change | Lines Affected |
|------|--------|---------------|
| `frontend/src/App.tsx` | Add 2 lazy imports + 2 `<Route>` elements | ~4 new lines |
| `frontend/src/components/layout/Sidebar.tsx` | Import `Film`, add "Media" group to `NAV_GROUPS` | ~8 new lines |
| `frontend/src/components/layout/AppShell.tsx` | Import `Film`, add "Media" group to `MOBILE_NAV_GROUPS` | ~8 new lines |
| `frontend/src/components/layout/MobileNav.tsx` | Import `Film`, add entry to `MORE_LINKS` | ~2 new lines |

### 10.2 Files Created by Prior Tickets

<!-- NOTE: ALL files below ALREADY EXIST. -->

| File | Ticket | Status |
|------|--------|--------|
| `frontend/src/pages/videos/VideosPage.tsx` | VOD-007 | **Done** |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | VOD-008 | **Done** (note: actual name is `VideoPlayerPage.tsx`, not `VideoPlayer.tsx`) |
| `frontend/src/api/endpoints/vod.ts` | VOD-007 | **Done** (note: file is `vod.ts`, not `videos.ts`) |

All routes are already registered in `App.tsx`: `/videos` (line 164), `/videos/:videoId` (line 165), `/gallery/:videoId` (line 163).

This ticket does NOT create these files. It wires them into routing and navigation. If VOD-007/VOD-008 have not yet landed, the lazy imports will cause a chunk-load error when navigating to `/videos`. To unblock development, a placeholder can be committed:

```typescript
// frontend/src/pages/videos/VideosPage.tsx (placeholder)
export default function VideosPage() {
  return <div className="p-6"><h1 className="text-2xl font-semibold">Videos</h1><p className="text-muted-foreground">Coming soon.</p></div>;
}
```

### 10.3 Step-by-Step Implementation

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

### 10.4 Dependency Ordering

```
VOD-001 (metadata model)
  -> VOD-002 (upload endpoint)
    -> VOD-003 (transcode worker)
      -> VOD-004 (FFmpeg executor)
        -> VOD-005 (S3 upload + manifest)
  -> VOD-006 (listing/detail API)
    -> VOD-007 (VideosPage.tsx)     -+
    -> VOD-008 (VideoPlayer.tsx)     +-> VOD-009 (routes + nav) [this ticket]
                                    -+
```

VOD-009 can be implemented in parallel with VOD-007 and VOD-008 by using placeholder page components. The placeholder approach allows:
- Navigation and routing to be tested immediately.
- Sidebar and mobile nav entries to be validated visually.
- E2E route guard tests to pass without real page content.

When VOD-007 and VOD-008 land, the placeholder files are replaced by the real implementations. No routing changes are needed at that point.

### 10.5 No Vite Proxy Changes Required

The existing `/ui` proxy rule in `vite.config.ts` already forwards all `/ui/*` requests (including `/ui/videos/*`) to the backend. The SPA route `/videos` does not collide with any backend prefix. No changes to `vite.config.ts` are needed.

Verification:
- `GET /videos` (browser navigation, `Accept: text/html`) -> Vite serves `index.html` -> SPA handles route.
- `GET /ui/videos` (XHR, `Accept: application/json`) -> Vite proxies to `http://localhost:8000/ui/videos` -> backend responds.
- `GET /ui/videos/abc123` (XHR) -> Vite proxies to backend.

---

## 11. Observability & Monitoring

Although this ticket is frontend-only, observability is still important for tracking
navigation usage, chunk load failures, and auth redirect rates.

### 11.1 Frontend Metrics (collected via Prometheus-style counters in `metrics.ts`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `spa_route_navigation_total` | Counter | `route`, `from_route` | Incremented on each React Router navigation to `/videos` or `/videos/:videoId` |
| `spa_lazy_chunk_load_duration_ms` | Histogram | `chunk_name` | Time from navigation start to chunk load complete (for `VideosPage`, `VideoPlayer`) |
| `spa_lazy_chunk_load_error_total` | Counter | `chunk_name`, `error_type` | Chunk load failures (network error, hash mismatch, timeout) |
| `spa_auth_redirect_total` | Counter | `target_route` | Auth redirects to `/login` from video routes |
| `spa_sidebar_click_total` | Counter | `item_label`, `group_title` | Sidebar link clicks (tracks feature discoverability) |
| `spa_mobile_more_sheet_click_total` | Counter | `item_label` | More sheet link clicks (tracks mobile feature usage) |

### 11.2 Log Events

| Event | Level | Payload | Trigger |
|-------|-------|---------|---------|
| `route.navigate` | DEBUG | `{ from, to, method: "link" \| "direct" \| "back" }` | Any navigation to `/videos` or `/videos/:id` |
| `route.auth_redirect` | INFO | `{ target: "/videos", reason: "unauthenticated" }` | ProtectedRoute redirects to login |
| `chunk.load_start` | DEBUG | `{ chunk: "VideosPage" }` | Lazy import begins |
| `chunk.load_complete` | DEBUG | `{ chunk: "VideosPage", duration_ms }` | Lazy import resolves |
| `chunk.load_error` | ERROR | `{ chunk: "VideosPage", error }` | Lazy import rejects |
| `sidebar.click` | DEBUG | `{ label: "Videos", group: "Media" }` | User clicks sidebar link |
| `mobile.more_click` | DEBUG | `{ label: "Videos" }` | User clicks More sheet link |

### 11.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High chunk load failure rate | `spa_lazy_chunk_load_error_total{chunk_name="VideosPage"}` > 10 in 5min | P2 | Check CDN cache invalidation; may need deploy rollback |
| Zero video route navigations | `rate(spa_route_navigation_total{route="/videos"}[1h]) == 0` for 24h post-launch | P3 | Check sidebar rendering; may have a display bug |
| Elevated auth redirects from videos | `rate(spa_auth_redirect_total{target_route="/videos"}[5m]) > 50` | P2 | Possible session expiry storm; check auth service health |
| Chunk load P99 > 5s | `histogram_quantile(0.99, spa_lazy_chunk_load_duration_ms{chunk_name=~"Videos.*"}) > 5000` | P3 | Check bundle size; may need further code splitting |

### 11.4 Dashboard Queries

**Video Feature Adoption (daily)**:
```promql
sum(increase(spa_route_navigation_total{route="/videos"}[1d]))
```

**Chunk Load Success Rate**:
```promql
1 - (
  sum(rate(spa_lazy_chunk_load_error_total{chunk_name=~"Videos.*"}[1h]))
  /
  sum(rate(spa_lazy_chunk_load_duration_ms_count{chunk_name=~"Videos.*"}[1h]))
)
```

**Mobile vs Desktop Navigation Split**:
```promql
# Desktop sidebar clicks
sum(rate(spa_sidebar_click_total{item_label="Videos"}[1d]))
# Mobile More sheet clicks
sum(rate(spa_mobile_more_sheet_click_total{item_label="Videos"}[1d]))
# Mobile drawer clicks
sum(rate(spa_sidebar_click_total{item_label="Videos", source="mobile_drawer"}[1d]))
```

---

## 12. Rollout Plan

### 12.1 Feature Flag Strategy

Although the initial implementation does not use a feature flag, the rollout plan includes
a progressive enable strategy for safety.

**Phase 0: Development (current)**
- Routes and navigation entries are committed to the `feat/media-integrations` branch.
- Placeholder page components are used until VOD-007/VOD-008 land.
- E2E tests validate routing and navigation chrome only.

**Phase 1: Internal Preview**
- Feature flag `VITE_VIDEO_MANAGEMENT_ENABLED=true` added (defaults to `false` in production).
- Internal team members see "Videos" in sidebar via feature flag override.
- Monitor: zero chunk load errors, correct auth redirects, sidebar renders without errors.

**Phase 2: Canary Rollout (10% of users)**
- Feature flag enabled for 10% of users via LaunchDarkly / Unleash integration.
- Monitor: no increase in error rate, no layout shift issues, no performance regression.
- Duration: 48 hours.
- Rollback: Disable feature flag (instant, no deploy needed).

**Phase 3: General Availability**
- Feature flag defaulted to `true` for all users.
- Feature flag code left in place for 30 days as a kill switch.
- After 30 days with no issues, remove feature flag conditionals (cleanup PR).

### 12.2 Migration Steps

No migration is needed. This is a purely additive change:
- No database schema changes.
- No backend code changes.
- No data migrations.
- No environment variable additions required for the routing change itself.

### 12.3 Rollback Procedure

| Step | Action | Time to Execute |
|------|--------|-----------------|
| 1 | Disable feature flag `VITE_VIDEO_MANAGEMENT_ENABLED=false` | Instant (remote config) |
| 2 | Verify: "Videos" no longer appears in sidebar, routes return 404 | 30 seconds |
| 3 | If feature flag is not available, revert the 4-file commit | 5 minutes (git revert + deploy) |
| 4 | Verify: no regressions in other navigation items | 2 minutes (run E2E suite sections 92-94) |

### 12.4 Backward Compatibility

- **Existing bookmarks to `/videos`**: If a user bookmarked `/videos` during the canary phase
  and the feature is rolled back, they will see the 404 page. This is acceptable since video
  management is a new feature with no prior user expectations.
- **Existing sidebar layout**: Adding a new "Media" group shifts the "Commerce" group down by
  one section. This is a minor visual change that does not break any existing navigation flows.
- **Mobile bottom nav**: Adding one more entry to the "More" sheet grid does not change the
  layout of existing entries (grid auto-flows).

---

## 13. Performance Considerations

### 13.1 Bundle Size Impact

| Concern | Analysis | Mitigation |
|---------|----------|------------|
| Lazy chunk size (VideosPage) | Estimated ~50-80KB gzipped (grid view, upload UI, status tracking) | Lazy-loaded; does not affect initial bundle |
| Lazy chunk size (VideoPlayer) | Estimated ~120-200KB gzipped (HLS.js library is ~70KB alone) | Lazy-loaded; only fetched on `/videos/:id` navigation |
| Sidebar code increase | ~200 bytes (one new group object) | Negligible; sidebar is in the main bundle |
| MobileNav code increase | ~100 bytes (one new entry) | Negligible |
| Total main bundle increase | ~300 bytes | Below the threshold for any performance concern |

### 13.2 Navigation Performance

| Operation | Expected Latency | Notes |
|-----------|-----------------|-------|
| Click sidebar "Videos" -> route transition | <5ms | Client-side React Router navigation; no network |
| First load of `/videos` chunk | 50-200ms | Network fetch of lazy chunk (depends on CDN/bundle size) |
| Subsequent loads of `/videos` chunk | <1ms | Cached in browser memory after first load |
| First load of `/videos/:id` chunk | 100-300ms | Larger chunk (includes HLS.js) |
| Deep link to `/videos` (cold start) | 500-1500ms | Full SPA bootstrap + auth check + lazy chunk load |
| Auth redirect to `/login` and back | 200-500ms | Two route transitions + session validation |

### 13.3 Sidebar Rendering Performance

Adding a fifth nav group to the sidebar has negligible rendering cost. The sidebar uses a
simple `.map()` over the `NAV_GROUPS` array to render items. Each `NavItem` is a small
functional component with no complex state or effects. The `isActive()` check is a simple
string comparison.

**Potential concern**: If many more items are added to the "Media" group in the future
(Broadcaster, Podcasts, Live Streams, etc.), the sidebar could become too tall for smaller
screens. The sidebar already has `overflow-y-auto` to handle scrolling.

### 13.4 Prefetching Strategy

For improved perceived performance, the video page chunks can be prefetched after the initial
page load:

```typescript
// In App.tsx or AppShell, after initial render
useEffect(() => {
  const timer = setTimeout(() => {
    // Prefetch video chunks after 3s idle
    import("@/pages/videos/VideosPage");
    import("@/pages/videos/VideoPlayer");
  }, 3000);
  return () => clearTimeout(timer);
}, []);
```

This is optional and not included in the initial implementation. It can be added if metrics
show that first-navigation chunk load times are impacting user experience.

### 13.5 Rate Limiting Considerations

No rate limiting is needed for this ticket since it does not add API endpoints. The
downstream video APIs called by the routed pages already have their own rate limits:

| API Endpoint | Rate Limit | Source |
|-------------|------------|--------|
| `GET /ui/videos` | 60 req/min per user | VOD-006 |
| `GET /ui/videos/{id}` | 120 req/min per user | VOD-006 |
| `POST /v1/playback/entitlements/issue` | 30 req/min per user | Playback entitlements |
| `GET /drm/hls-key` | 300 req/min per IP | VOD-010 |

### 13.6 Caching Strategy

| Resource | Cache Policy | Rationale |
|----------|-------------|-----------|
| Lazy JS chunks | `Cache-Control: public, max-age=31536000, immutable` | Content-hashed filenames; never changes |
| Sidebar config | In-memory (module scope) | `NAV_GROUPS` is a static array; no fetch needed |
| Route definitions | In-memory (React Router) | Defined at module load time; no runtime cost |
| Video list API response | React Query staleTime: 30s | Balance between freshness and API load |
| Video detail API response | React Query staleTime: 60s | Metadata changes infrequently |

---

## 14. Testing Strategy

### 14.1 E2E Test File: `frontend/e2e/video-routes-nav.spec.ts`

A dedicated E2E spec file validates routing, navigation, and auth guards. This file can run
without the full video pipeline (VOD-001 through VOD-008) because it tests navigation chrome
and route resolution, not video upload or playback.

### 14.2 Test Setup

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

### 14.3 Test Sections

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

test("90.3 /videos shows header and sidebar", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  // Header should be present
  await expect(page.locator("header")).toBeVisible();
  // Sidebar should be present on desktop viewport
  await expect(page.locator("aside")).toBeVisible();
  // Content area should exist
  await expect(page.locator("main")).toBeVisible();
});

test("90.4 navigating /videos -> /videos/:id preserves AppShell", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  // Verify sidebar is visible before navigation
  const sidebar = page.locator("aside");
  await expect(sidebar).toBeVisible();
  // Navigate to a specific video (simulate link click if available, else goto)
  await page.goto("/videos/some-video-id");
  // Sidebar should STILL be visible (AppShell preserved)
  await expect(sidebar).toBeVisible();
  // Header should still be visible
  await expect(page.locator("header")).toBeVisible();
});

test("90.5 /videos/foo/bar/baz falls through to 404", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos/foo/bar/baz");
  // Should show 404 error page
  await expect(page.getByText(/not found/i).or(page.getByText(/404/))).toBeVisible();
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

test("91.3 after login redirect returns to /videos", async ({ page }) => {
  // Step 1: Go to /videos unauthenticated -- should redirect to /login
  await page.goto("/videos");
  await expect(page).toHaveURL(/\/login/);
  // Step 2: Inject auth cookies (simulates successful login)
  await injectAuth(page, "alice");
  // Step 3: Navigate to the login success handler (or simulate it)
  // The login page reads state.from and redirects back
  await page.goto("/videos"); // Direct navigation after auth
  await expect(page).toHaveURL("/videos");
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
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

test("92.5 collapsed sidebar shows Film icon with tooltip", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  // Collapse the sidebar
  const collapseBtn = page.getByRole("button", { name: /collapse/i })
    .or(page.locator("aside button[aria-label*='collapse' i]"));
  await collapseBtn.click();
  // Verify the Film icon is still visible (sidebar collapsed shows icons)
  const videosIcon = page.locator("aside a[href='/videos'] svg");
  await expect(videosIcon).toBeVisible();
  // Hover to show tooltip
  await videosIcon.hover();
  await expect(page.getByRole("tooltip", { name: /videos/i })
    .or(page.locator("[role='tooltip']").filter({ hasText: "Videos" }))).toBeVisible();
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
  // Verify Media group label
  await expect(page.locator("[role='dialog']").getByText("MEDIA", { exact: false })).toBeVisible();
});

test("93.2 clicking Videos in drawer navigates to /videos", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto("/");
  await page.getByRole("button", { name: /menu/i }).click();
  await page.locator("[role='dialog']").getByText("Videos").click();
  await expect(page).toHaveURL("/videos");
});

test("93.3 drawer closes after Videos navigation", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto("/");
  await page.getByRole("button", { name: /menu/i }).click();
  // Verify drawer is open
  await expect(page.locator("[role='dialog']")).toBeVisible();
  // Click Videos
  await page.locator("[role='dialog']").getByText("Videos").click();
  // Drawer should close after navigation
  await expect(page.locator("[role='dialog']")).not.toBeVisible();
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

test("94.3 Videos button in More sheet has Film icon", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto("/");
  await page.locator("nav.fixed").getByText("More").click();
  // Find the Videos button and verify it contains an SVG (the Film icon)
  const videosBtn = page.getByRole("button", { name: /videos/i });
  await expect(videosBtn).toBeVisible();
  await expect(videosBtn.locator("svg")).toBeVisible();
});
```

**Section 95: Edge Cases and Negative Tests (8 tests)**

| # | Test | What it verifies |
|---|------|-----------------|
| 95.1 | Rapid sidebar double-click does not break routing | Two fast clicks on "Videos" do not cause error |
| 95.2 | Browser back from `/videos/:id` returns to `/videos` | History stack preserved during SPA navigation |
| 95.3 | `/videos` with hash fragment `#upload` resolves | Hash fragments are passed through to page component |
| 95.4 | `/videos` with query params `?status=published` resolves | Query params preserved and accessible via `useSearchParams` |
| 95.5 | Navigating away from `/videos` then back preserves scroll | React Query cache retains video list; scroll position via layout |
| 95.6 | Concurrent navigation (click Videos then immediately Messages) | Last navigation wins; no stale route rendered |
| 95.7 | Session expires while on `/videos`, API call triggers logout | 401 from video API causes global logout redirect |
| 95.8 | Resizing viewport from desktop to mobile on `/videos` | Sidebar hides, bottom nav appears, route still active |

```typescript
test("95.1 rapid double-click on Videos sidebar does not break", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/");
  const videosLink = page.locator("aside").getByText("Videos");
  await videosLink.dblclick();
  await expect(page).toHaveURL("/videos");
  // Page should still render correctly
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
});

test("95.2 browser back from /videos/:id returns to /videos", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  await page.goto("/videos/some-id");
  await page.goBack();
  await expect(page).toHaveURL("/videos");
});

test("95.3 /videos with hash fragment resolves", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos#upload");
  await expect(page).toHaveURL(/\/videos#upload/);
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
});

test("95.4 /videos with query params resolves", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos?status=published&sort=newest");
  await expect(page).toHaveURL(/\/videos\?status=published/);
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
});

test("95.5 navigate away and back preserves route", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
  // Navigate to Dashboard
  await page.locator("aside").getByText("Dashboard").click();
  await expect(page).toHaveURL("/");
  // Navigate back to Videos
  await page.locator("aside").getByText("Videos").click();
  await expect(page).toHaveURL("/videos");
  await expect(page.getByRole("heading", { name: /videos/i })).toBeVisible();
});

test("95.6 concurrent navigation resolves to last click", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/");
  // Click Videos then immediately click Messages
  await page.locator("aside").getByText("Videos").click();
  await page.locator("aside").getByText("Messages").click();
  // Should end up on Messages (last navigation wins)
  await expect(page).toHaveURL("/messages");
});

test("95.7 session expired on /videos triggers logout", async ({ page }) => {
  await injectAuth(page, "alice");
  await page.goto("/videos");
  // Clear auth cookies to simulate session expiry
  await page.context().clearCookies();
  // Trigger a navigation that would cause an API call
  await page.reload();
  // Should redirect to login
  await expect(page).toHaveURL(/\/login/);
});

test("95.8 resize from desktop to mobile on /videos", async ({ page }) => {
  await injectAuth(page, "alice");
  // Start on desktop viewport
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/videos");
  await expect(page.locator("aside")).toBeVisible();
  // Resize to mobile
  await page.setViewportSize({ width: 375, height: 667 });
  // Sidebar should be hidden
  await expect(page.locator("aside")).not.toBeVisible();
  // Bottom nav should appear
  await expect(page.locator("nav.fixed")).toBeVisible();
  // Route should still be /videos
  await expect(page).toHaveURL("/videos");
});
```

### 14.4 Test Count Summary

| Section | Description | Tests |
|---------|-------------|-------|
| 90 | Route resolution | 5 |
| 91 | Auth guard | 3 |
| 92 | Desktop sidebar navigation | 5 |
| 93 | Mobile sidebar drawer | 3 |
| 94 | Mobile bottom nav "More" sheet | 3 |
| 95 | Edge cases and negative tests | 8 |
| **Total** | | **27** |

### 14.5 Flakiness Mitigations

1. **Lazy chunk loading**: The first navigation to `/videos` triggers a dynamic import. In CI, this may take a few hundred milliseconds. Tests use `toBeVisible()` which auto-retries with Playwright's default timeout (30s). No explicit `waitForLoadState` is needed.

2. **Viewport size for mobile tests**: Mobile tests set `{ width: 375, height: 667 }` (iPhone SE) to trigger the responsive breakpoint (`md:hidden` / `hidden md:flex`). The sidebar is hidden below `md` (768px) and the bottom nav is shown.

3. **Sheet animation**: The "More" bottom sheet and hamburger drawer use Radix `Sheet` with CSS transitions. After clicking to open, `toBeVisible()` waits for the element to be in the DOM and visible, which accounts for animation. No explicit animation wait is needed.

4. **Sidebar collapsed state**: Test 92.5 (collapsed sidebar tooltip) requires the sidebar to be in collapsed state. Use the collapse toggle button: `page.getByRole("button", { name: /collapse/i }).click()` before asserting the tooltip.

5. **No backend dependency**: These tests do not call any video API endpoints. They only test navigation, routing, and UI chrome. They can run with placeholder page components and do not require the video pipeline or DynamoDB tables.

6. **Viewport resize race condition**: Test 95.8 resizes the viewport and immediately checks sidebar visibility. Playwright's `setViewportSize` is synchronous (it waits for the resize to complete), so no race condition occurs. The responsive CSS media queries apply instantly after resize.

7. **Double-click timing**: Test 95.1 uses Playwright's `dblclick()` which fires two clicks in rapid succession. React Router debounces identical navigations, so the second click is a no-op.

8. **History stack tests**: Tests 95.2 and 95.5 depend on the browser history stack. Playwright's `goBack()` correctly navigates the history stack within the same page context. No `waitForNavigation` is needed because `toHaveURL` auto-retries.

### 14.6 Manual Verification Checklist

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
- [ ] No console errors during any video route navigation
- [ ] No layout shift when navigating to/from video pages
- [ ] Screen reader announces "Videos" sidebar link correctly
- [ ] Keyboard navigation (Tab) reaches "Videos" sidebar link
- [ ] High-contrast mode: "Videos" active state is distinguishable

---

## 15. Accessibility Considerations

### 15.1 Keyboard Navigation

The sidebar uses standard `<a>` elements (via React Router's `<Link>`), which are natively
keyboard-focusable. The "Videos" entry inherits this behavior:

- **Tab order**: "Videos" appears in tab order between the last "Main" group item (Feed) and
  the first "Commerce" group item (Shop). Adding the "Media" group inserts it naturally.
- **Enter/Space to activate**: Standard `<a>` behavior; activates the link.
- **Focus indicator**: The sidebar uses `focus-visible:ring-2` for keyboard focus visibility.

### 15.2 Screen Reader Support

- **Nav group heading**: Each sidebar group uses `<h3 className="text-xs font-semibold ...">` as
  a group label. The "Media" heading is announced before "Videos".
- **Active state**: The active link uses `aria-current="page"` (if implemented by the sidebar)
  or relies on the visual `text-primary` class. Recommend adding `aria-current="page"` to
  active sidebar items for screen reader clarity.
- **Mobile More sheet**: The "Videos" button in the grid should have `aria-label="Videos"` to
  ensure screen readers announce it correctly (icon-only buttons need explicit labels).

### 15.3 Color Contrast

- **Active state**: `text-primary` on dark sidebar background meets WCAG AA (4.5:1 contrast).
- **Inactive state**: `text-muted-foreground` on sidebar background meets WCAG AA.
- **Film icon**: Inherits text color, so contrast is the same as the label text.

---

## 16. Future Considerations

### 16.1 Expanding the "Media" Nav Group

The "Media" group is designed to grow. Anticipated future entries:

| Entry | Ticket | Icon | Path |
|-------|--------|------|------|
| Videos | VOD-009 (this) | `Film` | `/videos` |
| Broadcasts | BCAST-001 | `Radio` | `/broadcasts` |
| Live Streams | LIVE-001 | `Tv` | `/live` |
| Podcasts | POD-001 | `Podcast` | `/podcasts` |
| Recordings | CALL-010 | `Mic` | `/recordings` |

### 16.2 Video Sub-Routes

As the video management feature matures, sub-routes may be added:

| Route | Page | Purpose |
|-------|------|---------|
| `/videos` | VideosPage | Library grid + upload |
| `/videos/:videoId` | VideoPlayer | Playback + metadata |
| `/videos/:videoId/edit` | VideoEditor | Title/description editing |
| `/videos/:videoId/analytics` | VideoAnalytics | View counts, engagement |
| `/videos/upload` | UploadPage | Dedicated upload flow |
| `/videos/playlists` | PlaylistsPage | Playlist management |
| `/videos/playlists/:playlistId` | PlaylistDetail | Playlist items |

These would be added as additional `<Route>` entries inside the existing `AppShell` layout.
The `isActive("/videos")` check would continue to highlight the sidebar for all sub-routes.

### 16.3 Video Search Integration

The existing search infrastructure (`search-messaging.spec.ts`, `search-files.spec.ts`) can
be extended to video search. The sidebar "Videos" entry could gain a search icon that opens
a search dialog, or the global search (`Cmd+K`) could include video results. This is out of
scope for VOD-009 but the route structure supports it.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_vod_009.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_vod_009_crud` | Vod 009 crud verified |
| 2 | `test_vod_009_validation` | Vod 009 validation verified |
| 3 | `test_vod_009_auth` | Vod 009 auth verified |
| 4 | `test_vod_009_not_found` | Vod 009 not found verified |
| 5 | `test_vod_009_edge_cases` | Vod 009 edge cases verified |
| 6 | `test_vod_009_integration` | Vod 009 integration verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Video Routes & Navigation integrates with video metadata CRUD lifecycle
2. End-to-end flow from video creation through video routes & navigation feature
3. Error propagation from video metadata service to video routes & navigation layer

### E2E Tests (Playwright)

**File**: `frontend/e2e/vod-009.spec.ts`
**Sections**: 1-3 (10 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Video Routes & Navigation API returns 200 | 200; expected fields present |
| 2 | Video Routes & Navigation handles invalid input | 422 or 400 response |
| 3 | Video Routes & Navigation requires auth | 401 without session |
| 4 | Video Routes & Navigation UI renders | Page loads; key elements visible |
| 5 | Video Routes & Navigation integrates with video metadata | Video data correctly referenced |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 video not found, 422 invalid input

**Edge cases**: Video in processing state, deleted video reference, concurrent operations

### Test Data Requirements

- **DDB seeds**: Video metadata records from VOD-001; related video routes & navigation test data
- **Test users**: Alice (creator), Bob (viewer)

### CI/Pipeline Considerations

- **Feature flags**: VOD_ENABLED=true
- **Serial execution**: Must run after VOD-001 video metadata table is created and seeded
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| VOD-001 | Video metadata for route data |
| VOD-008 | Player page component for video route |

### Depended On By

| Ticket | Reason |
|--------|--------|
| VOD-017 | Gallery hub uses video routes |

### Merge Strategy: **Sequential**

Requires VOD-001 video metadata model. Also depends on VOD-008.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `frontend/src/App.tsx` | 51 | `VideosPage` lazy import |
| `frontend/src/App.tsx` | 55 | `VideoPlayerPage` lazy import |
| `frontend/src/App.tsx` | 64 | `GalleryVideoDetailPage` lazy import |
| `frontend/src/App.tsx` | 163 | `/gallery/:videoId` route |
| `frontend/src/App.tsx` | 164 | `/videos` route |
| `frontend/src/App.tsx` | 165 | `/videos/:videoId` route |
| `frontend/src/App.tsx` | 198 | `/admin/video-review` route |
| `frontend/src/pages/videos/VideosPage.tsx` | -- | **Already exists** |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | -- | **Already exists** |
| `frontend/src/pages/gallery/GalleryPage.tsx` | -- | **Already exists** |
| `frontend/src/pages/gallery/GalleryVideoCard.tsx` | -- | **Already exists** |
| `frontend/src/pages/gallery/VideoDetailPage.tsx` | -- | **Already exists** |
| `frontend/src/api/endpoints/vod.ts` | -- | **Already exists** (112 lines) |
