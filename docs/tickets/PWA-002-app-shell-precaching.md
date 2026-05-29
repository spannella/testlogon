# PWA-002: App Shell Pre-Caching via Service Worker

**Ticket**: PWA-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28
**Depends on**: PWA-001

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The existing service worker (`frontend/public/sw.js`) handles only Web Push notifications.
It registers `push` and `notificationclick` event listeners and explicitly states in its
header comment: "Does NOT handle fetch caching or offline support." Every page navigation
and asset load goes directly to the network. When the user is on a slow connection or
briefly offline, the app displays the browser's default "No Internet" dinosaur page
instead of a meaningful cached shell. On repeat visits, the user re-downloads the same
Vite-hashed JS/CSS bundles that have not changed since the last visit.

Adding a `fetch` event listener with a caching strategy enables:

1. **Instant app shell loading**: HTML, CSS, and JS are served from the Cache API on repeat
   visits, with a background network check for updates.
2. **Pre-caching critical assets**: On service worker install, fetch and cache the HTML
   entry point and the Vite-generated JS/CSS chunks so the first repeat load is instant.
3. **Offline fallback**: When the network is unavailable, the cached app shell loads and
   the app's existing `OfflineBanner` component (in `AppShell.tsx`) informs the user that
   API data will be stale.
4. **Reduced bandwidth**: Hashed Vite assets (`/assets/index-a1b2c3d4.js`) are immutable
   and can be served cache-first forever.

### 1.2 User Stories

1. **As a returning user on a fast connection**, I want the app to load instantly from
   cache while checking for updates in the background, so I do not stare at a blank white
   page.
2. **As a user on a slow/flaky connection**, I want the app shell (header, sidebar,
   navigation) to appear from cache even if API calls are still pending.
3. **As a user who goes offline**, I want the app to show the cached page layout and the
   offline banner instead of the browser's "No Internet" error page.
4. **As a developer**, I want cache versioning so that deploying a new build triggers a
   clean cache sweep of stale assets.

### 1.3 Design Principles

- **Cache-first for immutable assets**: Vite-hashed files (`/assets/*`) are content-
  addressed; once cached they never need revalidation.
- **Network-first for HTML**: The HTML shell (`/index.html`) should always try to fetch
  fresh from the network. Only fall back to cache when offline.
- **Stale-while-revalidate for API responses**: API caching is NOT in scope for PWA-002
  (deferred to PWA-003). The `fetch` listener passes API requests through unchanged.
- **Explicit version string**: A `CACHE_VERSION` constant in `sw.js` is bumped at build
  time. On activate, old cache versions are purged.
- **No Workbox dependency**: The caching logic is small enough to implement in plain
  Service Worker APIs, avoiding a build-tool dependency.

---

## 2. Current State Analysis

### 2.1 `frontend/public/sw.js`

The current service worker (87 lines) handles four events:
<!-- CORRECTED: was "88 lines", actually 87 lines (verified via wc -l) -->

```javascript
// Line 11-13: install
self.addEventListener("install", (event) => {
  self.skipWaiting();
});

// Line 16-18: activate
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Line 21-59: push (show notification)
self.addEventListener("push", (event) => { ... });

// Line 62-82: notificationclick (navigate to URL)
self.addEventListener("notificationclick", (event) => { ... });

// Line 85-87: notificationclose (no-op, future analytics)
self.addEventListener("notificationclose", (event) => { ... });
```
<!-- CORRECTED: push handler ends at line 59, not 58; notificationclose starts at line 85, not 84 -->

Key observations:
- `self.skipWaiting()` on install means new SW versions activate immediately without
  waiting for existing clients to close.
- `self.clients.claim()` on activate means the new SW takes control of all open tabs
  immediately.
- There is **no `fetch` event listener** -- all network requests bypass the SW entirely.

The push handler parses JSON payloads with fields: `title`, `body`, `icon`, `badge`,
`url`, `alert_id`, `alert_type`, `tag`, `timestamp`. The notification click handler
searches for existing app tabs via `self.clients.matchAll()` and either navigates an
existing tab or opens a new one via `self.clients.openWindow()`.

### 2.2 Service Worker Registration (`frontend/src/lib/pushSetup.ts`)

Registration at lines 11-26:
<!-- VERIFIED: pushSetup.ts:11-26 -->

```typescript
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) {
    console.warn("Service workers not supported");
    return null;
  }
  try {
    const registration = await navigator.serviceWorker.register("/sw.js", {
      scope: "/",
    });
    console.log("SW registered:", registration.scope);
    return registration;
  } catch (err) {
    console.error("SW registration failed:", err);
    return null;
  }
}
```

The registration call is in `frontend/src/main.tsx` (lines 31-33):
<!-- VERIFIED: main.tsx:31-33 -->

```typescript
if ("serviceWorker" in navigator) {
  registerServiceWorker();
}
```

No `updatefound` event listener is registered. The SW updates silently via the browser's
standard 24-hour update check. The `registerServiceWorker` function also provides
`subscribeToPush()` and `unsubscribeFromPush()` utilities for push subscription management,
and `urlBase64ToUint8Array()` for VAPID key conversion.

### 2.3 Vite Build Output

Vite produces content-hashed files in `frontend/dist/assets/`:

```
dist/
├── index.html          <- Non-hashed; changes every build
├── favicon.svg         <- Static; changes rarely
├── manifest.json       <- Static (from PWA-001)
├── sw.js               <- Non-hashed; the SW itself
└── assets/
    ├── index-a1b2c3d4.js     <- Main bundle (hashed, immutable)
    ├── index-e5f6g7h8.css    <- Main CSS (hashed, immutable)
    ├── Login-i9j0k1l2.js     <- Lazy-loaded route chunk
    ├── MessagesPage-m3n4o5p6.js
    └── ... (50+ chunks)
```

The `index.html` references these hashed assets:
```html
<script type="module" src="/assets/index-a1b2c3d4.js"></script>
<link rel="stylesheet" href="/assets/index-e5f6g7h8.css" />
```

Because the hashes change with every build, old cache entries become unused after a deploy.
The Vite config (`frontend/vite.config.ts`) outputs to `frontend/dist/` with sourcemaps
enabled (`sourcemap: true`). The `public/` directory contents are copied as-is without
hashing.

### 2.4 Vite Dev Server

In development (`just up`), Vite serves un-hashed files from memory (`/src/main.tsx`,
`/@vite/client`, etc.). The service worker fetch interceptor must NOT interfere with Vite
HMR. In dev mode:

- `/@vite/*` and `/@fs/*` paths are Vite internals.
- WebSocket connections at `ws://localhost:3000/` handle HMR.
- `/src/*` paths are Vite-transformed modules.
- `/@react-refresh` is the React fast-refresh runtime.
- `/node_modules/.vite/*` are pre-bundled dependencies.

The SW must either be skipped in dev mode or its fetch handler must detect dev-mode paths
and pass them through.

### 2.5 Existing Offline Infrastructure

The app already has offline-awareness:

- **`OfflineBanner`** (`frontend/src/components/shared/OfflineBanner.tsx`): Renders a
  yellow banner "You're offline -- actions will be sent when reconnected" with a queue
  count badge. Uses `navigator.onLine` and `window.addEventListener("online"/"offline")`.
  The component reads from `useOfflineStore` for the queue count.
- **`offlineStore`** (`frontend/src/stores/offlineStore.ts`): Zustand store persisted to
  `localStorage` under key `"offline-store"`. Tracks `queue: OfflineAction[]` and
  `isOnline: boolean`. `isOnline` is initialized from `navigator.onLine` (line 42).
  The store defines `OfflineActionSendMessage` and `OfflineActionCreatePost` action types.
  <!-- CORRECTED: was "line 43", actually line 42 of offlineStore.ts -->
- **`useOfflineQueue`** (`frontend/src/hooks/useOfflineQueue.ts`, 96 lines): Mounted in `AppShell`
  via the `OfflineQueueFlusher` component (lines 19-23). Listens for `online`/`offline`
  events (lines 17-27) and flushes queued actions when connectivity returns (lines 30-79).
  Uses a `isFlushing` ref to prevent concurrent flush attempts.
  <!-- CORRECTED: was "97 lines", actually 96 lines; OfflineQueueFlusher is lines 19-23; listeners at lines 17-27, not 18-27; flush at lines 30-79, not 31-79 -->
- **ConversationView** (`frontend/src/pages/messages/ConversationView.tsx`, lines 182-201):
  Listens for `online` + `visibilitychange` events and calls
  `queryClient.invalidateQueries` for `["messages"]` and `["conversations"]` on reconnect.
  <!-- VERIFIED: ConversationView.tsx:182-201 -->

The gap is that none of this infrastructure serves cached HTML/JS when the network is
unavailable -- the browser simply cannot load the app at all when offline.

### 2.6 `frontend/vite.config.ts`

The Vite config (113 lines) uses `@vitejs/plugin-react` and `@tailwindcss/vite` plugins.
<!-- VERIFIED: vite.config.ts is 113 lines -->
The proxy configuration (lines 24-101) routes the following path prefixes to
`http://localhost:8000`:

| Path | Proxy behavior |
|------|---------------|
| `/ui` | Direct proxy |
| `/api` | Direct proxy |
| `/v1` | Direct proxy |
| `/messaging` | Direct proxy |
| `/feed` | Bypass for HTML requests (SPA routing), proxy API calls |
| `/posts` | Direct proxy |
| `/social` | Direct proxy |
| `/uploads` | Direct proxy |
| `/sse` | Direct proxy |
| `/notifications` | Direct proxy |
| `/mock` | Direct proxy |
| `/calendar/public` | Direct proxy |
| `/internal` | Direct proxy |
| `/tickets` | Bypass for HTML, proxy API |
| `/ticket-spaces` | Bypass for HTML, proxy API |
| `/broadcast` | Bypass for HTML, proxy API |
| `/live` | Bypass for HTML, proxy API |
| `/questionnaires` | Bypass for HTML, proxy API |

The SW fetch handler must avoid caching responses for ALL of these proxied API paths.

### 2.7 API Client Request Patterns

The API client (`frontend/src/api/client.ts`, 309 lines) uses `fetch()` with
`credentials: "include"` for all requests.
<!-- CORRECTED: was "310 lines", actually 309 lines --> It attaches `Authorization: Bearer <token>`
headers for authenticated requests and `X-CSRF-Token` headers from the `ui_csrf` cookie.
The client handles 401 responses with automatic session refresh, 403 responses with
geo-blocking detection, and network errors with toast notifications.

The SW fetch handler must NOT interfere with:
- Cookie transmission (`credentials: "include"`)
- Custom headers (Authorization, X-CSRF-Token, X-IMPERSONATION-TOKEN)
- Error handling (the client catches network errors and shows toast)

### 2.8 Google Fonts

The `index.html` preconnects to `fonts.googleapis.com` and `fonts.gstatic.com` and loads
Inter and JetBrains Mono fonts. These are cross-origin requests. The font CSS file returns
`@font-face` declarations pointing to `fonts.gstatic.com` woff2 files. Both the CSS and
the woff2 files have long `Cache-Control` headers set by Google's servers, so the
browser's HTTP cache handles them. The SW should NOT cache these cross-origin font
resources (opaque responses waste cache quota).

---

## 3. Technical Design

### 3.1 Cache Architecture

Three named caches:

| Cache Name | Strategy | Contents |
|------------|----------|----------|
| `app-shell-v{VERSION}` | Network-first, fallback to cache | `index.html`, `manifest.json`, `favicon.svg` |
| `assets-v{VERSION}` | Cache-first (immutable) | `/assets/*` (Vite hashed JS/CSS) |
| `icons-v{VERSION}` | Cache-first | `/icons/*` (PWA-001 icon PNGs) |

API requests (`/ui/*`, `/api/*`, `/messaging/*`, `/feed/*`, `/posts/*`, `/sse/*`,
`/mock/*`, `/internal/*`) are **not cached** by PWA-002. They pass through to the network.

**Cache size estimates**:

| Cache | Typical size | Entry count |
|-------|-------------|-------------|
| `app-shell-v1` | ~50 KB | 3-5 entries |
| `assets-v1` | 5-8 MB | 50-70 entries |
| `icons-v1` | ~500 KB | 15-20 entries |
| **Total** | **~6-9 MB** | **~70-95 entries** |

### 3.2 Service Worker Update Flow

```
                    Browser detects new sw.js
                    (byte-for-byte comparison
                     during 24h update check
                     or on navigation)
                              |
                     +--------v--------+
                     |    install       |
                     | 1. Open caches   |
                     | 2. Pre-cache     |
                     |    critical URLs  |
                     +--------+---------+
                              |
                     skipWaiting()
                              |
                     +--------v--------+
                     |    activate      |
                     | 1. Delete old    |
                     |    cache versions|
                     | 2. clients.claim |
                     +--------+---------+
                              |
                     Ready to intercept
                     fetch events
                              |
                     +--------v--------+
                     |  Notify clients  |
                     |  via postMessage |
                     |  "sw-updated"    |
                     +--------+---------+
                              |
                     UpdateBanner shown
                     in all open tabs
```

### 3.3 Pre-Cache URL List

On `install`, the SW pre-caches a static list of critical URLs:

```javascript
const PRECACHE_URLS = [
  "/",                    // index.html (via navigations)
  "/manifest.json",       // PWA manifest
  "/favicon.svg",         // App icon
  "/icons/icon-192.png",  // PWA icon
  "/icons/icon-512.png",  // PWA icon
];
```

Vite-hashed asset URLs (`/assets/index-*.js`) are NOT pre-cached at install time because
the SW does not know the hashes at build time (the SW is a static file in `public/`). Instead,
hashed assets are cached on first use via the cache-first fetch handler. After the first
page load, all JS/CSS chunks are in the `assets-v{VERSION}` cache and subsequent loads are
instant.

**Alternative (build-time injection)**: A Vite plugin could inject the hashed asset URLs
into `sw.js` at build time. This is deferred as a future optimization. The on-demand
caching approach is simpler and covers the common case (the user has visited the app at
least once before going offline).

**Resilient pre-caching**: Instead of `cache.addAll()` (which fails if ANY URL fails),
use individual `cache.add()` calls with error handling so that a missing icon doesn't
block the entire SW install:

```javascript
async function precacheUrls(cacheName, urls) {
  const cache = await caches.open(cacheName);
  const results = await Promise.allSettled(
    urls.map((url) => cache.add(url))
  );
  const failed = results.filter((r) => r.status === "rejected");
  if (failed.length > 0) {
    console.warn(`[SW] ${failed.length} precache URLs failed:`, failed);
  }
}
```

### 3.4 Fetch Event Handler Logic

```
                        fetch event
                             |
                    +--------v--------+
                    | Non-GET request? |
                    | (POST/PUT/etc)  |
                    +---+----------+--+
                   Yes  |          |  No
                        v          |
                   Pass through    |
                   (no caching)    |
                        |          v
                    +--------v--------+
                    | Is API request? |
                    | (/ui/ /api/     |
                    |  /messaging/..)|
                    +---+----------+--+
                   Yes  |          |  No
                        v          |
                   Pass through    |
                   (PWA-003 scope) |
                        |          v
                    +--------v--------+
                    | Vite dev path?  |
                    | (/@vite/ /src/) |
                    +---+----------+--+
                   Yes  |          |  No
                        v          |
                   Pass through    |
                        |          v
                    +--------v--------+
                    | WebSocket?      |
                    +---+----------+--+
                   Yes  |          |  No
                        v          |
                   Pass through    |
                        |          v
                    +--------v--------+
                    | Match /assets/? |
                    +---+----------+--+
                   Yes  |          |  No
                        v          v
                  Cache-first    +--------+
                  for hashed     | Match   |
                  assets         | /icons/ |
                  (immutable)    | /splash/|
                                 +---+-----+
                                Yes  |  No
                                     v     v
                            Cache-first    +--------+
                            for icons      | Is it a |
                                           | navigation|
                                           | request?  |
                                           +---+------+
                                          Yes  |  No
                                               v     v
                                      Network-first  Network only
                                      for HTML       (fonts, etc)
                                      (fallback to
                                       cached shell)
```

### 3.5 Updated `sw.js` Structure

```javascript
/* sw.js -- Service Worker (PLATFORM-010 + PWA-002)
 *
 * Handles:
 * - install: Pre-cache app shell + skip waiting
 * - activate: Purge old caches + claim clients
 * - fetch: Cache-first for assets, network-first for HTML, passthrough for API
 * - push: Show native browser notification
 * - notificationclick: Focus/open app tab
 * - notificationclose: Future analytics
 */

// ─── Cache versioning ─────────────────────────────────────────────
const CACHE_VERSION = 1;
const SHELL_CACHE  = `app-shell-v${CACHE_VERSION}`;
const ASSETS_CACHE = `assets-v${CACHE_VERSION}`;
const ICONS_CACHE  = `icons-v${CACHE_VERSION}`;
const VALID_CACHES = new Set([SHELL_CACHE, ASSETS_CACHE, ICONS_CACHE]);

const PRECACHE_URLS = [
  "/",
  "/manifest.json",
  "/favicon.svg",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

// ─── API / Backend paths that must NEVER be cached ──────────────
const API_PATH_PREFIXES = [
  "/ui/", "/api/", "/v1/", "/messaging/", "/feed/", "/posts/",
  "/social/", "/uploads/", "/sse/", "/notifications/", "/mock/",
  "/calendar/public/", "/internal/", "/tickets/", "/ticket-spaces/",
  "/broadcast/", "/helpdesk/", "/booking/", "/live/",
  "/questionnaires/", "/telemetry/",
];

/**
 * Check if a URL is an API/backend request that should never be cached.
 * Uses a Set-based prefix check for O(n) worst case but fast in practice
 * since the list is small and checked in order of frequency.
 */
function isApiRequest(url) {
  const path = new URL(url).pathname;
  return API_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

/**
 * Check if a URL is a Vite dev-server internal request.
 * These paths only exist during development (vite dev server) and must
 * never be cached -- they are ephemeral in-memory transforms.
 */
function isViteDevRequest(url) {
  const path = new URL(url).pathname;
  return path.startsWith("/@") || path.startsWith("/src/")
      || path.startsWith("/node_modules/");
}

/**
 * Check if a URL is a cross-origin request (fonts, analytics, etc.).
 * Cross-origin requests return opaque responses which waste cache quota.
 */
function isCrossOrigin(url) {
  return new URL(url).origin !== self.location.origin;
}

// ─── Install ─────────────────────────────────────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(SHELL_CACHE);
      // Use allSettled instead of addAll to tolerate individual failures
      const results = await Promise.allSettled(
        PRECACHE_URLS.map((url) => cache.add(url))
      );
      const failed = results.filter((r) => r.status === "rejected");
      if (failed.length > 0) {
        console.warn("[SW] Precache partial failure:", failed.length, "URLs failed");
      }
    })()
  );
  self.skipWaiting();
});

// ─── Activate ────────────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Delete all caches that don't match the current version
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((key) => !VALID_CACHES.has(key))
          .map((key) => {
            console.log("[SW] Deleting old cache:", key);
            return caches.delete(key);
          })
      );

      // Claim all clients immediately
      await self.clients.claim();

      // Notify all clients about the update
      const clients = await self.clients.matchAll({ type: "window" });
      for (const client of clients) {
        client.postMessage({ type: "sw-updated", version: CACHE_VERSION });
      }
    })()
  );
});

// ─── Fetch ───────────────────────────────────────────────────────
self.addEventListener("fetch", (event) => {
  const { request } = event;

  // Skip non-GET requests (POST, PUT, DELETE, etc.)
  if (request.method !== "GET") return;

  // Skip API requests -- handled by PWA-003 (offline read cache)
  if (isApiRequest(request.url)) return;

  // Skip Vite dev-server internal requests
  if (isViteDevRequest(request.url)) return;

  // Skip WebSocket upgrade requests
  if (request.headers.get("upgrade") === "websocket") return;

  // Skip cross-origin requests (fonts, analytics)
  if (isCrossOrigin(request.url)) return;

  const url = new URL(request.url);

  // ── Hashed assets: cache-first (immutable) ──
  if (url.pathname.startsWith("/assets/")) {
    event.respondWith(cacheFirst(request, ASSETS_CACHE));
    return;
  }

  // ── Icons + splash screens: cache-first ──
  if (url.pathname.startsWith("/icons/") || url.pathname.startsWith("/splash/")
      || url.pathname.startsWith("/screenshots/")) {
    event.respondWith(cacheFirst(request, ICONS_CACHE));
    return;
  }

  // ── Navigation (HTML) + shell files: network-first ──
  if (request.mode === "navigate" || PRECACHE_URLS.includes(url.pathname)) {
    event.respondWith(networkFirst(request, SHELL_CACHE));
    return;
  }

  // ── Everything else: network only ──
  // (third-party scripts, sourcemaps, etc.)
});

/**
 * Cache-first strategy: serve from cache if available, fetch from network
 * if not and cache the response for next time.
 */
async function cacheFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) {
    return cached;
  }

  try {
    const response = await fetch(request);
    if (response.ok) {
      // Clone the response before caching (response body can only be read once)
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    // Network failed and no cache -- return a 503
    return new Response("Offline — resource not cached", {
      status: 503,
      statusText: "Service Unavailable",
      headers: { "Content-Type": "text/plain" },
    });
  }
}

/**
 * Network-first strategy: try the network, update cache on success,
 * fall back to cache on network failure.
 */
async function networkFirst(request, cacheName) {
  const cache = await caches.open(cacheName);

  try {
    const response = await fetch(request);
    if (response.ok) {
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    // Network failed -- try cache
    const cached = await cache.match(request);
    if (cached) {
      return cached;
    }

    // No cache for this specific URL -- try the root as SPA fallback
    if (request.mode === "navigate") {
      const fallback = await cache.match("/");
      if (fallback) {
        return fallback;
      }
    }

    return new Response("Offline", {
      status: 503,
      statusText: "Service Unavailable",
      headers: { "Content-Type": "text/plain" },
    });
  }
}

// ─── Push + Notification handlers (unchanged from PLATFORM-010) ──

// Handle incoming push notification
self.addEventListener("push", (event) => {
  if (!event.data) {
    event.waitUntil(
      self.registration.showNotification("New notification", {
        body: "You have a new notification",
        icon: "/favicon.svg",
        badge: "/favicon.svg",
      })
    );
    return;
  }

  let payload;
  try {
    payload = event.data.json();
  } catch (e) {
    payload = { title: "Notification", body: event.data.text() };
  }

  const title = payload.title || "Notification";
  const options = {
    body: payload.body || "",
    icon: payload.icon || "/favicon.svg",
    badge: payload.badge || "/favicon.svg",
    data: {
      url: payload.url || "/",
      alertId: payload.alert_id || "",
      alertType: payload.alert_type || "",
    },
    tag: payload.tag || payload.alert_type || "default",
    renotify: !!payload.tag,
    timestamp: payload.timestamp
      ? new Date(payload.timestamp * 1000).getTime()
      : Date.now(),
    silent: false,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// Handle notification click -- navigate to the relevant page
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const url = event.notification.data?.url || "/";
  const fullUrl = new URL(url, self.location.origin).href;

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if (client.url.startsWith(self.location.origin) && "focus" in client) {
            return client.navigate(fullUrl).then(() => client.focus());
          }
        }
        return self.clients.openWindow(fullUrl);
      })
  );
});

// Handle notification close (analytics, optional)
self.addEventListener("notificationclose", (event) => {
  // Future: track notification dismissal rate
});
```

### 3.6 Cache Versioning and Cleanup

When `CACHE_VERSION` is incremented (in a new deploy):

1. The browser detects the new `sw.js` (byte-for-byte comparison).
2. `install` fires: new caches (`app-shell-v2`, `assets-v2`, `icons-v2`) are created and
   pre-populated.
3. `activate` fires: the `VALID_CACHES` set only contains `v2` names, so `v1` caches
   are deleted via `caches.delete()`.

This ensures stale assets from previous builds are cleaned up.

**Detailed cache lifecycle**:

```
Deploy v1:
  install: create app-shell-v1, assets-v1, icons-v1
  activate: delete nothing (no old caches)
  running: cache assets on first load

Deploy v2 (bump CACHE_VERSION to 2):
  install: create app-shell-v2, assets-v2, icons-v2
           (v1 caches still exist at this point)
  activate: VALID_CACHES = {app-shell-v2, assets-v2, icons-v2}
            delete app-shell-v1, assets-v1, icons-v1
  running: fresh caches, old assets gone
```

### 3.7 Build-Time Version Injection

Create a Vite plugin that replaces `CACHE_VERSION` in `sw.js` at build time:

```typescript
// frontend/vite-plugin-sw-version.ts
import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import type { Plugin } from "vite";

export function swVersionPlugin(): Plugin {
  return {
    name: "sw-version-inject",
    apply: "build",
    closeBundle() {
      const swPath = join(__dirname, "dist", "sw.js");
      const timestamp = Date.now();
      let content = readFileSync(swPath, "utf-8");
      content = content.replace(
        /const CACHE_VERSION = \d+;/,
        `const CACHE_VERSION = ${timestamp};`,
      );
      writeFileSync(swPath, content);
      console.log(`[sw-version] Injected CACHE_VERSION = ${timestamp}`);
    },
  };
}
```

Add to `vite.config.ts`:

```typescript
import { swVersionPlugin } from "./vite-plugin-sw-version";

export default defineConfig({
  plugins: [react(), tailwindcss(), swVersionPlugin()],
  // ...
});
```

This is optional for the initial implementation -- manual version bumping is sufficient
for the first iteration. The plugin automates it for CI/CD builds.

### 3.8 Update Notification

When the SW detects a new version, notify the user so they can refresh.

**Service worker side** (in `sw.js` activate handler, shown above):
```javascript
// Notify all clients about the update
const clients = await self.clients.matchAll({ type: "window" });
for (const client of clients) {
  client.postMessage({ type: "sw-updated", version: CACHE_VERSION });
}
```

**Main thread listener** -- Add to `frontend/src/lib/pushSetup.ts`:

```typescript
/**
 * Listen for service worker update events.
 * When a new SW version activates, it sends a "sw-updated" message.
 * This function dispatches a custom event so the UpdateBanner can react.
 *
 * Also listens for the standard `updatefound` event on the registration
 * to provide early notification that an update is downloading.
 */
export function listenForSwUpdate(registration: ServiceWorkerRegistration): void {
  // Listen for the SW's postMessage
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.addEventListener("message", (event) => {
      if (event.data?.type === "sw-updated") {
        window.dispatchEvent(
          new CustomEvent("sw-updated", {
            detail: { version: event.data.version },
          }),
        );
      }
    });
  }

  // Also listen for the standard updatefound event
  registration.addEventListener("updatefound", () => {
    const newWorker = registration.installing;
    if (!newWorker) return;

    newWorker.addEventListener("statechange", () => {
      if (
        newWorker.state === "activated" &&
        navigator.serviceWorker.controller
      ) {
        // New SW has taken over -- the postMessage above will also fire,
        // but this provides a backup notification path.
        window.dispatchEvent(new CustomEvent("sw-updated"));
      }
    });
  });
}
```

**Update `main.tsx`** to wire the listener:

```typescript
// In main.tsx, replace the simple registration call:
if ("serviceWorker" in navigator) {
  registerServiceWorker().then((registration) => {
    if (registration) {
      listenForSwUpdate(registration);
    }
  });
}
```

**Create `frontend/src/components/shared/UpdateBanner.tsx`**:

```typescript
import { useState, useEffect, useCallback } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * Banner shown when a new service worker version is activated.
 * Prompts the user to reload to pick up the latest code.
 *
 * Rendered in AppShell alongside OfflineBanner. The banner is
 * non-dismissible (the only action is "Refresh") because running
 * old JS against a new SW can cause cache inconsistencies.
 */
export function UpdateBanner() {
  const [showUpdate, setShowUpdate] = useState(false);

  useEffect(() => {
    const handler = () => setShowUpdate(true);
    window.addEventListener("sw-updated", handler);
    return () => window.removeEventListener("sw-updated", handler);
  }, []);

  const handleRefresh = useCallback(() => {
    // Hard reload to ensure the new SW serves fresh assets
    window.location.reload();
  }, []);

  if (!showUpdate) return null;

  return (
    <div
      className="flex w-full items-center justify-center gap-2 bg-blue-500 px-4 py-2 text-white text-sm font-medium animate-in slide-in-from-top duration-200"
      role="alert"
      aria-live="polite"
    >
      <RefreshCw className="h-4 w-4 animate-spin-slow" aria-hidden />
      <span>A new version is available.</span>
      <Button
        size="sm"
        variant="secondary"
        onClick={handleRefresh}
        className="h-7 px-3 text-xs font-semibold"
      >
        Refresh
      </Button>
    </div>
  );
}
```

**Render in `AppShell.tsx`** alongside `OfflineBanner`:

```typescript
import { UpdateBanner } from "@/components/shared/UpdateBanner";

// In the JSX (after OfflineBanner, before InstallPrompt):
<OfflineBanner />
<UpdateBanner />
<InstallPrompt />
<IOSInstallHint />
<OfflineQueueFlusher />
<Header onMobileMenuToggle={() => setMobileMenuOpen(true)} />
```

### 3.9 SPA Navigation Fallback

For the network-first HTML strategy, the `networkFirst` function includes an SPA fallback:
when the user navigates to `/messages` or `/calendar` while offline, and the exact URL
is not cached, the function falls back to returning the cached `/` (root index.html).
Since the app is a single-page application, the same HTML serves all routes -- React
Router handles the URL interpretation client-side.

This is important because:
- The user might be on `/messages/abc123` (a deep link) when going offline
- The cache only has `/` (the root navigation)
- Returning the cached root HTML lets React Router render the `/messages/abc123` route
- The API calls for that route will fail (handled by PWA-003), but the app shell loads

### 3.10 Cache Inspection Utilities

For debugging, add helper functions to the SW:

```javascript
/**
 * Debug helper: list all cache contents. Call from DevTools console:
 *   navigator.serviceWorker.controller.postMessage({ type: "list-caches" })
 */
self.addEventListener("message", async (event) => {
  if (event.data?.type === "list-caches") {
    const keys = await caches.keys();
    const details = {};
    for (const key of keys) {
      const cache = await caches.open(key);
      const requests = await cache.keys();
      details[key] = requests.map((r) => new URL(r.url).pathname);
    }
    event.source?.postMessage({ type: "cache-contents", caches: details });
  }

  if (event.data?.type === "clear-all-caches") {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => caches.delete(k)));
    event.source?.postMessage({ type: "caches-cleared" });
  }
});
```

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/UpdateBanner.tsx` | "New version available" banner |
| `frontend/vite-plugin-sw-version.ts` | Build-time CACHE_VERSION injection (optional) |

### 4.2 Modified Files

| File | Changes |
|------|---------|
| `frontend/public/sw.js` | Add fetch handler, cache constants, pre-cache logic, cache inspection message handler |
| `frontend/src/lib/pushSetup.ts` | Add `listenForSwUpdate()` function |
| `frontend/src/main.tsx` | Call `listenForSwUpdate()` after registration; change registration to async |
| `frontend/src/components/layout/AppShell.tsx` | Add `<UpdateBanner />` |
| `frontend/vite.config.ts` | Optionally add `swVersionPlugin()` |

### 4.3 Implementation Phases

1. **Phase 1 -- Fetch handler + cache-first assets** (2 hours)
   - Add `CACHE_VERSION`, cache name constants, `PRECACHE_URLS` to `sw.js`
   - Implement `isApiRequest()`, `isViteDevRequest()`, `isCrossOrigin()` guards
   - Implement `cacheFirst()` and `networkFirst()` helper functions
   - Add the `fetch` event listener with asset/navigation strategies
   - Update `install` event to pre-cache URLs with resilient `Promise.allSettled`
   - Update `activate` event to purge old caches

2. **Phase 2 -- Cache versioning + cleanup** (1 hour)
   - Test that incrementing `CACHE_VERSION` purges old caches on activate
   - Verify hashed assets are cached on first load and served from cache on reload
   - Verify HTML falls back to cache when network is unavailable
   - Test SPA navigation fallback (deep link while offline returns root HTML)

3. **Phase 3 -- Update notification** (1.5 hours)
   - Add `listenForSwUpdate()` to `pushSetup.ts`
   - Add SW postMessage handler in activate event
   - Create `UpdateBanner` component
   - Wire into `AppShell` and `main.tsx`
   - Test update flow: change `CACHE_VERSION`, verify banner appears

4. **Phase 4 -- Dev mode safeguards** (30 min)
   - Verify Vite HMR WebSocket is not intercepted
   - Verify `/@vite/*`, `/@fs/*`, `/src/*` requests pass through
   - Verify `/@react-refresh` is not cached
   - Verify `/node_modules/.vite/*` passes through
   - Add `console.log` breadcrumbs in fetch handler for debugging

5. **Phase 5 -- Build-time version injection** (30 min, optional)
   - Create `vite-plugin-sw-version.ts`
   - Add to `vite.config.ts`
   - Test: build, verify CACHE_VERSION is a timestamp

---

## 5. Testing Strategy

### 5.1 E2E Test Plan (`frontend/e2e/pwa-caching.spec.ts`)

**Section 93: Service Worker Fetch Interception (5 tests)**

```typescript
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers";

test.describe("93 . Service worker fetch interception", () => {
  test("93.1 service worker is registered with scope /", async ({ page }) => {
    await page.goto("/");
    const swScope = await page.evaluate(async () => {
      const reg = await navigator.serviceWorker.ready;
      return reg.scope;
    });
    expect(swScope).toContain("/");
  });

  test("93.2 hashed assets are served from cache on reload", async ({ page }) => {
    // First load: assets are fetched from network and cached
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Find a hashed asset URL from the page
    const assetUrl = await page.evaluate(() => {
      const scripts = document.querySelectorAll('script[src*="/assets/"]');
      return scripts[0]?.getAttribute("src") || null;
    });
    expect(assetUrl).toBeTruthy();

    // Verify it's now in the cache
    const isCached = await page.evaluate(async (url) => {
      const cache = await caches.open("assets-v1");
      const match = await cache.match(url!);
      return !!match;
    }, assetUrl);
    expect(isCached).toBe(true);
  });

  test("93.3 navigation to / returns cached HTML when offline", async ({ page, context }) => {
    // Load the page to populate cache
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Simulate offline
    await context.setOffline(true);

    // Navigate -- should get cached HTML
    const response = await page.goto("/");
    expect(response?.status()).not.toBe(503);

    // The page should render (React mounts from cached JS)
    await page.waitForSelector("#root", { timeout: 5000 });

    // Restore
    await context.setOffline(false);
  });

  test("93.4 deep link while offline falls back to root HTML", async ({ page, context }) => {
    // Load root to populate cache
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Go offline
    await context.setOffline(true);

    // Navigate to a deep link
    const response = await page.goto("/messages");
    // Should not be a 503 -- the SPA fallback should serve cached root HTML
    expect(response?.status()).not.toBe(503);

    await context.setOffline(false);
  });

  test("93.5 API requests are not cached by the service worker", async ({ page, context }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    // Go offline and try to fetch conversations API
    await context.setOffline(true);
    const result = await page.evaluate(async () => {
      try {
        const resp = await fetch("/messaging/conversations");
        return { ok: resp.ok, status: resp.status };
      } catch {
        return { ok: false, status: 0 };
      }
    });

    // API call should fail (not served from SW cache)
    expect(result.ok).toBe(false);
    await context.setOffline(false);
  });
});
```

**Section 94: Cache Versioning (4 tests)**

```typescript
test.describe("94 . Cache versioning", () => {
  test("94.1 caches exist with version suffix", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const cacheNames = await page.evaluate(async () => {
      return await caches.keys();
    });

    const versionPattern = /v\d+$/;
    const swCaches = cacheNames.filter(
      (name) =>
        name.startsWith("app-shell-") ||
        name.startsWith("assets-") ||
        name.startsWith("icons-"),
    );

    expect(swCaches.length).toBeGreaterThan(0);
    for (const name of swCaches) {
      expect(name).toMatch(versionPattern);
    }
  });

  test("94.2 precache URLs are in the shell cache", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const hasCachedRoot = await page.evaluate(async () => {
      const cacheNames = await caches.keys();
      const shellCache = cacheNames.find((n) => n.startsWith("app-shell-"));
      if (!shellCache) return false;
      const cache = await caches.open(shellCache);
      const keys = await cache.keys();
      return keys.some((r) => new URL(r.url).pathname === "/");
    });
    expect(hasCachedRoot).toBe(true);
  });

  test("94.3 manifest.json is in the shell cache", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const hasCachedManifest = await page.evaluate(async () => {
      const cacheNames = await caches.keys();
      const shellCache = cacheNames.find((n) => n.startsWith("app-shell-"));
      if (!shellCache) return false;
      const cache = await caches.open(shellCache);
      const keys = await cache.keys();
      return keys.some((r) => new URL(r.url).pathname === "/manifest.json");
    });
    expect(hasCachedManifest).toBe(true);
  });

  test("94.4 Vite dev paths are not cached", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const hasViteCache = await page.evaluate(async () => {
      const allKeys = await caches.keys();
      for (const name of allKeys) {
        const cache = await caches.open(name);
        const requests = await cache.keys();
        for (const req of requests) {
          const path = new URL(req.url).pathname;
          if (path.startsWith("/@") || path.startsWith("/src/") || path.startsWith("/node_modules/")) {
            return true;
          }
        }
      }
      return false;
    });
    expect(hasViteCache).toBe(false);
  });
});
```

**Section 95: Update Banner (4 tests)**

```typescript
test.describe("95 . Update banner", () => {
  test("95.1 update banner appears when SW sends sw-updated message", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");

    // Simulate sw-updated event
    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent("sw-updated"));
    });

    await expect(page.getByText(/new version is available/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /refresh/i })).toBeVisible();
  });

  test("95.2 update banner is not shown without the event", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");
    await page.waitForTimeout(2000);

    await expect(page.getByText(/new version is available/i)).not.toBeVisible();
  });

  test("95.3 clicking Refresh reloads the page", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");

    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent("sw-updated"));
    });

    const [response] = await Promise.all([
      page.waitForNavigation(),
      page.getByRole("button", { name: /refresh/i }).click(),
    ]);
    expect(response).toBeTruthy();
  });

  test("95.4 update banner has correct ARIA attributes", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");

    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent("sw-updated"));
    });

    const banner = page.locator('[role="alert"]').filter({ hasText: /new version/i });
    await expect(banner).toBeVisible();
    await expect(banner).toHaveAttribute("aria-live", "polite");
  });
});
```

### 5.2 Manual Test Checklist

- [ ] Load app, check DevTools > Application > Cache Storage: `app-shell-v1`, `assets-v1`,
  `icons-v1` exist.
- [ ] Reload with DevTools Network tab open: hashed assets show "(ServiceWorker)" source.
- [ ] Toggle offline in DevTools > Network: reload shows cached app shell + OfflineBanner.
- [ ] Navigate to `/messages` while offline: app shell loads, API shows errors.
- [ ] Update `CACHE_VERSION` in `sw.js`, reload: UpdateBanner appears.
- [ ] After UpdateBanner refresh: old caches are gone; new caches created.
- [ ] Vite HMR still works in dev mode (edit a component, see hot update).
- [ ] WebSocket for SSE events is not intercepted by SW.
- [ ] `page.request.post()` for API calls is not intercepted by SW.
- [ ] Google Fonts still load (not blocked by SW cross-origin check).

---

## 6. Edge Cases & Gotchas

### 6.1 Vite Dev Mode vs. Production

In dev mode, Vite serves un-built files from memory. The SW's fetch handler will encounter
paths like `/src/main.tsx`, `/@vite/client`, and `/@react-refresh`. The `isViteDevRequest()`
guard ensures these are not cached. Without this guard, the SW would cache the
Vite-transformed source files which are ephemeral and would cause stale module errors.

**Full list of Vite dev paths to exclude**:
- `/@vite/client` -- HMR client
- `/@react-refresh` -- React fast-refresh runtime
- `/@fs/...` -- direct filesystem access
- `/@id/...` -- module ID resolution
- `/src/...` -- source file transforms
- `/node_modules/.vite/...` -- pre-bundled dependencies

### 6.2 `skipWaiting()` and Consistency

The current `sw.js` calls `self.skipWaiting()` on install, meaning a new SW version
activates immediately. This can cause a brief inconsistency where the page was loaded with
old JS but the new SW is now intercepting fetches with a new `CACHE_VERSION`. The
`UpdateBanner` component mitigates this by prompting the user to refresh.

A safer alternative is to NOT call `skipWaiting()` and instead use `clients.claim()` only
on activate, letting the old SW serve the current session and the new SW take over on next
visit. However, this conflicts with the existing push notification behavior which relies on
immediate activation. We keep `skipWaiting()` for backward compatibility and use the
UpdateBanner to prompt a full reload.

### 6.3 Opaque Responses (Third-Party Fonts)

Google Fonts (`fonts.googleapis.com`) returns CSS that references font files on
`fonts.gstatic.com`. These are cross-origin requests and the SW receives opaque responses
(status 0). Caching opaque responses is allowed but each one consumes ~7MB of cache quota
in some browsers. The `isCrossOrigin()` guard in the fetch handler ensures cross-origin
requests pass through without caching. Google's servers set long `Cache-Control` headers
on font files, so the browser's HTTP cache handles them efficiently.

### 6.4 Large Cache Size

The Vite build for this app produces 50+ JS chunks plus CSS. Total size is approximately
5-8 MB. The Cache API quota varies by browser:
- Chrome: 60% of available disk space per origin (typically 10+ GB)
- Firefox: 50% of available disk space per origin
- Safari: 1 GB per origin (with user prompt after ~50 MB for some versions)

8 MB is well within limits. However, without old-cache cleanup, multiple deploys could
accumulate stale caches. The `activate` cleanup handler prevents this.

### 6.5 Service Worker Scope Conflict

The manifest's `scope` (from PWA-001) and the SW's registration scope are both `/`. This
is correct -- the SW controls all requests within its scope, and the manifest defines the
PWA's navigation scope. They must match.

### 6.6 Precache Failures

If any URL in `PRECACHE_URLS` fails to fetch during install (e.g., `/icons/icon-192.png`
does not exist yet because PWA-001 hasn't been deployed), the resilient
`Promise.allSettled()` approach logs a warning but allows the SW to install successfully.
The failed URLs will be cached on next access via the fetch handler.

### 6.7 SSE Connections

The app uses Server-Sent Events via `/sse/*` paths for real-time messaging updates
(see `useMessagingStream.ts`). SSE connections use `EventSource` which sends GET requests
with `Accept: text/event-stream`. The `isApiRequest()` guard catches `/sse/` paths and
passes them through. Even if the SSE path were not in the API list, the response would be
a streaming response that the Cache API cannot meaningfully store.

### 6.8 Sourcemaps

Vite generates `.map` files alongside JS bundles (e.g., `/assets/index-a1b2c3d4.js.map`).
These are fetched by browser DevTools, not by the page. The cache-first handler for
`/assets/*` would cache sourcemaps, which is unnecessary but harmless (they are hashed
and immutable). Optionally, the fetch handler could check `url.pathname.endsWith(".map")`
and skip caching, but the additional complexity is not worth it.

### 6.9 Service Worker Cache vs. HTTP Cache

The browser has two layers of caching:
1. **HTTP cache**: Controlled by `Cache-Control` headers from the server
2. **Service Worker cache**: The Cache API, managed by our fetch handler

For hashed Vite assets, both caches store the same content. The SW cache takes priority
(the SW intercepts before the HTTP cache is consulted). For non-hashed files (`index.html`,
`manifest.json`), the SW uses network-first, which bypasses the HTTP cache.

The CDN/server should set appropriate headers:
- `Cache-Control: public, max-age=31536000, immutable` for `/assets/*` (hashed files)
- `Cache-Control: no-cache` for `sw.js`, `index.html`, `manifest.json` (unhashed files)

---

## 7. Security Considerations

### 7.1 Cache Poisoning

The fetch handler only caches responses from the same origin (`self.location.origin`).
Cross-origin requests fall through to the network via the `isCrossOrigin()` guard. The
API path guard (`isApiRequest()`) ensures that auth-sensitive API responses are never
stored in the Cache API (API caching with proper auth token scoping is deferred to
PWA-003).

### 7.2 Sensitive Data in Cached HTML

The cached `index.html` is the same static file served to all users. It contains no
user-specific data -- authentication state is managed by cookies and the `authStore`
(localStorage). Caching `index.html` does not leak sensitive information.

### 7.3 Service Worker Update Integrity

In production, `sw.js` should be served with `Cache-Control: no-cache` (or
`max-age=0`) so the browser always checks for updates. Vite's production build does not
hash `sw.js` (it is in `public/`), so the CDN/server must set appropriate cache headers.
If `sw.js` is cached by the CDN with a long TTL, users would not receive SW updates.

### 7.4 CSRF Token in Cached Responses

The CSRF token is set via a cookie (`ui_csrf`), not embedded in the HTML. Caching the HTML
does not affect CSRF protection -- the cookie is always fresh from the last server
interaction.

### 7.5 Cache Inspection Debug Commands

The `list-caches` and `clear-all-caches` message handlers (section 3.10) are debug
utilities accessible only from the same origin via `postMessage`. They do not expose
data to cross-origin scripts. In production, these handlers could be gated behind a
`DEV_MODE` check, but since they only operate on the origin's own cache, the security
risk is negligible.

---

## Appendix A: File Reference

| Existing File | Relevance |
|---------------|-----------|
| `frontend/public/sw.js` | The service worker file to extend |
| `frontend/src/lib/pushSetup.ts` | SW registration + push subscription helpers |
| `frontend/src/main.tsx` | Calls `registerServiceWorker()` at boot |
| `frontend/src/components/layout/AppShell.tsx` | Renders `OfflineBanner`; will render `UpdateBanner` |
| `frontend/src/components/shared/OfflineBanner.tsx` | Existing offline UI; pattern for UpdateBanner |
| `frontend/src/stores/offlineStore.ts` | Zustand store tracking `isOnline` state |
| `frontend/src/hooks/useOfflineQueue.ts` | Queue flush on reconnect |
| `frontend/vite.config.ts` | Proxy config; confirms API paths to exclude |
| `frontend/index.html` | Entry HTML; links to hashed assets |
| `frontend/src/api/client.ts` | API client with fetch(); confirms credentials: include usage |
| `frontend/src/hooks/useMessagingStream.ts` | SSE connection; confirms /sse/ paths |

## Appendix B: Dependencies & Risks

| Risk | Mitigation |
|------|------------|
| SW caches stale Vite dev files | `isViteDevRequest()` guard skips all `/@*`, `/src/*`, `/node_modules/` paths |
| Precache fails if PWA-001 icons missing | `Promise.allSettled()` allows partial precache success |
| New SW version causes asset mismatch | UpdateBanner prompts user to refresh |
| Opaque cross-origin responses waste cache quota | `isCrossOrigin()` guard passes cross-origin requests through |
| SW update not detected for 24+ hours | Browser checks every 24h by default; can force via `registration.update()` on focus |
| Multiple tabs with different SW versions | `skipWaiting()` + `clients.claim()` ensures all tabs use new SW immediately |
| SSE connections intercepted by SW | `isApiRequest()` catches `/sse/` prefix; SSE responses are streaming and not cacheable |
| Sourcemaps inflate cache size | Harmless; sourcemaps are hashed and immutable; total cache remains under 10 MB |
| CDN caches sw.js with long TTL | Production deployment must set `Cache-Control: no-cache` for sw.js |
| Cache API unavailable in some contexts | `caches.open()` throws in some private browsing modes; SW catches and passes through |

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `sw.js` (service worker) | `frontend/public/sw.js` | 576 lines | **ALREADY IMPLEMENTED** — has install (precache), activate (purge old caches), fetch (cache-first for assets, network-first for HTML, passthrough for API), and message handlers |
| `registerServiceWorker()` | `frontend/src/lib/pushSetup.ts` | 11 | **Verified** (126 lines total) |
| `listenForSwUpdate()` | `frontend/src/lib/pushSetup.ts` | — | **Exists** — imported and called in `main.tsx:29` |
| SW registration + update listener | `frontend/src/main.tsx` | 29-34 | **Verified** |
| `OfflineBanner` | `frontend/src/components/shared/OfflineBanner.tsx` | 45 lines | **Exists** |
| `offlineStore` | `frontend/src/stores/offlineStore.ts` | 213 lines | **Exists** — Zustand store |
| `useOfflineQueue` hook | `frontend/src/hooks/useOfflineQueue.ts` | 133 lines | **Exists** |
| Vite config | `frontend/vite.config.ts` | — | **Exists** |
| API client | `frontend/src/api/client.ts` | 309 lines | **Exists** |
| `ConversationView` SSE refetch | `frontend/src/pages/messages/ConversationView.tsx` | — | **Exists** (1461 lines) |

### Key Correction

**This ticket appears to be ALREADY IMPLEMENTED.** The service worker (`sw.js`, 576 lines) already has: precache URLs on install, old cache purge on activate, fetch interception with cache-first for static assets / network-first for HTML / passthrough for API routes, SKIP_WAITING message handler, and cache inspection/clearing. The `listenForSwUpdate` function exists in `pushSetup.ts`. Verify whether an UpdateBanner component and version injection also exist before scoping remaining work.
