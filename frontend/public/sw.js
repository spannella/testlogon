/* sw.js -- Service Worker (PLATFORM-010 + PWA-002)
 *
 * Handles:
 * - install: Pre-cache app shell + skip waiting
 * - activate: Purge old caches + claim clients
 * - fetch: Cache-first for assets, network-first for HTML, passthrough for API
 * - push: Show native browser notification
 * - notificationclick: Focus/open app tab
 * - notificationclose: Future analytics
 * - message: SKIP_WAITING, list-caches, clear-all-caches
 */

// ─── Cache versioning ─────────────────────────────────────────────
const CACHE_VERSION = 1;
const SHELL_CACHE  = `app-shell-v${CACHE_VERSION}`;
const ASSETS_CACHE = `assets-v${CACHE_VERSION}`;
const ICONS_CACHE  = `icons-v${CACHE_VERSION}`;
const IMAGE_CACHE  = `images-v${CACHE_VERSION}`;
const MAX_IMAGE_CACHE_ENTRIES = 200;
const VALID_CACHES = new Set([SHELL_CACHE, ASSETS_CACHE, ICONS_CACHE, IMAGE_CACHE]);

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

// Single-path API routes (exact match or startsWith for paths without trailing /)
const API_EXACT_PATHS = [
  "/openapi.json", "/docs", "/redoc", "/ws",
];

/**
 * Check if a URL is an API/backend request that should never be cached.
 */
function isApiRequest(url) {
  const path = new URL(url).pathname;
  if (API_PATH_PREFIXES.some((prefix) => path.startsWith(prefix))) return true;
  if (API_EXACT_PATHS.some((p) => path === p || path.startsWith(p + "/"))) return true;
  return false;
}

/**
 * Check if a URL is a Vite dev-server internal request.
 * These paths only exist during development and must never be cached.
 */
function isViteDevRequest(url) {
  const path = new URL(url).pathname;
  return (
    path.startsWith("/@vite/") ||
    path.startsWith("/@fs/") ||
    path.startsWith("/@id/") ||
    path.startsWith("/@react-refresh") ||
    path === "/__vite_ping" ||
    path.startsWith("/src/") ||
    path.startsWith("/node_modules/.vite/") ||
    path.startsWith("/node_modules/")
  );
}

/**
 * Check if a URL is a cross-origin request (fonts, analytics, etc.).
 * Cross-origin requests return opaque responses which waste cache quota.
 */
function isCrossOrigin(url, location) {
  return new URL(url).origin !== location.origin;
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

  // ── Image cache: cache-first for /mock/s3/ and /uploads/ paths (PWA-003) ──
  const urlObj = new URL(request.url);
  if (urlObj.pathname.startsWith("/mock/s3/") || urlObj.pathname.startsWith("/uploads/")) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(IMAGE_CACHE);
        const cached = await cache.match(request);
        if (cached) return cached;

        try {
          const response = await fetch(request);
          if (response.ok) {
            const clone = response.clone();
            cache.put(request, clone);

            // Evict oldest if over limit (LRU approximation)
            const keys = await cache.keys();
            if (keys.length > MAX_IMAGE_CACHE_ENTRIES) {
              const excess = keys.length - MAX_IMAGE_CACHE_ENTRIES;
              for (let i = 0; i < excess; i++) {
                await cache.delete(keys[i]);
              }
            }
          }
          return response;
        } catch {
          return new Response("", {
            status: 503,
            statusText: "Image not available offline",
          });
        }
      })()
    );
    return;
  }

  // Skip API requests -- handled by PWA-003 (offline read cache)
  if (isApiRequest(request.url)) return;

  // Skip Vite dev-server internal requests
  if (isViteDevRequest(request.url)) return;

  // Skip WebSocket upgrade requests
  if (request.headers.get("upgrade") === "websocket") return;

  // Skip cross-origin requests (fonts, analytics)
  if (isCrossOrigin(request.url, self.location)) return;

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
    return new Response("Offline -- resource not cached", {
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

// ─── Message handlers (PWA-002) ─────────────────────────────────

self.addEventListener("message", async (event) => {
  if (event.data?.type === "SKIP_WAITING") {
    self.skipWaiting();
  }

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

  if (event.data?.type === "csrf-token") {
    _cachedCsrfToken = event.data.token || "";
  }

  if (event.data?.type === "clear-all-caches") {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => caches.delete(k)));
    event.source?.postMessage({ type: "caches-cleared" });
  }
});

// ─── Background Sync (PWA-004) ──────────────────────────────────

const SYNC_TAG = "flush-offline-queue";
const SYNC_DB_NAME = "app-offline-cache";
const SYNC_DB_VERSION = 2;
const SYNC_STORE_NAME = "sync_queue";
const MAX_RETRIES = 5;
const BASE_BACKOFF_MS = 2000;
const MAX_BACKOFF_MS = 64000;

/** Cached CSRF token (refreshed via postMessage from client) */
let _cachedCsrfToken = "";

self.addEventListener("sync", (event) => {
  if (event.tag === SYNC_TAG) {
    event.waitUntil(flushSyncQueue());
  }
});

/** Open the sync queue IDB from the service worker context. */
function openSyncDbSW() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(SYNC_DB_NAME, SYNC_DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      const oldVersion = event.oldVersion;
      if (oldVersion < 1) {
        const apiStore = db.createObjectStore("api_cache", { keyPath: "cacheKey" });
        apiStore.createIndex("cachedAt", "cachedAt", { unique: false });
        apiStore.createIndex("endpoint", "endpoint", { unique: false });
        apiStore.createIndex("userId", "userId", { unique: false });
        apiStore.createIndex("userId_endpoint", ["userId", "endpoint"], { unique: false });
        db.createObjectStore("api_cache_meta", { keyPath: "endpoint" });
      }
      if (oldVersion < 2) {
        const syncStore = db.createObjectStore(SYNC_STORE_NAME, { keyPath: "id" });
        syncStore.createIndex("type", "type", { unique: false });
        syncStore.createIndex("enqueuedAt", "enqueuedAt", { unique: false });
        syncStore.createIndex("status", "status", { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Get all sync queue items with the given status, ordered by enqueuedAt. */
function getAllByStatusSW(db, status) {
  return new Promise((resolve) => {
    const tx = db.transaction(SYNC_STORE_NAME, "readonly");
    const store = tx.objectStore(SYNC_STORE_NAME);
    const index = store.index("status");
    const items = [];
    const req = index.openCursor(IDBKeyRange.only(status));
    req.onsuccess = () => {
      const cursor = req.result;
      if (cursor) {
        items.push(cursor.value);
        cursor.continue();
      } else {
        items.sort((a, b) => a.enqueuedAt - b.enqueuedAt);
        resolve(items);
      }
    };
    req.onerror = () => resolve([]);
  });
}

/** Delete a sync item from IDB. */
function deleteSyncItemSW(db, id) {
  return new Promise((resolve) => {
    const tx = db.transaction(SYNC_STORE_NAME, "readwrite");
    tx.objectStore(SYNC_STORE_NAME).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => resolve();
  });
}

/** Update a sync item in IDB. */
function updateSyncItemSW(db, id, updates) {
  return new Promise((resolve) => {
    const tx = db.transaction(SYNC_STORE_NAME, "readwrite");
    const store = tx.objectStore(SYNC_STORE_NAME);
    const getReq = store.get(id);
    getReq.onsuccess = () => {
      if (getReq.result) {
        store.put(Object.assign({}, getReq.result, updates));
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => resolve();
  });
}

/** Try to get CSRF token via CookieStore API or fall back to cached value. */
async function getCsrfTokenSW() {
  try {
    if (typeof self.cookieStore !== "undefined") {
      const cookie = await self.cookieStore.get("ui_csrf");
      if (cookie?.value) return cookie.value;
    }
  } catch {
    // CookieStore not available
  }
  return _cachedCsrfToken;
}

/** Dispatch a queued action to the backend. */
async function dispatchSyncAction(item) {
  const csrfToken = item.csrfToken || (await getCsrfTokenSW());
  let url;
  let body;

  if (item.type === "send_message") {
    const conversationId = item.payload.conversationId;
    url = `/messaging/conversations/${conversationId}/messages`;
    body = JSON.stringify(item.payload.req);
  } else if (item.type === "create_post") {
    url = "/posts";
    body = JSON.stringify(item.payload);
  } else {
    throw new Error(`Unknown action type: ${item.type}`);
  }

  const resp = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body,
  });

  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  }
}

/** Send a postMessage to all controlled clients. */
async function notifyClients(data) {
  try {
    const allClients = await self.clients.matchAll({ type: "window" });
    for (const client of allClients) {
      client.postMessage(data);
    }
  } catch {
    // Failed to notify clients
  }
}

/** Main flush loop: process pending + retrying items with exponential backoff. */
async function flushSyncQueue() {
  let db;
  try {
    db = await openSyncDbSW();
  } catch {
    return; // IDB unavailable
  }

  const pending = await getAllByStatusSW(db, "pending");
  const retrying = await getAllByStatusSW(db, "retrying");
  const items = [...pending, ...retrying].sort((a, b) => a.enqueuedAt - b.enqueuedAt);

  for (const item of items) {
    try {
      await dispatchSyncAction(item);
      // Success -- remove from IDB and notify clients
      await deleteSyncItemSW(db, item.id);
      await notifyClients({ type: "sync-item-success", id: item.id });
    } catch (err) {
      const newRetryCount = (item.retryCount || 0) + 1;
      const errorMsg = err instanceof Error ? err.message : String(err);

      if (newRetryCount >= MAX_RETRIES) {
        // Move to dead letter
        await updateSyncItemSW(db, item.id, {
          status: "dead",
          retryCount: newRetryCount,
          lastRetryAt: Date.now(),
          lastError: errorMsg,
        });
        await notifyClients({
          type: "sync-item-dead",
          id: item.id,
          retryCount: newRetryCount,
          error: errorMsg,
        });
      } else {
        // Schedule for retry with backoff
        const backoff = Math.min(
          BASE_BACKOFF_MS * Math.pow(2, newRetryCount - 1),
          MAX_BACKOFF_MS,
        );
        await updateSyncItemSW(db, item.id, {
          status: "retrying",
          retryCount: newRetryCount,
          lastRetryAt: Date.now(),
          lastError: errorMsg,
        });
        // Wait for backoff before continuing to next item
        await new Promise((r) => setTimeout(r, backoff));
      }
    }
  }

  await notifyClients({ type: "sync-flush-complete" });
}

// ─── Push + Notification handlers (unchanged from PLATFORM-010) ──

// Handle incoming push notification
self.addEventListener("push", (event) => {
  if (!event.data) {
    // No payload -- show a generic notification
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
    // Fallback: treat as plain text
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
    timestamp: payload.timestamp ? new Date(payload.timestamp * 1000).getTime() : Date.now(),
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
        // Try to find an existing app tab to focus + navigate
        for (const client of clientList) {
          if (client.url.startsWith(self.location.origin) && "focus" in client) {
            return client.navigate(fullUrl).then(() => client.focus());
          }
        }
        // No existing tab -- open a new one
        return self.clients.openWindow(fullUrl);
      })
  );
});

// Handle notification close (analytics, optional)
self.addEventListener("notificationclose", (event) => {
  // Future: track notification dismissal rate
});
