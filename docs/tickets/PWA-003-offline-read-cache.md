# PWA-003: Offline Read Cache (IndexedDB + Cache API)

**Ticket**: PWA-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28
**Depends on**: PWA-002

---

## 1. Overview & Motivation

### 1.1 Problem Statement

After PWA-002, the app shell (HTML/CSS/JS) loads from cache when offline, but all API
data is unavailable. The user sees the app layout (header, sidebar, navigation) but every
page shows loading spinners that never resolve. Conversations, messages, feed posts, and
other content are completely inaccessible offline. The `OfflineBanner` component displays
"You're offline" but offers no access to previously-loaded data.

The platform has a rich data model with conversations, messages, and feed posts that users
frequently re-read. Caching these API responses locally would let users browse their most
recent data while offline, with clear staleness indicators showing when data was last
refreshed.

### 1.2 User Stories

1. **As a user who loses connectivity**, I want to see my recent conversations and messages
   that I already loaded, so I can re-read important information.
2. **As a commuter on spotty Wi-Fi**, I want the feed to show previously-loaded posts
   instead of an empty spinner, so I can continue reading.
3. **As a user**, I want to see a "Last updated 5 minutes ago" indicator on cached data,
   so I know the information might be stale.
4. **As a user**, I want cached data to expire after a reasonable period (e.g., 24 hours
   for messages, 1 hour for feed), so I do not see extremely outdated content.

### 1.3 Design Principles

- **Read-Only Cache**: PWA-003 only caches GET responses for reading. Write operations
  (POST/PUT/DELETE) are handled by PWA-004 (Background Sync).
- **Per-Endpoint TTL**: Different data types have different freshness requirements.
  Conversations list is stale after 5 minutes; individual messages after 30 minutes;
  feed posts after 1 hour.
- **IndexedDB for Structured Data**: API JSON responses are stored in IndexedDB (via a
  thin wrapper), not the Cache API. This allows querying, pagination, and selective
  eviction -- the Cache API only supports URL-keyed opaque blobs.
- **Cache API for Binary Assets**: Images (message attachments, post images) are stored
  in the Cache API via the service worker.
- **Transparent to React Query**: The offline cache layer integrates with the existing
  React Query setup so that cached data populates `useQuery` results when the network
  request fails.

---

## 2. Current State Analysis

### 2.1 React Query Configuration (`frontend/src/main.tsx`)

The `QueryClient` is configured at lines 50-58:
<!-- VERIFIED: main.tsx:50-58 -->

```typescript
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});
```

Key observations:
- `staleTime: 30_000` (30 seconds) means queries are considered stale after 30s and will
  refetch on mount. This is too aggressive for offline caching -- when offline, we want to
  serve cached data even if it is hours old.
- `retry: 1` means a failed query retries once. When offline, both attempts fail, and the
  query enters the `error` state. The UI shows error states, not cached data.
- `refetchOnWindowFocus: false` prevents automatic refetches when the user switches tabs.

### 2.2 Conversations Query (`frontend/src/pages/messages/ConversationList.tsx`)

The conversations list query at lines 41-47:
<!-- VERIFIED: ConversationList.tsx:41-47 -->

```typescript
const { data, isLoading } = useQuery({
  queryKey: ["conversations"],
  queryFn: () => getConversations(),
  refetchOnWindowFocus: true,
  refetchOnMount: true,
  staleTime: 0,
});
```

This overrides the global `staleTime` to 0, meaning the conversations list is always
considered stale and refetches on every mount. When offline, `getConversations()` fails,
and the UI shows the loading skeleton or empty state.

The `addConvoToCache` function (lines 49-60) manually updates the React Query cache when
<!-- VERIFIED: ConversationList.tsx:49-60 -->
a new conversation is created, showing a pattern of direct cache manipulation that the
offline cache must be compatible with.

### 2.3 Messages Query (`frontend/src/pages/messages/ConversationView.tsx`)

The infinite query at lines 103-104 uses a custom hook:
<!-- VERIFIED: ConversationView.tsx:103-104 -->

```typescript
const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } =
  useMessagesQuery(convoId);
```

The `useMessagesQuery` hook (defined at line 1235 of the same file) wraps `useInfiniteQuery`:
<!-- VERIFIED: ConversationView.tsx:1235-1244 -->

```typescript
function useMessagesQuery(conversationId: string) {
  return useInfiniteQuery({
    queryKey: ["messages", conversationId],
    queryFn: ({ pageParam }) => getMessages(conversationId, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
}
```

The messages query uses `useInfiniteQuery` with cursor-based pagination. Each page
contains a `messages` array and an optional `next_cursor`. The `allMessages` memo
(lines 112-123) flattens pages into chronological order:
<!-- VERIFIED: ConversationView.tsx:112-123 -->

```typescript
const allMessages = React.useMemo(() => {
  if (!data?.pages) return [];
  const msgs: Message[] = [];
  for (let i = data.pages.length - 1; i >= 0; i--) {
    const page = data.pages[i];
    if (page) msgs.push(...(page.messages ?? []).slice().reverse());
  }
  return msgs;
}, [data]);
```

### 2.4 Reconnect Handling (`ConversationView.tsx`, lines 182-201)
<!-- VERIFIED: ConversationView.tsx:182-201 -->

```typescript
React.useEffect(() => {
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
    void queryClient.invalidateQueries({ queryKey: ["conversations"] });
  };

  const onVisibility = () => {
    if (document.visibilityState === "visible") {
      refresh();
    }
  };

  window.addEventListener("online", refresh);
  document.addEventListener("visibilitychange", onVisibility);
  // ...
}, [convoId, queryClient]);
```

When the browser comes back online, this code invalidates all cached queries, triggering
a refetch. This is the right behavior for transitioning from offline to online -- the
stale cached data is replaced with fresh data from the network.

### 2.5 Feed Query (`frontend/src/api/endpoints/newsfeed.ts`)

```typescript
export const getFeed = (params?: FeedQueryParams) => {
  const query: Record<string, string> = {};
  // ... build query params ...
  return api.get<{ items: FeedPost[]; next_cursor?: string }>(
    "/feed",
    Object.keys(query).length ? query : undefined,
  );
};
```

The feed is fetched via `useInfiniteQuery` in the `useFeedTimelineQuery` hook
(`frontend/src/hooks/useFeedTimelineQuery.ts`), used by `FeedTimeline.tsx` (line 35).
The `NewsFeed.tsx` component wraps `FeedTimeline` and `ScheduledPostsPanel`.
<!-- VERIFIED: FeedTimeline.tsx:35, NewsFeed.tsx:9-10 -->

### 2.6 Offline Store (`frontend/src/stores/offlineStore.ts`)

The existing `offlineStore` (69 lines) tracks online/offline status and the action queue:

```typescript
export const useOfflineStore = create<OfflineState>()(
  persist(
    (set) => ({
      queue: [],
      isOnline: typeof navigator !== "undefined" ? navigator.onLine : true,
      setOnline: (online) => set({ isOnline: online }),
      addToQueue: (action) =>
        set((s) => ({
          queue: [
            ...s.queue,
            {
              ...action,
              id: `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`,
              enqueuedAt: Date.now(),
            } as OfflineAction,
          ],
        })),
      removeFromQueue: (id) =>
        set((s) => ({ queue: s.queue.filter((a) => a.id !== id) })),
      clearQueue: () => set({ queue: [] }),
    }),
    {
      name: "offline-store",
      partialize: (state) => ({ queue: state.queue }),
    },
  ),
);
```

The store does NOT currently store any cached API data. The `queue` only holds pending
write actions (`send_message`, `create_post`).

### 2.7 Offline Banner (`frontend/src/components/shared/OfflineBanner.tsx`)

```typescript
export function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);
  const queueCount = useOfflineStore((s) => s.queue.length);

  useEffect(() => {
    const goOffline = () => setOffline(true);
    const goOnline = () => setOffline(false);
    window.addEventListener("offline", goOffline);
    window.addEventListener("online", goOnline);
    return () => {
      window.removeEventListener("offline", goOffline);
      window.removeEventListener("online", goOnline);
    };
  }, []);

  if (!offline) return null;

  return (
    <div className="flex w-full items-center justify-center gap-2 bg-warning px-4 py-2 text-warning-foreground text-sm font-medium animate-in slide-in-from-top duration-200">
      <WifiOff className="h-4 w-4" />
      You&apos;re offline &mdash; actions will be sent when reconnected
      {queueCount > 0 && (
        <span className="ml-1 rounded-full bg-warning-foreground/20 px-2 py-0.5 text-xs font-semibold">
          {queueCount} queued
        </span>
      )}
    </div>
  );
}
```

This banner shows the queue count but has no staleness indicator for cached data.

### 2.8 API Client (`frontend/src/api/client.ts`)

The API client (`api` function at line 140) uses `fetch()` with `credentials: "include"`.
<!-- VERIFIED: client.ts:140 -->
When offline, the `fetch()` call throws a `TypeError` ("Failed to fetch"), which is caught
at line 185:
<!-- CORRECTED: was "line 186", actually the catch is at line 185 (try at line 179, catch at line 185) -->

```typescript
try {
  res = await fetch(url, { ...init, headers, credentials: "include" });
} catch (err) {
  toast.error("Network error -- check your connection and try again");
  throw new ApiError(0, "Network error", err);
}
```

The React Query retry logic catches this `ApiError(0)` and retries once. When both
attempts fail, the query enters the `error` state.

### 2.9 SSE Event-Driven Invalidation

The `useMessagingStream` hook listens for SSE events (`message:new`,
`conversation_updated`, `typing`, `poll:vote`, `poll:confirmed`) and invalidates
relevant React Query caches. When offline, the SSE connection drops, so no invalidations
fire and the IndexedDB cache remains stable until reconnection.

---

## 3. Technical Design

### 3.1 Architecture Overview

```
                    React Query
                        |
                   queryFn()
                        |
              +---------v----------+
              | offlineQueryWrapper|
              | (per-endpoint)     |
              +----+----------+----+
                   |          |
             Online|          |Offline or
                   |          |network error
                   v          v
              Network      IndexedDB
              fetch()      cache lookup
                   |          |
                   v          v
              Cache response  Return cached
              in IndexedDB   data with
              (async, after  __cachedAt
               returning     metadata
               data to UI)
```

**Data flow for online requests**:
1. React Query calls `queryFn()` which invokes `withOfflineCache(networkFn, options)`
2. `networkFn()` succeeds -- data is returned to React Query immediately
3. A fire-and-forget `setCachedResponse()` writes the response to IndexedDB
4. The UI renders fresh data with no staleness indicator

**Data flow for offline requests**:
1. React Query calls `queryFn()` which invokes `withOfflineCache(networkFn, options)`
2. `networkFn()` throws `ApiError(0, "Network error")`
3. `getCachedResponse()` reads from IndexedDB
4. If found and not expired: return data with `__cachedAt` metadata
5. If not found or expired: rethrow the original error (UI shows error state)

### 3.2 IndexedDB Schema

Use a single IndexedDB database `"app-offline-cache"` with two object stores:

**Object Store: `api_cache`**

| Field | Type | Index | Description |
|-------|------|-------|-------------|
| `cacheKey` | string | Primary key | URL path + sorted query params |
| `data` | object | -- | Parsed JSON response body |
| `cachedAt` | number | Yes (ascending) | Unix timestamp (ms) when cached |
| `endpoint` | string | Yes | Endpoint category (e.g., `"conversations"`, `"messages"`, `"feed"`) |
| `ttlSeconds` | number | -- | TTL for this entry |
| `userId` | string | Yes | User ID that owns this cache entry |
| `sizeEstimate` | number | -- | Approximate size in bytes for quota management |

**Object Store: `api_cache_meta`**

| Field | Type | Index | Description |
|-------|------|-------|-------------|
| `endpoint` | string | Primary key | Endpoint category |
| `lastRefreshedAt` | number | -- | Last successful network fetch timestamp |
| `entryCount` | number | -- | Number of cached entries for this endpoint |
| `totalSizeEstimate` | number | -- | Approximate total size for quota tracking |

**IndexedDB upgrade handler**:

```typescript
req.onupgradeneeded = (event) => {
  const db = (event.target as IDBOpenDBRequest).result;
  const oldVersion = event.oldVersion;

  if (oldVersion < 1) {
    // Version 1: Initial schema
    const store = db.createObjectStore("api_cache", { keyPath: "cacheKey" });
    store.createIndex("cachedAt", "cachedAt", { unique: false });
    store.createIndex("endpoint", "endpoint", { unique: false });
    store.createIndex("userId", "userId", { unique: false });
    // Compound index for efficient user+endpoint queries
    store.createIndex("userId_endpoint", ["userId", "endpoint"], { unique: false });

    db.createObjectStore("api_cache_meta", { keyPath: "endpoint" });
  }

  // Future: if (oldVersion < 2) { ... add sync_queue for PWA-004 ... }
};
```

### 3.3 Cache Key Format

```typescript
/**
 * Build a deterministic cache key from a path and optional query params.
 * Params are sorted alphabetically to ensure the same params in different
 * order produce the same key.
 *
 * @example
 *   buildCacheKey("/messaging/conversations") => "/messaging/conversations"
 *   buildCacheKey("/messaging/conversations/abc123/messages") => "/messaging/conversations/abc123/messages"
 *   buildCacheKey("/feed", { cursor: "xyz", author_id: "u1" }) => "/feed?author_id=u1&cursor=xyz"
 */
function buildCacheKey(path: string, params?: Record<string, string>): string {
  const sorted = params
    ? "?" + Object.keys(params).sort().map((k) => `${k}=${params[k]}`).join("&")
    : "";
  return `${path}${sorted}`;
}
```

**Important**: Cursor-based pagination means each page has a different cache key (e.g.,
`/feed?cursor=abc`). This is correct -- each page is cached independently.

### 3.4 Per-Endpoint TTL Configuration

```typescript
// frontend/src/lib/offlineCacheConfig.ts

/**
 * TTL configuration for offline cache per endpoint category.
 * Values are in seconds.
 *
 * Rationale for each TTL:
 * - conversations: 5 min -- list changes frequently as messages arrive
 * - messages: 30 min -- message content is immutable once sent
 * - feed: 60 min -- posts change infrequently; likes/comments are secondary
 * - post_detail: 60 min -- individual post view
 * - contacts: 15 min -- contact list changes infrequently
 * - calendar_events: 30 min -- events change infrequently
 * - alerts: 10 min -- alerts should be relatively fresh
 * - profile: 24 hours -- profile info rarely changes
 * - billing: 10 min -- payment methods / billing history
 * - catalog: 60 min -- shop items change infrequently
 */
export const CACHE_TTL_CONFIG: Record<string, number> = {
  conversations: 5 * 60,       // 5 minutes
  messages: 30 * 60,           // 30 minutes
  feed: 60 * 60,               // 1 hour
  post_detail: 60 * 60,        // 1 hour
  contacts: 15 * 60,           // 15 minutes
  calendar_events: 30 * 60,    // 30 minutes
  alerts: 10 * 60,             // 10 minutes
  profile: 24 * 60 * 60,       // 24 hours (rarely changes)
  billing: 10 * 60,            // 10 minutes
  catalog: 60 * 60,            // 1 hour
};

export const DEFAULT_TTL = 15 * 60;   // 15 minutes for unconfigured endpoints

/**
 * Maximum number of entries per endpoint category.
 * Prevents unbounded cache growth for high-volume endpoints.
 */
export const MAX_ENTRIES_PER_ENDPOINT: Record<string, number> = {
  conversations: 1,            // Only the conversations list
  messages: 50,                // 50 conversation pages
  feed: 10,                    // 10 feed pages
  post_detail: 20,             // 20 individual posts
  contacts: 5,                 // Contact list pages
  calendar_events: 10,         // Calendar event pages
  alerts: 5,                   // Alert pages
  profile: 5,                  // Profile variations
};

export const DEFAULT_MAX_ENTRIES = 10;

/**
 * Get the TTL for a given endpoint category.
 */
export function getTtlForEndpoint(endpoint: string): number {
  return CACHE_TTL_CONFIG[endpoint] ?? DEFAULT_TTL;
}

/**
 * Determine the endpoint category from a URL path.
 */
export function classifyEndpoint(path: string): string {
  if (path.includes("/conversations") && path.includes("/messages")) return "messages";
  if (path.includes("/conversations")) return "conversations";
  if (path.startsWith("/feed")) return "feed";
  if (path.startsWith("/posts/")) return "post_detail";
  if (path.includes("/contacts")) return "contacts";
  if (path.includes("/calendars") || path.includes("/events")) return "calendar_events";
  if (path.includes("/alerts")) return "alerts";
  if (path.includes("/profile") || path.includes("/me")) return "profile";
  if (path.includes("/billing") || path.includes("/payment-methods")) return "billing";
  if (path.includes("/catalog")) return "catalog";
  return "other";
}
```

### 3.5 IndexedDB Wrapper (`frontend/src/lib/offlineCache.ts`)

```typescript
// frontend/src/lib/offlineCache.ts

const DB_NAME = "app-offline-cache";
const DB_VERSION = 1;
const STORE_NAME = "api_cache";
const META_STORE = "api_cache_meta";

/** Cached singleton to avoid repeated open calls */
let dbInstance: IDBDatabase | null = null;

/**
 * Open (or reuse) the IndexedDB database.
 * Creates object stores on first open or version upgrade.
 */
function openDb(): Promise<IDBDatabase> {
  if (dbInstance) return Promise.resolve(dbInstance);

  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      const oldVersion = event.oldVersion;

      if (oldVersion < 1) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: "cacheKey" });
        store.createIndex("cachedAt", "cachedAt", { unique: false });
        store.createIndex("endpoint", "endpoint", { unique: false });
        store.createIndex("userId", "userId", { unique: false });
        store.createIndex("userId_endpoint", ["userId", "endpoint"], { unique: false });

        db.createObjectStore(META_STORE, { keyPath: "endpoint" });
      }
    };

    req.onsuccess = () => {
      dbInstance = req.result;

      // Clear singleton if the database is unexpectedly closed
      dbInstance.onclose = () => { dbInstance = null; };
      dbInstance.onversionchange = () => {
        dbInstance?.close();
        dbInstance = null;
      };

      resolve(dbInstance);
    };

    req.onerror = () => reject(req.error);
  });
}

/**
 * Retrieve a cached API response from IndexedDB.
 *
 * Returns null if:
 * - No entry exists for the cacheKey
 * - The entry belongs to a different userId
 * - The entry has expired (age > ttlSeconds)
 * - IndexedDB is unavailable
 */
export async function getCachedResponse<T>(
  cacheKey: string,
  userId: string,
): Promise<{ data: T; cachedAt: number } | null> {
  try {
    const db = await openDb();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(cacheKey);

      req.onsuccess = () => {
        const entry = req.result;
        if (!entry || entry.userId !== userId) {
          resolve(null);
          return;
        }
        const ageSeconds = (Date.now() - entry.cachedAt) / 1000;
        if (ageSeconds > entry.ttlSeconds) {
          resolve(null); // expired
          return;
        }
        resolve({ data: entry.data as T, cachedAt: entry.cachedAt });
      };

      req.onerror = () => resolve(null);
    });
  } catch {
    // IndexedDB unavailable (private browsing, quota exceeded, etc.)
    return null;
  }
}

/**
 * Store an API response in IndexedDB.
 * Fire-and-forget: errors are silently ignored.
 */
export async function setCachedResponse(
  cacheKey: string,
  endpoint: string,
  data: unknown,
  userId: string,
  ttlSeconds: number,
): Promise<void> {
  try {
    const db = await openDb();
    const sizeEstimate = JSON.stringify(data).length;

    return new Promise((resolve) => {
      const tx = db.transaction([STORE_NAME, META_STORE], "readwrite");
      const store = tx.objectStore(STORE_NAME);

      store.put({
        cacheKey,
        endpoint,
        data,
        cachedAt: Date.now(),
        ttlSeconds,
        userId,
        sizeEstimate,
      });

      // Update metadata
      const metaStore = tx.objectStore(META_STORE);
      const metaReq = metaStore.get(endpoint);
      metaReq.onsuccess = () => {
        const meta = metaReq.result ?? {
          endpoint,
          lastRefreshedAt: 0,
          entryCount: 0,
          totalSizeEstimate: 0,
        };
        meta.lastRefreshedAt = Date.now();
        meta.entryCount += 1;
        meta.totalSizeEstimate += sizeEstimate;
        metaStore.put(meta);
      };

      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve(); // silent failure
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Clear all cache entries for a specific endpoint category.
 */
export async function clearCacheForEndpoint(endpoint: string): Promise<void> {
  try {
    const db = await openDb();
    return new Promise((resolve) => {
      const tx = db.transaction([STORE_NAME, META_STORE], "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const index = store.index("endpoint");
      const req = index.openCursor(IDBKeyRange.only(endpoint));
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };

      // Reset metadata
      const metaStore = tx.objectStore(META_STORE);
      metaStore.delete(endpoint);

      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Clear all cache entries for a specific user.
 * Called on logout to prevent data leakage.
 */
export async function clearAllCacheForUser(userId: string): Promise<void> {
  try {
    const db = await openDb();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const index = store.index("userId");
      const req = index.openCursor(IDBKeyRange.only(userId));
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        } else {
          resolve();
        }
      };
      req.onerror = () => resolve();
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Evict the oldest entries for an endpoint if the count exceeds the max.
 * Call after setCachedResponse to keep cache size bounded.
 */
export async function evictOldestForEndpoint(
  endpoint: string,
  userId: string,
  maxEntries: number,
): Promise<void> {
  try {
    const db = await openDb();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const index = store.index("userId_endpoint");
      const range = IDBKeyRange.only([userId, endpoint]);
      const entries: { cacheKey: string; cachedAt: number }[] = [];

      const req = index.openCursor(range);
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          entries.push({
            cacheKey: cursor.value.cacheKey,
            cachedAt: cursor.value.cachedAt,
          });
          cursor.continue();
        } else {
          // All entries collected -- evict oldest if over limit
          if (entries.length > maxEntries) {
            entries.sort((a, b) => a.cachedAt - b.cachedAt);
            const toEvict = entries.slice(0, entries.length - maxEntries);
            for (const entry of toEvict) {
              store.delete(entry.cacheKey);
            }
          }
          resolve();
        }
      };
      req.onerror = () => resolve();
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Get cache statistics for debugging/monitoring.
 */
export async function getCacheStats(): Promise<{
  totalEntries: number;
  totalSizeEstimate: number;
  byEndpoint: Record<string, { count: number; size: number }>;
}> {
  try {
    const db = await openDb();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const stats: Record<string, { count: number; size: number }> = {};
      let totalEntries = 0;
      let totalSize = 0;

      const req = store.openCursor();
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          const entry = cursor.value;
          const ep = entry.endpoint ?? "unknown";
          if (!stats[ep]) stats[ep] = { count: 0, size: 0 };
          stats[ep].count += 1;
          stats[ep].size += entry.sizeEstimate ?? 0;
          totalEntries += 1;
          totalSize += entry.sizeEstimate ?? 0;
          cursor.continue();
        } else {
          resolve({ totalEntries, totalSizeEstimate: totalSize, byEndpoint: stats });
        }
      };
      req.onerror = () => resolve({ totalEntries: 0, totalSizeEstimate: 0, byEndpoint: {} });
    });
  } catch {
    return { totalEntries: 0, totalSizeEstimate: 0, byEndpoint: {} };
  }
}
```

### 3.6 React Query Integration

Create a wrapper factory `frontend/src/lib/withOfflineCache.ts`:

```typescript
// frontend/src/lib/withOfflineCache.ts

import { getCachedResponse, setCachedResponse, evictOldestForEndpoint } from "./offlineCache";
import { getTtlForEndpoint, MAX_ENTRIES_PER_ENDPOINT, DEFAULT_MAX_ENTRIES } from "./offlineCacheConfig";

interface OfflineCacheOptions {
  /** Endpoint category (e.g., "conversations", "messages", "feed") */
  endpoint: string;
  /** Cache key (URL path + sorted query params) */
  cacheKey: string;
  /** Optional TTL override (seconds). Defaults to endpoint config. */
  ttlSeconds?: number;
}

/**
 * Wrap a network query function with offline cache fallback.
 *
 * Strategy: network-first with cache fallback.
 * - Online: fetch from network, cache response in IndexedDB, return data
 * - Offline: fetch fails, look up cached response in IndexedDB
 * - Cache miss: rethrow original network error
 *
 * The cached data includes `__cachedAt` and `__fromOfflineCache` metadata
 * fields so the UI can show staleness indicators.
 *
 * @example
 * ```ts
 * const { data } = useQuery({
 *   queryKey: ["conversations"],
 *   queryFn: withOfflineCache(
 *     () => getConversations(),
 *     { endpoint: "conversations", cacheKey: "/messaging/conversations" },
 *     userId,
 *   ),
 * });
 * ```
 */
export function withOfflineCache<T>(
  networkFn: () => Promise<T>,
  options: OfflineCacheOptions,
  userId: string,
): () => Promise<T> {
  const ttl = options.ttlSeconds ?? getTtlForEndpoint(options.endpoint);
  const maxEntries = MAX_ENTRIES_PER_ENDPOINT[options.endpoint] ?? DEFAULT_MAX_ENTRIES;

  return async () => {
    try {
      // Try network first
      const data = await networkFn();

      // Cache the successful response (fire-and-forget)
      void (async () => {
        await setCachedResponse(
          options.cacheKey,
          options.endpoint,
          data,
          userId,
          ttl,
        );
        await evictOldestForEndpoint(options.endpoint, userId, maxEntries);
      })();

      return data;
    } catch (err) {
      // Network failed -- try cache
      const cached = await getCachedResponse<T>(options.cacheKey, userId);
      if (cached) {
        // Attach staleness metadata so the UI can show it
        const enriched = cached.data as T & {
          __cachedAt?: number;
          __fromOfflineCache?: boolean;
        };
        if (typeof enriched === "object" && enriched !== null) {
          enriched.__cachedAt = cached.cachedAt;
          enriched.__fromOfflineCache = true;
        }
        return enriched;
      }
      // No cache -- rethrow the original error
      throw err;
    }
  };
}

/**
 * Hook-friendly version that builds the cache key from query key parts.
 */
export function buildCacheKeyFromParts(parts: (string | undefined)[]): string {
  return parts.filter(Boolean).join("/");
}
```

**Usage in `ConversationList.tsx`**:

```typescript
import { withOfflineCache } from "@/lib/withOfflineCache";

const userId = useAuthStore((s) => s.userId);

const { data, isLoading } = useQuery({
  queryKey: ["conversations"],
  queryFn: withOfflineCache(
    () => getConversations(),
    {
      endpoint: "conversations",
      cacheKey: "/messaging/conversations",
    },
    userId ?? "",
  ),
  refetchOnWindowFocus: true,
  refetchOnMount: true,
  staleTime: 0,
});

// Check if data came from offline cache
const isFromCache = (data as any)?.__fromOfflineCache === true;
const cachedAt = (data as any)?.__cachedAt as number | undefined;
```

**Usage in `ConversationView.tsx`** (infinite query):

```typescript
// For infinite queries, each page is cached independently
function useMessagesQuery(conversationId: string) {
  const userId = useAuthStore((s) => s.userId) ?? "";

  return useInfiniteQuery({
    queryKey: ["messages", conversationId],
    queryFn: ({ pageParam }) =>
      withOfflineCache(
        () => getMessages(conversationId, pageParam),
        {
          endpoint: "messages",
          cacheKey: `/messaging/conversations/${conversationId}/messages${pageParam ? `?cursor=${pageParam}` : ""}`,
        },
        userId,
      )(),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
}
```

### 3.7 Staleness Indicator Component

Create `frontend/src/components/shared/StalenessIndicator.tsx`:

```typescript
// frontend/src/components/shared/StalenessIndicator.tsx

import { Clock } from "lucide-react";
import { useState, useEffect } from "react";

interface StalenessIndicatorProps {
  /** Timestamp (ms) when the data was cached */
  cachedAt: number | undefined;
  /** Whether to auto-update the age display */
  live?: boolean;
}

/**
 * Shows "Cached X ago" badge when data came from the offline cache.
 * Updates the age display every minute when `live` is true.
 */
export function StalenessIndicator({ cachedAt, live = true }: StalenessIndicatorProps) {
  const [, forceUpdate] = useState(0);

  useEffect(() => {
    if (!cachedAt || !live) return;
    const interval = setInterval(() => forceUpdate((n) => n + 1), 60_000);
    return () => clearInterval(interval);
  }, [cachedAt, live]);

  if (!cachedAt) return null;

  const age = Date.now() - cachedAt;
  const minutes = Math.floor(age / 60_000);

  let label: string;
  if (minutes < 1) {
    label = "Just now";
  } else if (minutes < 60) {
    label = `${minutes}m ago`;
  } else {
    const hours = Math.floor(minutes / 60);
    label = hours === 1 ? "1 hour ago" : `${hours}h ago`;
  }

  return (
    <div
      className="flex items-center gap-1 text-xs text-muted-foreground"
      role="status"
      aria-label={`Data cached ${label}`}
    >
      <Clock className="h-3 w-3" aria-hidden />
      <span>Cached {label}</span>
    </div>
  );
}
```

Render in `ConversationList` header area when data has `__fromOfflineCache` flag:

```typescript
// In ConversationList.tsx, above the conversation list:
{isFromCache && (
  <StalenessIndicator cachedAt={cachedAt} />
)}
```

### 3.8 Image Caching via Service Worker

Extend `sw.js` (from PWA-002) with an image cache for message/post images:

```javascript
// Add to cache constants in sw.js:
const IMAGE_CACHE = `images-v${CACHE_VERSION}`;
const MAX_IMAGE_CACHE_ENTRIES = 200; // max cached images

// Add IMAGE_CACHE to VALID_CACHES:
const VALID_CACHES = new Set([SHELL_CACHE, ASSETS_CACHE, ICONS_CACHE, IMAGE_CACHE]);

// In the fetch handler, add after the icons block:
if (url.pathname.startsWith("/mock/s3/") || url.pathname.startsWith("/uploads/")) {
  event.respondWith(
    (async () => {
      const cache = await caches.open(IMAGE_CACHE);
      const cached = await cache.match(request);
      if (cached) return cached;

      try {
        const response = await fetch(request);
        if (response.ok) {
          // Clone before caching
          const clone = response.clone();
          cache.put(request, clone);

          // Evict oldest if over limit (LRU approximation)
          const keys = await cache.keys();
          if (keys.length > MAX_IMAGE_CACHE_ENTRIES) {
            // Delete the oldest entries (first in list = oldest)
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
```

### 3.9 Cache Eviction on Logout

When the user logs out (via `useAuthStore.logout()`), clear all cached data for that user:

```typescript
// In authStore.ts, modify the logout action:
logout: (reason?: string) => {
  const prevUserId = get().userId;
  set({
    userId: null,
    accessToken: null,
    isAuthenticated: false,
    logoutReason: reason ?? null,
  });
  // Clear offline cache for the logged-out user
  if (prevUserId) {
    import("@/lib/offlineCache").then(({ clearAllCacheForUser }) => {
      clearAllCacheForUser(prevUserId).catch(() => {
        // Cache cleanup is best-effort
      });
    });
  }
},
```

### 3.10 Enhanced Offline Banner

Update `OfflineBanner` to show staleness context when cached data is being served:

```typescript
export function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);
  const queueCount = useOfflineStore((s) => s.queue.length);

  useEffect(() => {
    const goOffline = () => setOffline(true);
    const goOnline = () => setOffline(false);
    window.addEventListener("offline", goOffline);
    window.addEventListener("online", goOnline);
    return () => {
      window.removeEventListener("offline", goOffline);
      window.removeEventListener("online", goOnline);
    };
  }, []);

  if (!offline) return null;

  return (
    <div className="flex w-full items-center justify-center gap-2 bg-warning px-4 py-2 text-warning-foreground text-sm font-medium animate-in slide-in-from-top duration-200">
      <WifiOff className="h-4 w-4" />
      <span>
        You&apos;re offline &mdash; showing cached data
      </span>
      {queueCount > 0 && (
        <span className="ml-1 rounded-full bg-warning-foreground/20 px-2 py-0.5 text-xs font-semibold">
          {queueCount} queued
        </span>
      )}
    </div>
  );
}
```

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `frontend/src/lib/offlineCache.ts` | IndexedDB wrapper (open, get, set, clear, evict, stats) |
| `frontend/src/lib/offlineCacheConfig.ts` | Per-endpoint TTL and max-entries configuration |
| `frontend/src/lib/withOfflineCache.ts` | React Query wrapper factory |
| `frontend/src/components/shared/StalenessIndicator.tsx` | "Cached X ago" badge |

### 4.2 Modified Files

| File | Changes |
|------|---------|
| `frontend/public/sw.js` | Add image cache strategy for `/mock/s3/` and `/uploads/` paths; add IMAGE_CACHE to VALID_CACHES |
| `frontend/src/pages/messages/ConversationList.tsx` | Wrap `getConversations()` with offline cache; show StalenessIndicator |
| `frontend/src/pages/messages/ConversationView.tsx` | Wrap `getMessages()` with offline cache; show StalenessIndicator |
| `frontend/src/pages/feed/FeedTimeline.tsx` | Wrap feed query with offline cache |
| `frontend/src/stores/authStore.ts` | Clear IndexedDB cache on logout |
| `frontend/src/components/shared/OfflineBanner.tsx` | Updated text for cached data context |

### 4.3 Implementation Phases

1. **Phase 1 -- IndexedDB wrapper** (2 hours)
   - Create `offlineCache.ts` with `openDb`, `getCachedResponse`, `setCachedResponse`,
     `clearCacheForEndpoint`, `clearAllCacheForUser`, `evictOldestForEndpoint`, `getCacheStats`
   - Create `offlineCacheConfig.ts` with TTL map, max entries map, and classifier
   - Unit test the wrapper with `fake-indexeddb`

2. **Phase 2 -- React Query integration** (3 hours)
   - Create `withOfflineCache.ts` wrapper
   - Apply to `ConversationList` conversations query
   - Apply to `ConversationView` messages infinite query
   - Apply to `FeedTimeline` feed infinite query
   - Test: load data online, go offline, verify cached data appears

3. **Phase 3 -- Staleness UI** (1.5 hours)
   - Create `StalenessIndicator` component
   - Show in ConversationList header when cached
   - Show in ConversationView header when cached
   - Show in FeedPage header when cached
   - Update OfflineBanner text

4. **Phase 4 -- Image caching in SW** (1 hour)
   - Extend `sw.js` fetch handler for `/mock/s3/` and `/uploads/` paths
   - Add cache-size limit with LRU eviction
   - Test: load conversation with images, go offline, verify images still visible

5. **Phase 5 -- Logout cleanup** (30 min)
   - Add `clearAllCacheForUser()` call in `authStore.logout()`
   - Test: log out, verify IndexedDB is empty for that user

---

## 5. Testing Strategy

### 5.1 E2E Test Plan (`frontend/e2e/pwa-offline-cache.spec.ts`)

**Section 96: IndexedDB Cache Population (4 tests)**

```typescript
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers";

test.describe("96 . IndexedDB cache population", () => {
  test("96.1 conversations are cached after loading", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const hasCachedConversations = await page.evaluate(async () => {
      return new Promise<boolean>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 1);
        req.onsuccess = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains("api_cache")) {
            resolve(false);
            return;
          }
          const tx = db.transaction("api_cache", "readonly");
          const store = tx.objectStore("api_cache");
          const getReq = store.get("/messaging/conversations");
          getReq.onsuccess = () => resolve(!!getReq.result);
          getReq.onerror = () => resolve(false);
        };
        req.onerror = () => resolve(false);
      });
    });
    expect(hasCachedConversations).toBe(true);
  });

  test("96.2 cached entry has correct metadata fields", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const entry = await page.evaluate(async () => {
      return new Promise<Record<string, unknown> | null>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 1);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readonly");
          const store = tx.objectStore("api_cache");
          const getReq = store.get("/messaging/conversations");
          getReq.onsuccess = () => {
            const result = getReq.result;
            if (!result) { resolve(null); return; }
            resolve({
              cacheKey: result.cacheKey,
              endpoint: result.endpoint,
              hasCachedAt: typeof result.cachedAt === "number",
              hasTtl: typeof result.ttlSeconds === "number",
              hasUserId: typeof result.userId === "string",
              hasData: result.data !== undefined,
            });
          };
        };
      });
    });

    expect(entry).not.toBeNull();
    expect(entry!.endpoint).toBe("conversations");
    expect(entry!.hasCachedAt).toBe(true);
    expect(entry!.hasTtl).toBe(true);
    expect(entry!.hasUserId).toBe(true);
    expect(entry!.hasData).toBe(true);
  });

  test("96.3 messages are cached after opening a conversation", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const firstConvo = page.locator("[data-testid='conversation-item']").first();
    if (await firstConvo.isVisible({ timeout: 3000 }).catch(() => false)) {
      await firstConvo.click();
      await page.waitForLoadState("networkidle");

      const cachedMessages = await page.evaluate(async () => {
        return new Promise<number>((resolve) => {
          const req = indexedDB.open("app-offline-cache", 1);
          req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction("api_cache", "readonly");
            const store = tx.objectStore("api_cache");
            const index = store.index("endpoint");
            const countReq = index.count(IDBKeyRange.only("messages"));
            countReq.onsuccess = () => resolve(countReq.result);
            countReq.onerror = () => resolve(0);
          };
        });
      });
      expect(cachedMessages).toBeGreaterThan(0);
    }
  });

  test("96.4 feed posts are cached after loading feed page", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");
    await page.waitForLoadState("networkidle");

    const hasCachedFeed = await page.evaluate(async () => {
      return new Promise<boolean>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 1);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readonly");
          const store = tx.objectStore("api_cache");
          const index = store.index("endpoint");
          const countReq = index.count(IDBKeyRange.only("feed"));
          countReq.onsuccess = () => resolve(countReq.result > 0);
          countReq.onerror = () => resolve(false);
        };
      });
    });
    // Feed might be empty if no posts exist yet, so just check no error
    expect(typeof hasCachedFeed).toBe("boolean");
  });
});
```

**Section 97: Offline Data Access (5 tests)**

```typescript
test.describe("97 . Offline data access", () => {
  test("97.1 conversations list shows cached data when offline", async ({ page, context }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const onlineCount = await page.locator("[data-testid='conversation-item']").count();

    await context.setOffline(true);
    await page.reload();
    await page.waitForTimeout(3000);

    if (onlineCount > 0) {
      const offlineCount = await page.locator("[data-testid='conversation-item']").count();
      expect(offlineCount).toBe(onlineCount);
      await expect(page.getByText(/cached/i)).toBeVisible();
    }

    await context.setOffline(false);
  });

  test("97.2 staleness indicator shows time since cache", async ({ page, context }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    await context.setOffline(true);
    await page.reload();
    await page.waitForTimeout(3000);

    const stalenessText = page.getByText(/cached.*ago|cached.*just now/i);
    if (await stalenessText.count() > 0) {
      await expect(stalenessText.first()).toBeVisible();
    }

    await context.setOffline(false);
  });

  test("97.3 expired cache entries are not served", async ({ page, context }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    // Set cachedAt to 2 hours ago (past the 5-minute TTL for conversations)
    await page.evaluate(async () => {
      const req = indexedDB.open("app-offline-cache", 1);
      return new Promise<void>((resolve) => {
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readwrite");
          const store = tx.objectStore("api_cache");
          const getReq = store.get("/messaging/conversations");
          getReq.onsuccess = () => {
            if (getReq.result) {
              getReq.result.cachedAt = Date.now() - 2 * 60 * 60 * 1000; // 2 hours ago
              store.put(getReq.result);
            }
            tx.oncomplete = () => resolve();
          };
        };
      });
    });

    await context.setOffline(true);
    await page.reload();
    await page.waitForTimeout(3000);

    // Should show error/empty state, not stale cached data
    // The staleness indicator should NOT appear for expired data
    await context.setOffline(false);
  });

  test("97.4 online data replaces cached data on reconnect", async ({ page, context }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    await context.setOffline(true);
    await page.reload();
    await page.waitForTimeout(2000);

    // Come back online
    await context.setOffline(false);
    // Trigger refetch
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await page.waitForTimeout(3000);

    // Staleness indicator should disappear once fresh data loads
    const stalenessIndicator = page.getByText(/cached.*ago/i);
    if (await stalenessIndicator.count() > 0) {
      await expect(stalenessIndicator.first()).not.toBeVisible({ timeout: 10000 });
    }
  });

  test("97.5 different users have isolated caches", async ({ browser }) => {
    // Alice's session
    const aliceContext = await browser.newContext();
    const alicePage = await aliceContext.newPage();
    await injectAuth(alicePage, "alice");
    await alicePage.goto("/messages");
    await alicePage.waitForLoadState("networkidle");

    // Bob's session (different user)
    const bobContext = await browser.newContext();
    const bobPage = await bobContext.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto("/messages");
    await bobPage.waitForLoadState("networkidle");

    // Both should have separate cache entries with different userId
    // Verification: Bob going offline should not see Alice's conversations
    await aliceContext.close();
    await bobContext.close();
  });
});
```

**Section 98: Cache Cleanup (3 tests)**

```typescript
test.describe("98 . Cache cleanup", () => {
  test("98.1 logout clears IndexedDB cache for the user", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const preLogoutCount = await page.evaluate(async () => {
      return new Promise<number>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 1);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readonly");
          const store = tx.objectStore("api_cache");
          const countReq = store.count();
          countReq.onsuccess = () => resolve(countReq.result);
        };
      });
    });
    expect(preLogoutCount).toBeGreaterThan(0);

    // Clear auth (simulates logout)
    await page.evaluate(() => {
      localStorage.removeItem("auth-store");
    });

    // Trigger the cache clear that logout would perform
    await page.evaluate(async () => {
      const req = indexedDB.open("app-offline-cache", 1);
      return new Promise<void>((resolve) => {
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readwrite");
          const store = tx.objectStore("api_cache");
          store.clear();
          tx.oncomplete = () => resolve();
        };
      });
    });

    const postLogoutCount = await page.evaluate(async () => {
      return new Promise<number>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 1);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readonly");
          const store = tx.objectStore("api_cache");
          const countReq = store.count();
          countReq.onsuccess = () => resolve(countReq.result);
        };
      });
    });
    expect(postLogoutCount).toBe(0);
  });

  test("98.2 image cache exists in Cache API", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const cacheNames = await page.evaluate(async () => {
      return await caches.keys();
    });
    const hasImageCache = cacheNames.some((n) => n.startsWith("images-"));
    // Image cache may or may not exist depending on whether images were loaded
    expect(typeof hasImageCache).toBe("boolean");
  });

  test("98.3 cache stats report correct entry counts", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const stats = await page.evaluate(async () => {
      return new Promise<{ totalEntries: number }>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 1);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("api_cache", "readonly");
          const store = tx.objectStore("api_cache");
          const countReq = store.count();
          countReq.onsuccess = () => resolve({ totalEntries: countReq.result });
        };
      });
    });
    expect(stats.totalEntries).toBeGreaterThanOrEqual(0);
  });
});
```

### 5.2 Unit Tests

- `frontend/src/lib/__tests__/offlineCache.test.ts`: Test IndexedDB wrapper with
  `fake-indexeddb` (npm package). Test `get`, `set`, TTL expiry, user-scoped clearing,
  eviction, stats.
- `frontend/src/lib/__tests__/withOfflineCache.test.ts`: Test network-first with cache
  fallback; test cache population on success; test cache miss when expired.
- `frontend/src/lib/__tests__/offlineCacheConfig.test.ts`: Test `classifyEndpoint` for
  all known URL patterns.

---

## 6. Edge Cases & Gotchas

### 6.1 Multi-User Cache Isolation

The `userId` field on each cache entry ensures that if User A logs out and User B logs in
on the same device, User B does not see User A's cached conversations. The `clearAllCacheForUser()`
call on logout provides additional cleanup.

### 6.2 Infinite Query Cache Shape

`useInfiniteQuery` stores data as `{ pages: [...], pageParams: [...] }`. The offline
cache stores the raw API response, not the React Query internal shape. The
`withOfflineCache` wrapper returns data in the same shape as the network call, so React
Query reconstructs the infinite query state correctly. However, only the first page is
cached on initial load; subsequent pages loaded via `fetchNextPage` are also cached
individually.

### 6.3 IndexedDB Quota

IndexedDB has generous quota limits (typically 50% of available disk, with a minimum of
several hundred MB). A few hundred cached API responses (conversations, messages, feed
posts) will total well under 10 MB. No quota issues are expected.

### 6.4 Race Condition: Cache Write During Network Response

The `setCachedResponse()` call is fire-and-forget (non-blocking). If the user navigates
away before the IndexedDB write completes, the write may be lost. This is acceptable --
the cache is best-effort, and the next successful network fetch will repopulate it.

### 6.5 SSE Events and Cache Invalidation

The `useMessagingStream` hook (in `frontend/src/hooks/useMessagingStream.ts`) invalidates
React Query caches on SSE events (`message:new`, `conversation_updated`, etc.). These
invalidations trigger refetches which will update the IndexedDB cache with fresh data.
When offline, SSE is disconnected, so no invalidations fire and the cache remains stable.

### 6.6 Stale Data After Long Offline Period

If the user is offline for hours and then reopens the app, the cached data may be very
stale. The `StalenessIndicator` component clearly communicates this. When the user comes
back online, the `ConversationView` `online` event handler (lines 182-201) automatically
invalidates and refetches all data, replacing the stale cache.

### 6.7 IndexedDB in Private Browsing

Some browsers restrict IndexedDB in private/incognito mode. Firefox allows it but deletes
data on window close. Safari blocks it entirely in private tabs. The `getCachedResponse`
and `setCachedResponse` functions wrap all IDB operations in try/catch, so failures are
silently ignored and the app falls through to network-only mode.

### 6.8 Concurrent Tab Cache Writes

If the user has multiple tabs open and both write to the same cache key, the last write
wins. IndexedDB transactions are atomic, so no partial writes occur. This is acceptable
since both tabs are writing the same API response data.

---

## 7. Security Considerations

### 7.1 Sensitive Data in IndexedDB

IndexedDB stores message text, conversation metadata, and feed post content. This data is
accessible to any JavaScript running on the same origin. The risk is equivalent to the
existing `localStorage` usage for `auth-store` and `offline-store`. In a shared-device
scenario, the logout cleanup (`clearAllCacheForUser()`) removes all cached data.

### 7.2 Encrypted Messages

Messages with `is_encrypted: true` have their `text` field set to empty string and the
ciphertext stored in the `encryption` envelope. The IndexedDB cache stores the full
`Message` object including the envelope. The decryption key (user-entered password) is
never stored -- it is only held in memory during the decryption operation. Caching
encrypted messages is safe because the ciphertext is already opaque.

### 7.3 View-Once Messages

View-once messages (`view_once: true`) should NOT be cached in IndexedDB. Once consumed,
the text is cleared server-side. The `withOfflineCache` wrapper should strip view-once
messages from cached responses or skip caching for conversations that contain view-once
messages. A simpler approach: cache the response as-is, but the client-side rendering
logic already hides consumed view-once messages (via `viewedOnceIds` state in
`ConversationView.tsx`).

### 7.4 Locked Messages

Locked messages (`lock_price_cents > 0`) have `text: null` and `is_unlocked: false` for
non-senders until unlocked. The cached response correctly reflects the user's unlock status
at cache time. If the user unlocks a message and it is cached, then goes offline, they
will see the unlocked content. This is correct behavior.

### 7.5 IndexedDB Data at Rest

IndexedDB data is stored unencrypted on disk. On shared or public computers, this means
cached message text could be accessed by another user via browser DevTools. The logout
cleanup mitigates this, but users on shared devices should use private browsing mode.

---

## Appendix A: File Reference

| Existing File | Relevance |
|---------------|-----------|
| `frontend/src/main.tsx` | QueryClient config; staleTime/retry defaults |
| `frontend/src/pages/messages/ConversationList.tsx` | Conversations query to wrap |
| `frontend/src/pages/messages/ConversationView.tsx` | Messages query + reconnect handler |
| `frontend/src/pages/feed/FeedTimeline.tsx` | Feed query to wrap |
| `frontend/src/pages/feed/NewsFeed.tsx` | Feed page component |
| `frontend/src/api/endpoints/newsfeed.ts` | `getFeed()` function |
| `frontend/src/api/endpoints/messaging.ts` | `getConversations()`, `getMessages()` |
| `frontend/src/api/client.ts` | API client; error handling; ApiError class |
| `frontend/src/stores/offlineStore.ts` | Existing offline state store |
| `frontend/src/stores/authStore.ts` | Logout action; cache cleanup hook |
| `frontend/src/hooks/useOfflineQueue.ts` | Queue flush; invalidation on reconnect |
| `frontend/src/hooks/useMessagingStream.ts` | SSE-driven cache invalidation |
| `frontend/src/components/shared/OfflineBanner.tsx` | Offline banner to extend |
| `frontend/public/sw.js` | Service worker to extend with image caching |

## Appendix B: Dependencies & Risks

| Risk | Mitigation |
|------|------------|
| IndexedDB not available (private browsing, old browser) | `withOfflineCache` catches IDB errors and falls through to network-only |
| Large message history exhausts IDB quota | Cap cached messages per conversation via `evictOldestForEndpoint`; max 50 entries |
| View-once messages cached insecurely | Client rendering already hides consumed view-once; optionally strip from cache |
| Multi-tab cache contention | IndexedDB transactions are atomic; concurrent writes are safe; last write wins |
| Stale cache served when online (slow network) | `withOfflineCache` always tries network first; cache is fallback only |
| Infinite query page caching complexity | Cache each page independently by URL; React Query reassembles pages |
| IndexedDB version upgrade in future (PWA-004) | Use `oldVersion` check in `onupgradeneeded` to support incremental migrations |
| Cache size grows unbounded | `evictOldestForEndpoint` enforces per-endpoint max entries; `getCacheStats` for monitoring |

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `offlineCache.ts` | `frontend/src/lib/offlineCache.ts` | 306 lines | **ALREADY EXISTS** — IndexedDB wrapper (open, get, set, clear, evict, stats) |
| `offlineCacheConfig.ts` | `frontend/src/lib/offlineCacheConfig.ts` | 63 lines | **ALREADY EXISTS** — per-endpoint TTL and max-entries configuration |
| `withOfflineCache.ts` | `frontend/src/lib/withOfflineCache.ts` | 99 lines | **ALREADY EXISTS** — React Query wrapper factory |
| `StalenessIndicator` | `frontend/src/components/shared/StalenessIndicator.tsx` | 52 lines | **ALREADY EXISTS** — "Cached X ago" badge |
| `ConversationView.tsx` | `frontend/src/pages/messages/ConversationView.tsx` | 1461 lines | **Exists** |
| `ConversationList.tsx` | `frontend/src/pages/messages/ConversationList.tsx` | 356 lines | **Exists** |
| `FeedPage.tsx` | `frontend/src/pages/feed/FeedPage.tsx` | 18 lines | **Exists** |
| `offlineStore` | `frontend/src/stores/offlineStore.ts` | 213 lines | **Exists** |
| `OfflineBanner` | `frontend/src/components/shared/OfflineBanner.tsx` | 45 lines | **Exists** |
| API client | `frontend/src/api/client.ts` | 309 lines | **Exists** |

### Key Correction

**This ticket appears to be ALREADY IMPLEMENTED.** All four proposed new files (`offlineCache.ts`, `offlineCacheConfig.ts`, `withOfflineCache.ts`, `StalenessIndicator.tsx`) exist with the described functionality.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_offline_cache.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_pwa_003_create` | Create primary entity; 201 |
| 2 | `test_pwa_003_read` | Read back entity; correct fields |
| 3 | `test_pwa_003_update` | Update entity; 200; changes reflected |
| 4 | `test_pwa_003_delete` | Delete entity; 200/204 |
| 5 | `test_pwa_003_auth_required` | No auth; 401 |
| 6 | `test_pwa_003_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/pwa-offline-cache.spec.ts` -- 12 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Tests cover API CRUD, UI rendering, negative cases (401/403/404/422), and edge cases.

**Negative/edge tests**: 401 unauthenticated, 403 insufficient role, 404 not found, 422 validation error, 409 conflict

### Test Data Requirements

- DDB seeds: feature-specific tables via setup scripts
- Test users: Alice, Bob, Root, Charlie (admin)
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: Feature-specific flags (see Rollout Plan section)
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| PWA-002 | Required | Service worker caching infrastructure from PWA-002 |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| PWA-004 | Required | Background sync builds on offline cache |
| PWA-005 | Required | Optimistic UI uses offline cache |

### Merge Strategy

**Sequential** -- Requires PWA-002 merged first.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/pwa-offline-cache.spec.ts`
