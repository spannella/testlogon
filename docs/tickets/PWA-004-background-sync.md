# PWA-004: Background Sync API Integration

**Ticket**: PWA-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28
**Depends on**: PWA-002, PWA-003

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform has an existing offline queue (`frontend/src/stores/offlineStore.ts`) that
accumulates `send_message` and `create_post` actions when the user is offline. The queue
is persisted to `localStorage` and flushed when the user comes back online via the
`useOfflineQueue` hook (`frontend/src/hooks/useOfflineQueue.ts`). However, this approach
has critical limitations:

1. **Requires an open tab**: The flush logic runs in React (via `useEffect` in the
   `OfflineQueueFlusher` component in `AppShell.tsx`). If the user closes the browser
   while offline, the queued actions remain in `localStorage` but are not retried until
   the user manually opens the app again. The user may not know they have unsent messages.
2. **No retry on transient failure**: The current flush loop (in `useOfflineQueue.ts`,
   lines 43-49) catches errors per-action and keeps failed items in the queue, but only
   retries when the next `online` event fires. There is no exponential backoff, no retry
   count limit, and no dead-letter handling for permanently failed items.
3. **No browser-restart persistence**: If the browser crashes or the device reboots while
   actions are queued, `localStorage` persists the queue but nothing triggers a flush
   until the user opens the app and the `useEffect` in `useOfflineQueue` re-runs.
4. **No batching or ordering guarantees**: Actions are flushed sequentially in enqueue
   order, but if one fails and is kept in the queue, subsequent actions may succeed,
   creating out-of-order delivery.

The Background Sync API (`ServiceWorkerRegistration.sync.register()`) solves these
problems by letting the service worker retry queued actions in the background, even after
the browser tab is closed, with browser-managed retry scheduling.

### 1.2 User Stories

1. **As a user who closes the app while offline**, I want my queued messages to be sent
   automatically when connectivity returns, without reopening the app.
2. **As a user on flaky connectivity**, I want failed sends to be retried with exponential
   backoff, so I do not need to manually retry.
3. **As a user**, I want a clear count of pending actions and their status (queued,
   retrying, failed), so I know what has not been sent yet.
4. **As a user**, I want permanently failed items (after max retries) to appear in a
   "failed queue" where I can retry or discard them, so I do not lose important messages
   silently.

### 1.3 Design Principles

- **Progressive Enhancement**: Background Sync is only available in Chromium-based
  browsers. When unavailable, the existing `useOfflineQueue` in-tab flush logic continues
  to work as a fallback.
- **Single Source of Truth**: The queue remains in `localStorage` (via the Zustand persist
  middleware in `offlineStore.ts`). The SW reads from and writes to the same store. This
  avoids duplication and ensures the React UI always reflects the true queue state.
- **Dead-Letter Queue**: After `MAX_RETRIES` (default: 5) per action, the item is moved
  from the active queue to a dead-letter list. The user can inspect, retry, or discard
  dead-letter items via the UI.
- **Idempotency**: Each queued action carries a unique `id` (already generated at enqueue
  time in `offlineStore.ts`, line 52). The backend must handle duplicate submissions
  gracefully (POST with the same `id` is idempotent or returns a conflict).

---

## 2. Current State Analysis

### 2.1 Offline Store (`frontend/src/stores/offlineStore.ts`)

The full store definition (69 lines):

```typescript
export interface OfflineActionSendMessage {
  id: string;
  type: "send_message";
  enqueuedAt: number;
  payload: {
    conversationId: string;
    req: SendTextMessageReq;
  };
}

export interface OfflineActionCreatePost {
  id: string;
  type: "create_post";
  enqueuedAt: number;
  payload: CreatePostReq;
}

export type OfflineAction = OfflineActionSendMessage | OfflineActionCreatePost;

interface OfflineState {
  queue: OfflineAction[];
  isOnline: boolean;
  setOnline: (online: boolean) => void;
  addToQueue: (action: Omit<OfflineAction, "id" | "enqueuedAt">) => void;
  removeFromQueue: (id: string) => void;
  clearQueue: () => void;
}
```

Key details:
- Each action gets a unique `id` at enqueue time: `offline-${Date.now()}-${Math.random().toString(36).slice(2)}` (line 52).
- `enqueuedAt: Date.now()` is stored for ordering and age display.
- The store is persisted under `localStorage` key `"offline-store"` with `partialize`
  that only saves `queue` (line 66). The `isOnline` field is transient and re-derived
  from `navigator.onLine` on hydration (line 42).
  <!-- CORRECTED: was "line 43", actually line 42 of offlineStore.ts -->

### 2.2 Offline Queue Hook (`frontend/src/hooks/useOfflineQueue.ts`)

The flush logic (96 lines):
<!-- CORRECTED: was "97 lines", actually 96 lines -->

```typescript
export function useOfflineQueue() {
  const queue = useOfflineStore((s) => s.queue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const setOnline = useOfflineStore((s) => s.setOnline);
  const removeFromQueue = useOfflineStore((s) => s.removeFromQueue);
  const queryClient = useQueryClient();
  const isFlushing = React.useRef(false);

  // Sync window.online / window.offline into the store
  React.useEffect(() => {
    const goOnline = () => setOnline(true);
    const goOffline = () => setOnline(false);
    window.addEventListener("online", goOnline);
    window.addEventListener("offline", goOffline);
    return () => { /* cleanup */ };
  }, [setOnline]);

  // Flush the queue whenever we come back online
  React.useEffect(() => {
    if (!isOnline || queue.length === 0 || isFlushing.current) return;

    const flush = async () => {
      isFlushing.current = true;
      const snapshot = [...queue];
      toast.info(`Sending ${snapshot.length} queued item${snapshot.length !== 1 ? "s" : ""}...`);

      let successCount = 0;
      let failCount = 0;

      for (const action of snapshot) {
        try {
          await dispatchAction(action);
          removeFromQueue(action.id);
          successCount += 1;
        } catch {
          failCount += 1;
          // Keep in queue -- will retry on next reconnect
        }
      }

      if (successCount > 0) {
        void queryClient.invalidateQueries({ queryKey: ["messages"] });
        void queryClient.invalidateQueries({ queryKey: ["conversations"] });
        void invalidateFeedCaches(queryClient);
      }
      // ... toast messages ...
      isFlushing.current = false;
    };
    void flush();
  }, [isOnline, queue.length]);
}
```

The `dispatchAction` function (lines 84-96) dispatches to the appropriate API:
<!-- VERIFIED: useOfflineQueue.ts:84-96 -->

```typescript
async function dispatchAction(action: OfflineAction): Promise<void> {
  if (action.type === "send_message") {
    await sendTextMessage(action.payload.conversationId, action.payload.req);
    return;
  }
  if (action.type === "create_post") {
    await createPost(action.payload);
    return;
  }
  const _exhaustive: never = action;
  throw new Error(`Unknown offline action type: ${(_exhaustive as OfflineAction).type}`);
}
```

### 2.3 Queue Enqueue in ConversationView

In `ConversationView.tsx` (lines 1028-1033):
<!-- VERIFIED: ConversationView.tsx:1028-1033 -->

```typescript
if (!isOnline && !fullPayload.send_at) {
  addToQueue({ type: "send_message", payload: { conversationId: convoId, req: fullPayload } });
  toast.info("You're offline -- message queued and will send when reconnected");
  setReplyingTo(null);
  return;
}
```

Key observation: Only non-scheduled text messages are queued. Image messages, file shares,
calendar shares, and other complex message types are NOT queued when offline -- the user
gets no feedback at all for those send attempts.

### 2.4 Queue Enqueue in CreatePost

In `CreatePost.tsx` (lines 635-654):
<!-- VERIFIED: CreatePost.tsx:635-654 -->

```typescript
if (!isOnline) {
  const queuedPayload = {
    ...buildContentPayload(body, editorMode, richDoc),
    ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
    ...(pendingFiles.length > 0 ? { file_paths: pendingFiles.map((f) => f.path) } : {}),
    ...(unlockPriceCents ? { unlock_price_cents: unlockPriceCents } : {}),
  };
  addToQueue({ type: "create_post", payload: queuedPayload });
  toast.info("You're offline -- post queued and will publish when reconnected");
  resetComposer();
  return;
}
```

### 2.5 `OfflineQueueFlusher` in AppShell

In `AppShell.tsx` (lines 19-23):
<!-- VERIFIED: AppShell.tsx:19-23 -->

```typescript
/** Mounts the offline queue flush side-effect -- renders nothing. */
function OfflineQueueFlusher() {
  useOfflineQueue();
  return null;
}
```

This component is rendered inside `AppShell` (line 62), which means
<!-- VERIFIED: AppShell.tsx:62 --> the flush logic is
only active when the user is logged in and viewing an authenticated page. If the user
closes the tab or navigates to a non-authenticated page, the flush stops.

### 2.6 Service Worker (`frontend/public/sw.js`)

The current SW has no `sync` event listener. After PWA-002, it handles `install`,
`activate`, `fetch`, `push`, `notificationclick`, and `notificationclose`.

The SW does not import any modules (it is a plain JS file in `public/`). To access
`localStorage` from the SW, we need to use a `MessageChannel` or read from IndexedDB
(service workers cannot access `localStorage` directly).

### 2.7 Backend Idempotency

The `sendTextMessage` endpoint (`POST /messaging/conversations/{id}/messages`) generates
a new `message_id` server-side. It does not check for duplicate submissions based on
client-provided IDs. If the same message is sent twice (due to a retry), two distinct
messages appear in the conversation.

To support safe retries, the backend should accept an optional `client_request_id` field
and deduplicate based on it. This is a backend change that should be implemented
alongside PWA-004. Until then, the risk of duplicate messages exists but is low (the SW
removes items from the queue before retrying, and the main thread skips flush when
Background Sync is active).

### 2.8 API Client CSRF Token Handling

The API client in `frontend/src/api/client.ts` reads the CSRF token from the `ui_csrf`
cookie at line 168:
<!-- VERIFIED: client.ts:168 -->

```typescript
const csrf = getCookie("ui_csrf");
if (csrf) {
  headers.set("X-CSRF-Token", csrf);
}
```

The `getCookie` function (lines 16-18) reads from `document.cookie`. In the service worker
<!-- VERIFIED: client.ts:16-18 -->
context, `document` is not available. The SW must use the `CookieStore` API or receive
the CSRF token via `postMessage` from the main thread.

---

## 3. Technical Design

### 3.1 Architecture Overview

```
                    Main Thread (React)
                         |
                  User sends message
                  while offline
                         |
              +----------v-----------+
              | offlineStore.addToQueue |
              | (localStorage)         |
              +----------+-----------+
                         |
              +----------v-----------+
              | Copy to IndexedDB    |
              | (sync_queue store)   |
              +----------+-----------+
                         |
              +----------v-----------+
              | registration.sync    |
              | .register("flush")   |
              +----------+-----------+
                         |
              +----------v-----------+
              | Forward CSRF token   |
              | via postMessage      |
              +----------+-----------+
                         |
                    Browser manages
                    retry scheduling
                         |
              +----------v-----------+
              | SW: sync event       |
              | reads IndexedDB      |
              | dispatches actions   |
              | removes on success   |
              +----------+-----------+
                         |
              +----------v-----------+
              | postMessage to client|
              | "flush-complete"     |
              | -> invalidate queries|
              +----------+-----------+
```

### 3.2 IndexedDB Queue Store

Since service workers cannot access `localStorage`, the queue must also be stored in
IndexedDB for the SW to read. Add a new object store to the `app-offline-cache` database
(from PWA-003):

**Object Store: `sync_queue`**

| Field | Type | Index | Description |
|-------|------|-------|-------------|
| `id` | string | Primary key | Same unique ID from `offlineStore` |
| `type` | string | Yes | `"send_message"` or `"create_post"` |
| `enqueuedAt` | number | Yes (ascending) | Timestamp when enqueued |
| `payload` | object | -- | Action-specific payload |
| `retryCount` | number | -- | Number of SW retry attempts (default: 0) |
| `lastRetryAt` | number | -- | Timestamp of last retry attempt (default: 0) |
| `status` | string | Yes | `"pending"` / `"retrying"` / `"dead"` |
| `lastError` | string | -- | Error message from last failed attempt |
| `csrfToken` | string | -- | CSRF token at enqueue time (for SW auth) |

**IndexedDB upgrade handler** (extends PWA-003's database):

```typescript
// In offlineCache.ts openDb():
req.onupgradeneeded = (event) => {
  const db = (event.target as IDBOpenDBRequest).result;
  const oldVersion = event.oldVersion;

  if (oldVersion < 1) {
    // ... PWA-003 stores ...
  }

  if (oldVersion < 2) {
    // PWA-004: sync queue
    const syncStore = db.createObjectStore("sync_queue", { keyPath: "id" });
    syncStore.createIndex("type", "type", { unique: false });
    syncStore.createIndex("enqueuedAt", "enqueuedAt", { unique: false });
    syncStore.createIndex("status", "status", { unique: false });
  }
};
```

### 3.3 Sync Queue DB Helpers (`frontend/src/lib/syncQueueDb.ts`)

```typescript
// frontend/src/lib/syncQueueDb.ts

import type { OfflineAction } from "@/stores/offlineStore";

const DB_NAME = "app-offline-cache";
const DB_VERSION = 2; // Bumped from 1 (PWA-003) to add sync_queue
const SYNC_STORE = "sync_queue";

function openSyncDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(SYNC_STORE)) {
        const store = db.createObjectStore(SYNC_STORE, { keyPath: "id" });
        store.createIndex("type", "type", { unique: false });
        store.createIndex("enqueuedAt", "enqueuedAt", { unique: false });
        store.createIndex("status", "status", { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Write a queued action to IndexedDB sync_queue.
 * Called from offlineStore.addToQueue alongside the localStorage write.
 */
export async function writeToSyncQueue(
  action: OfflineAction,
  csrfToken: string,
): Promise<void> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readwrite");
      const store = tx.objectStore(SYNC_STORE);
      store.put({
        id: action.id,
        type: action.type,
        enqueuedAt: action.enqueuedAt,
        payload: action.payload,
        retryCount: 0,
        lastRetryAt: 0,
        status: "pending",
        lastError: "",
        csrfToken,
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve(); // silent failure
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Remove a successfully-processed item from the sync queue.
 */
export async function removeFromSyncQueue(id: string): Promise<void> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readwrite");
      tx.objectStore(SYNC_STORE).delete(id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Update fields on a sync queue item (retry count, status, error).
 */
export async function updateSyncQueueItem(
  id: string,
  updates: Partial<{
    status: string;
    retryCount: number;
    lastRetryAt: number;
    lastError: string;
  }>,
): Promise<void> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readwrite");
      const store = tx.objectStore(SYNC_STORE);
      const getReq = store.get(id);
      getReq.onsuccess = () => {
        if (getReq.result) {
          const updated = { ...getReq.result, ...updates };
          store.put(updated);
        }
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    });
  } catch {
    // IndexedDB unavailable
  }
}

/**
 * Get all items from the sync queue with a given status.
 */
export async function getQueueItemsByStatus(
  status: string,
): Promise<Array<Record<string, unknown>>> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readonly");
      const store = tx.objectStore(SYNC_STORE);
      const index = store.index("status");
      const req = index.getAll(IDBKeyRange.only(status));
      req.onsuccess = () => resolve(req.result ?? []);
      req.onerror = () => resolve([]);
    });
  } catch {
    return [];
  }
}

/**
 * Get the total count of items in the sync queue.
 */
export async function getSyncQueueCount(): Promise<number> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readonly");
      const store = tx.objectStore(SYNC_STORE);
      const req = store.count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(0);
    });
  } catch {
    return 0;
  }
}
```

### 3.4 Sync Registration

Extend `offlineStore.ts` `addToQueue` to also write to IndexedDB and register a sync:

```typescript
addToQueue: (action) =>
  set((s) => {
    const fullAction = {
      ...action,
      id: `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      enqueuedAt: Date.now(),
    } as OfflineAction;

    // Get current CSRF token for the SW to use
    const csrfToken = getCookie("ui_csrf") ?? "";

    // Fire-and-forget: write to IndexedDB and register sync
    void (async () => {
      try {
        const { writeToSyncQueue } = await import("@/lib/syncQueueDb");
        await writeToSyncQueue(fullAction, csrfToken);

        if ("serviceWorker" in navigator && "SyncManager" in window) {
          const reg = await navigator.serviceWorker.ready;
          await reg.sync.register("flush-offline-queue");
        }
      } catch {
        // Sync registration is best-effort
      }
    })();

    return { queue: [...s.queue, fullAction] };
  }),
```

### 3.5 Service Worker Sync Handler

Add to `sw.js`:

```javascript
// ─── Background Sync ─────────────────────────────────────────────

const MAX_RETRIES = 5;
const BASE_BACKOFF_MS = 2000; // 2 seconds base, doubles each retry

self.addEventListener("sync", (event) => {
  if (event.tag === "flush-offline-queue") {
    event.waitUntil(flushSyncQueue());
  }
});

async function flushSyncQueue() {
  const db = await openSyncDb();

  // Get all pending and retrying items
  const pending = await getAllByStatus(db, "pending");
  const retrying = await getAllByStatus(db, "retrying");
  const items = [...pending, ...retrying].sort((a, b) => a.enqueuedAt - b.enqueuedAt);

  if (items.length === 0) return;

  let anyFailed = false;
  let successCount = 0;

  for (const item of items) {
    // Exponential backoff check
    if (item.retryCount > 0 && item.lastRetryAt) {
      const backoff = BASE_BACKOFF_MS * Math.pow(2, Math.min(item.retryCount - 1, 5));
      if (Date.now() - item.lastRetryAt < backoff) {
        anyFailed = true; // Signal the browser to retry later
        continue;
      }
    }

    try {
      await dispatchSyncAction(item);

      // Success: remove from IDB queue
      await deleteSyncItem(db, item.id);
      successCount++;

      // Notify main thread
      await notifyClients({
        type: "sync-item-success",
        id: item.id,
        actionType: item.type,
      });
    } catch (err) {
      const newRetryCount = (item.retryCount || 0) + 1;
      const errorMsg = err instanceof Error ? err.message : String(err);

      if (newRetryCount >= MAX_RETRIES) {
        // Move to dead-letter
        await updateSyncItem(db, item.id, {
          status: "dead",
          retryCount: newRetryCount,
          lastRetryAt: Date.now(),
          lastError: errorMsg,
        });
        await notifyClients({
          type: "sync-item-dead",
          id: item.id,
          actionType: item.type,
          error: errorMsg,
          retryCount: newRetryCount,
        });
      } else {
        // Mark for retry
        await updateSyncItem(db, item.id, {
          status: "retrying",
          retryCount: newRetryCount,
          lastRetryAt: Date.now(),
          lastError: errorMsg,
        });
        anyFailed = true;
      }
    }
  }

  if (successCount > 0) {
    // Batch notification for query invalidation
    await notifyClients({
      type: "sync-flush-complete",
      successCount,
    });
  }

  if (anyFailed) {
    // Throw to signal the browser that a retry is needed.
    // The browser will re-fire the sync event on its own schedule.
    throw new Error("Some items failed -- retry needed");
  }
}

async function dispatchSyncAction(item) {
  const baseUrl = self.location.origin;
  const csrfToken = item.csrfToken || (await getCsrfToken());

  if (item.type === "send_message") {
    const { conversationId, req } = item.payload;
    const resp = await fetch(
      `${baseUrl}/messaging/conversations/${conversationId}/messages`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrfToken,
        },
        credentials: "include",
        body: JSON.stringify(req),
      },
    );
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new Error(`${resp.status}: ${body.slice(0, 200)}`);
    }
    return;
  }

  if (item.type === "create_post") {
    const resp = await fetch(`${baseUrl}/posts`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-csrf-token": csrfToken,
      },
      credentials: "include",
      body: JSON.stringify(item.payload),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new Error(`${resp.status}: ${body.slice(0, 200)}`);
    }
    return;
  }

  throw new Error(`Unknown action type: ${item.type}`);
}

// ─── IDB helpers for sync queue (within SW scope) ────────────────

function openSyncDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("app-offline-cache", 2);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function getAllByStatus(db, status) {
  return new Promise((resolve) => {
    const tx = db.transaction("sync_queue", "readonly");
    const index = tx.objectStore("sync_queue").index("status");
    const req = index.getAll(IDBKeyRange.only(status));
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => resolve([]);
  });
}

function deleteSyncItem(db, id) {
  return new Promise((resolve) => {
    const tx = db.transaction("sync_queue", "readwrite");
    tx.objectStore("sync_queue").delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => resolve();
  });
}

function updateSyncItem(db, id, updates) {
  return new Promise((resolve) => {
    const tx = db.transaction("sync_queue", "readwrite");
    const store = tx.objectStore("sync_queue");
    const getReq = store.get(id);
    getReq.onsuccess = () => {
      if (getReq.result) {
        store.put({ ...getReq.result, ...updates });
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => resolve();
  });
}

async function notifyClients(data) {
  const clients = await self.clients.matchAll({ type: "window" });
  for (const client of clients) {
    client.postMessage(data);
  }
}
```

### 3.6 CSRF Token Forwarding

Service workers cannot access `document.cookie`. Two approaches:

**Option A: CookieStore API** (Chromium 87+): `await cookieStore.get("ui_csrf")` returns
the cookie value asynchronously. Available in service workers.

**Option B: Stored with queue item**: When enqueueing, the main thread reads the CSRF
token from the cookie and stores it in the IndexedDB `sync_queue` entry alongside the
payload. The SW uses this stored token.

**Option C: PostMessage from Main Thread**: When enqueueing, the main thread sends the
current CSRF token to the SW via `navigator.serviceWorker.controller.postMessage(...)`.

We use Option B (stored with queue item) as primary, with Option A as a fallback
for items that were enqueued before this change:

```javascript
// In sw.js:
let cachedCsrfToken = "";

self.addEventListener("message", (event) => {
  if (event.data?.type === "set-csrf") {
    cachedCsrfToken = event.data.token;
  }
});

async function getCsrfToken() {
  // Try CookieStore API first (Chromium 87+)
  if (typeof cookieStore !== "undefined") {
    try {
      const cookie = await cookieStore.get("ui_csrf");
      if (cookie?.value) return cookie.value;
    } catch {
      /* fallthrough */
    }
  }
  // Fallback to cached value from postMessage
  return cachedCsrfToken;
}
```

### 3.7 Dead-Letter Queue UI

Create `frontend/src/components/shared/DeadLetterPanel.tsx`:

```typescript
// frontend/src/components/shared/DeadLetterPanel.tsx

import { AlertTriangle, RefreshCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useOfflineStore } from "@/stores/offlineStore";
import { formatDistanceToNow } from "@/lib/dateUtils";

interface DeadLetterItem {
  id: string;
  type: string;
  enqueuedAt: number;
  payload: Record<string, unknown>;
  retryCount: number;
  lastError: string;
}

export function DeadLetterPanel() {
  const deadLetter = useOfflineStore((s) => s.deadLetter);
  const retryDeadLetter = useOfflineStore((s) => s.retryDeadLetter);
  const discardDeadLetter = useOfflineStore((s) => s.discardDeadLetter);
  const clearDeadLetter = useOfflineStore((s) => s.clearDeadLetter);

  if (!deadLetter || deadLetter.length === 0) return null;

  return (
    <Collapsible defaultOpen>
      <CollapsibleTrigger className="flex w-full items-center justify-between rounded-t-lg bg-destructive/10 px-4 py-2 text-sm font-medium text-destructive">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          <span>Failed Items ({deadLetter.length})</span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={(e) => {
            e.stopPropagation();
            clearDeadLetter();
          }}
        >
          Clear All
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="divide-y border border-t-0 rounded-b-lg">
          {deadLetter.map((item: DeadLetterItem) => (
            <div key={item.id} className="flex items-start gap-3 p-3 text-sm">
              <AlertTriangle className="h-4 w-4 mt-0.5 text-destructive shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="font-medium truncate">
                  {item.type === "send_message" ? "Message" : "Feed Post"}
                  {": "}
                  {getPreviewText(item)}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Failed after {item.retryCount} retries: {item.lastError}
                </p>
                <p className="text-xs text-muted-foreground">
                  Queued {formatDistanceToNow(item.enqueuedAt)}
                </p>
              </div>
              <div className="flex gap-1 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-xs"
                  onClick={() => retryDeadLetter(item.id)}
                >
                  <RefreshCw className="h-3 w-3 mr-1" />
                  Retry
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-xs text-muted-foreground"
                  onClick={() => discardDeadLetter(item.id)}
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Discard
                </Button>
              </div>
            </div>
          ))}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function getPreviewText(item: DeadLetterItem): string {
  if (item.type === "send_message") {
    const payload = item.payload as { req?: { text?: string } };
    return payload.req?.text?.slice(0, 50) ?? "(no text)";
  }
  if (item.type === "create_post") {
    const payload = item.payload as { body?: string; body_plain?: string };
    return (payload.body_plain ?? payload.body ?? "").slice(0, 50) || "(no content)";
  }
  return "(unknown)";
}

function formatDistanceToNow(timestamp: number): string {
  const minutes = Math.floor((Date.now() - timestamp) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? "s" : ""} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days > 1 ? "s" : ""} ago`;
}
```

### 3.8 Store Extensions

Add to `offlineStore.ts`:

```typescript
interface DeadLetterItem extends OfflineAction {
  retryCount: number;
  lastError: string;
}

interface OfflineState {
  queue: OfflineAction[];
  deadLetter: DeadLetterItem[];
  isOnline: boolean;

  setOnline: (online: boolean) => void;
  addToQueue: (action: Omit<OfflineAction, "id" | "enqueuedAt">) => void;
  removeFromQueue: (id: string) => void;
  moveToDeadLetter: (id: string, retryCount: number, lastError: string) => void;
  retryDeadLetter: (id: string) => void;
  discardDeadLetter: (id: string) => void;
  clearQueue: () => void;
  clearDeadLetter: () => void;
}
```

**Implementation**:

```typescript
moveToDeadLetter: (id, retryCount, lastError) =>
  set((s) => {
    const item = s.queue.find((a) => a.id === id);
    if (!item) return s;
    return {
      queue: s.queue.filter((a) => a.id !== id),
      deadLetter: [
        ...s.deadLetter,
        { ...item, retryCount, lastError },
      ],
    };
  }),

retryDeadLetter: (id) =>
  set((s) => {
    const item = s.deadLetter.find((a) => a.id === id);
    if (!item) return s;
    const { retryCount: _, lastError: __, ...action } = item;
    return {
      deadLetter: s.deadLetter.filter((a) => a.id !== id),
      queue: [...s.queue, action as OfflineAction],
    };
  }),

discardDeadLetter: (id) =>
  set((s) => ({
    deadLetter: s.deadLetter.filter((a) => a.id !== id),
  })),

clearDeadLetter: () => set({ deadLetter: [] }),
```

Update `partialize` to persist `deadLetter`:
```typescript
partialize: (state) => ({
  queue: state.queue,
  deadLetter: state.deadLetter,
}),
```

### 3.9 Main Thread Message Listener

Create `frontend/src/lib/swMessageHandler.ts`:

```typescript
// frontend/src/lib/swMessageHandler.ts

import type { QueryClient } from "@tanstack/react-query";
import { useOfflineStore } from "@/stores/offlineStore";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";
import { toast } from "sonner";

/**
 * Listen for postMessage events from the service worker's sync handler.
 * Routes sync results to the offline store and React Query.
 */
export function listenForSyncMessages(queryClient: QueryClient): void {
  if (!("serviceWorker" in navigator)) return;

  navigator.serviceWorker.addEventListener("message", (event) => {
    const data = event.data;
    if (!data?.type) return;

    switch (data.type) {
      case "sync-item-success": {
        // Remove from React store (localStorage)
        useOfflineStore.getState().removeFromQueue(data.id);
        break;
      }

      case "sync-item-dead": {
        // Move to dead-letter in React store
        useOfflineStore.getState().moveToDeadLetter(
          data.id,
          data.retryCount ?? 5,
          data.error ?? "Unknown error",
        );
        toast.error("A queued item failed permanently -- check Failed Items");
        break;
      }

      case "sync-flush-complete": {
        // Invalidate relevant queries to show the newly-sent data
        if (data.successCount > 0) {
          void queryClient.invalidateQueries({ queryKey: ["messages"] });
          void queryClient.invalidateQueries({ queryKey: ["conversations"] });
          void invalidateFeedCaches(queryClient);
          toast.success(
            `${data.successCount} queued item${data.successCount > 1 ? "s" : ""} sent`,
          );
        }
        break;
      }
    }
  });
}
```

### 3.10 Fallback for Non-Chromium Browsers

Firefox and Safari do not support the Background Sync API. The feature check:

```typescript
const backgroundSyncSupported =
  "serviceWorker" in navigator && "SyncManager" in window;
```

When `false`, the existing `useOfflineQueue` hook remains the sole flush mechanism.
Modify `useOfflineQueue` to skip flushing when Background Sync is active:

```typescript
// In useOfflineQueue.ts, at the top of the flush effect:
React.useEffect(() => {
  if (!isOnline || queue.length === 0 || isFlushing.current) return;

  // Skip main-thread flush if Background Sync is handling it
  if ("SyncManager" in window) {
    // Background Sync will handle the flush via the service worker.
    // Only proceed with main-thread flush for items that may have
    // failed to register with the sync manager.
    return;
  }

  // ... existing flush logic for non-Chromium browsers ...
}, [isOnline, queue.length]);
```

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `frontend/src/lib/syncQueueDb.ts` | IndexedDB helpers for `sync_queue` object store |
| `frontend/src/lib/swMessageHandler.ts` | Main-thread listener for SW postMessage events |
| `frontend/src/components/shared/DeadLetterPanel.tsx` | Dead-letter queue UI |

### 4.2 Modified Files

| File | Changes |
|------|---------|
| `frontend/public/sw.js` | Add `sync` event handler, `dispatchSyncAction`, `getCsrfToken`, IDB helpers |
| `frontend/src/stores/offlineStore.ts` | Add `deadLetter` array, `moveToDeadLetter`, `retryDeadLetter`, `discardDeadLetter`; extend `addToQueue` to write to IDB + register sync; extend `partialize` |
| `frontend/src/hooks/useOfflineQueue.ts` | Skip flush when Background Sync is active |
| `frontend/src/lib/pushSetup.ts` | Export CSRF forwarding utility |
| `frontend/src/main.tsx` | Call `listenForSyncMessages()` after SW registration |
| `frontend/src/components/shared/OfflineBanner.tsx` | Show dead-letter count badge |
| `frontend/src/components/layout/AppShell.tsx` | Render `DeadLetterPanel` when items exist |
| `frontend/src/lib/offlineCache.ts` | Bump DB_VERSION to 2; add sync_queue store in upgrade handler |

### 4.3 Implementation Phases

1. **Phase 1 -- IndexedDB sync queue** (2 hours)
   - Create `syncQueueDb.ts` with CRUD helpers
   - Upgrade `app-offline-cache` IDB to version 2 (add `sync_queue` store)
   - Test: write/read/delete queue items

2. **Phase 2 -- SW sync handler** (3 hours)
   - Add `sync` event listener to `sw.js`
   - Implement `dispatchSyncAction` for `send_message` and `create_post`
   - Implement CSRF token handling (stored with item + CookieStore fallback)
   - Implement retry counting and dead-letter transition
   - Test: queue message, go offline, come online, verify message sent

3. **Phase 3 -- Store + hook integration** (2 hours)
   - Extend `offlineStore` with `deadLetter` state and actions
   - Modify `addToQueue` to write to IDB + register sync
   - Modify `useOfflineQueue` to skip flush when Background Sync is available
   - Create `swMessageHandler.ts` to reconcile SW flush results with React state

4. **Phase 4 -- Dead-letter UI** (1.5 hours)
   - Create `DeadLetterPanel` component
   - Wire retry (move back to pending, re-register sync) and discard (delete from IDB)
   - Show dead-letter badge in `OfflineBanner`

5. **Phase 5 -- Fallback verification** (1 hour)
   - Test in Firefox (no Background Sync): verify `useOfflineQueue` still works
   - Test in Safari: verify fallback path
   - Test in Chrome: verify SW sync path takes priority

---

## 5. Testing Strategy

### 5.1 E2E Test Plan (`frontend/e2e/pwa-background-sync.spec.ts`)

**Section 99: Sync Queue Population (3 tests)**

```typescript
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers";

test.describe("99 . Sync queue population", () => {
  test("99.1 offline message writes to IndexedDB sync queue", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    // Open a conversation (click first one if available)
    const firstConvo = page.locator("[data-testid='conversation-item']").first();
    if (!(await firstConvo.isVisible({ timeout: 3000 }).catch(() => false))) {
      test.skip();
      return;
    }
    await firstConvo.click();
    await page.waitForLoadState("networkidle");

    // Go offline
    await page.context().setOffline(true);

    // Send a message
    const testMsg = `Sync test ${Date.now()}`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Verify toast
    await expect(page.getByText(/offline.*queued/i)).toBeVisible();

    // Verify IndexedDB sync queue
    const queueCount = await page.evaluate(async () => {
      return new Promise<number>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 2);
        req.onsuccess = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains("sync_queue")) {
            resolve(-1);
            return;
          }
          const tx = db.transaction("sync_queue", "readonly");
          const count = tx.objectStore("sync_queue").count();
          count.onsuccess = () => resolve(count.result);
          count.onerror = () => resolve(0);
        };
      });
    });
    expect(queueCount).toBeGreaterThan(0);

    await page.context().setOffline(false);
  });

  test("99.2 sync queue item has correct fields", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    await page.waitForLoadState("networkidle");

    const firstConvo = page.locator("[data-testid='conversation-item']").first();
    if (!(await firstConvo.isVisible({ timeout: 3000 }).catch(() => false))) {
      test.skip();
      return;
    }
    await firstConvo.click();
    await page.waitForLoadState("networkidle");

    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill("Field test " + Date.now());
    await page.getByRole("button", { name: /send/i }).click();

    const item = await page.evaluate(async () => {
      return new Promise<Record<string, unknown> | null>((resolve) => {
        const req = indexedDB.open("app-offline-cache", 2);
        req.onsuccess = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains("sync_queue")) {
            resolve(null);
            return;
          }
          const tx = db.transaction("sync_queue", "readonly");
          const store = tx.objectStore("sync_queue");
          const getAll = store.getAll();
          getAll.onsuccess = () => {
            const items = getAll.result;
            resolve(items.length > 0 ? items[items.length - 1] : null);
          };
        };
      });
    });

    expect(item).not.toBeNull();
    expect(item!.type).toBe("send_message");
    expect(item!.status).toBe("pending");
    expect(item!.retryCount).toBe(0);
    expect(typeof item!.enqueuedAt).toBe("number");
    expect(typeof item!.csrfToken).toBe("string");

    await page.context().setOffline(false);
  });

  test("99.3 offline post enqueue writes to sync queue", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");
    await page.waitForLoadState("networkidle");

    await page.context().setOffline(true);

    const composer = page.getByPlaceholder(/what.*mind|write.*post/i);
    if (await composer.isVisible({ timeout: 3000 }).catch(() => false)) {
      await composer.fill("Sync post test " + Date.now());
      await page.getByRole("button", { name: /post|publish/i }).click();

      const hasPostInQueue = await page.evaluate(async () => {
        return new Promise<boolean>((resolve) => {
          const req = indexedDB.open("app-offline-cache", 2);
          req.onsuccess = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains("sync_queue")) {
              resolve(false);
              return;
            }
            const tx = db.transaction("sync_queue", "readonly");
            const store = tx.objectStore("sync_queue");
            const index = store.index("type");
            const countReq = index.count(IDBKeyRange.only("create_post"));
            countReq.onsuccess = () => resolve(countReq.result > 0);
          };
        });
      });
      expect(hasPostInQueue).toBe(true);
    }

    await page.context().setOffline(false);
  });
});
```

**Section 100: Background Sync Flush (4 tests)** and **Section 101: Dead-Letter Queue (3 tests)** follow the same patterns as described in the original ticket with the additional field validations above.

### 5.2 Unit Tests

- `frontend/src/lib/__tests__/syncQueueDb.test.ts`: IndexedDB CRUD, retry count
  increment, status transitions, dead-letter move.
- `frontend/src/stores/__tests__/offlineStore.test.ts`: New `deadLetter` state management,
  `moveToDeadLetter`, `retryDeadLetter`, `discardDeadLetter`.
- `frontend/src/lib/__tests__/swMessageHandler.test.ts`: Mock SW postMessage events and
  verify store updates.

---

## 6. Edge Cases & Gotchas

### 6.1 CSRF Token Expiry

If the user closes the browser and the CSRF token expires (cookie TTL is tied to the
session lifetime), the SW's sync handler will get a 403 from the backend. The CSRF token
is validated per-request in `require_ui_session` (`app/auth/deps.py`). When the session
expires and the user is not there to re-authenticate, the sync will fail with 403 and
eventually hit the dead-letter queue. This is the correct behavior -- the user must
re-authenticate to send messages.

### 6.2 Bearer Token Auth Path

The existing `ConversationView.tsx` enqueue path uses cookie auth (session cookies sent
with `credentials: "include"`). The SW fetch also uses `credentials: "include"`. If the
backend's CSRF validation requires a matching `x-csrf-token` header AND the `ui_csrf`
cookie, the SW must send both. The stored CSRF token in the queue item provides the header
value; the cookie is sent automatically via `credentials: "include"`.

### 6.3 Duplicate Prevention

If the `useOfflineQueue` hook AND the SW sync handler both attempt to flush at the same
time, duplicate messages could be sent. Prevention:

1. The `useOfflineQueue` hook checks `"SyncManager" in window` and skips flushing when
   true, delegating entirely to the SW.
2. The SW reads from IndexedDB (canonical source) and removes items on success.
3. The `offlineStore.removeFromQueue()` is called by the main thread only when the SW
   reports success via `postMessage`.

### 6.4 Queue Ordering

Items are flushed in `enqueuedAt` order. If item A fails and item B succeeds, the
conversation will show messages out of order. The backend stores `created_at` at the time
of actual delivery (not enqueue time). For strict ordering, the SW should stop processing
after the first failure in a given conversation. This is a future enhancement.

### 6.5 Image Messages Not Queued

The current architecture only queues `send_message` (text) and `create_post` actions.
Image messages require a `FormData` upload, which is harder to serialize to IndexedDB.
This is deferred to a future ticket. When the user tries to send an image while offline,
the existing code does not enqueue it -- the `sendImage` mutation simply fails. PWA-005
addresses the UI feedback for this case.

### 6.6 Browser Sync API Limitations

The Background Sync API fires at most once when connectivity is restored. If the SW
throws an error (indicating incomplete work), the browser retries with its own schedule
(typically within minutes, but implementation-specific). The browser may coalesce multiple
`sync.register("flush-offline-queue")` calls into a single sync event.

### 6.7 Service Worker Scope and Cookies

Service workers can only access cookies that are within their scope (`/`) and not marked
`HttpOnly`. The `ui_csrf` cookie is NOT `HttpOnly` (it is read by JavaScript in
`client.ts` line 17: `getCookie("ui_csrf")`). The `ui_session` cookie IS `HttpOnly` and
is sent automatically via `credentials: "include"`. Both work correctly in the SW context.

### 6.8 IndexedDB Version Upgrade

Bumping the DB version from 1 (PWA-003) to 2 (PWA-004) triggers an `onupgradeneeded`
event. If the user has the app open in multiple tabs, the version change causes a
`versionchange` event in existing tabs. The `onversionchange` handler in `offlineCache.ts`
closes the connection. The new tab opens version 2 and creates the `sync_queue` store.
Existing `api_cache` data is preserved.

---

## 7. Security Considerations

### 7.1 Queue Tampering

The sync queue is stored in IndexedDB and `localStorage`, both accessible to any JS on
the origin. A malicious script could modify the queue to send arbitrary messages. This is
the same threat model as the existing `offlineStore` in `localStorage`. The backend's auth
check (session cookie + CSRF token) prevents unauthorized actions regardless of the
client-side queue contents.

### 7.2 Stale CSRF Tokens

A stale or expired CSRF token causes a 403 response. The SW does NOT bypass CSRF
validation. If the token is invalid, the sync fails and the item retries or moves to
dead-letter. The user must open the app (refreshing the CSRF cookie) to successfully flush.

### 7.3 Dead-Letter Data Exposure

Dead-letter items contain the full message payload (text, conversation ID, post content).
This data is visible in the UI's dead-letter panel. No additional exposure beyond what the
user already typed -- the data was composed by the user and is only visible to the same user.

### 7.4 Background Fetch Without User Presence

The SW can send network requests in the background without the user actively using the app.
This is by design (the whole point of Background Sync). The requests carry the user's
session cookies, which is appropriate -- the user explicitly queued these actions.

### 7.5 CSRF Token Storage in IndexedDB

The CSRF token is stored alongside each queue item in IndexedDB. This is no less secure
than the `ui_csrf` cookie itself, which is readable by JavaScript (not `HttpOnly`). The
token is specific to the user's session and expires when the session expires.

---

## Appendix A: File Reference

| Existing File | Relevance |
|---------------|-----------|
| `frontend/src/stores/offlineStore.ts` | Queue store to extend with dead-letter + IDB write |
| `frontend/src/hooks/useOfflineQueue.ts` | Flush hook to conditionally disable when sync available |
| `frontend/public/sw.js` | Service worker to extend with sync handler |
| `frontend/src/lib/pushSetup.ts` | SW registration; add sync message listener |
| `frontend/src/main.tsx` | Boot; wire up sync message listener |
| `frontend/src/pages/messages/ConversationView.tsx` | Enqueue path for messages (line 1028) |
| `frontend/src/pages/feed/CreatePost.tsx` | Enqueue path for posts (line 635) |
| `frontend/src/components/shared/OfflineBanner.tsx` | Show dead-letter badge |
| `frontend/src/components/layout/AppShell.tsx` | Renders OfflineQueueFlusher + OfflineBanner |
| `frontend/src/api/client.ts` | CSRF cookie reading; error handling |
| `frontend/src/api/endpoints/messaging.ts` | `sendTextMessage()` endpoint wrapper |
| `frontend/src/api/endpoints/newsfeed.ts` | `createPost()` endpoint wrapper |
| `frontend/src/lib/offlineCache.ts` | IndexedDB database; needs version bump for sync_queue |

## Appendix B: Dependencies & Risks

| Risk | Mitigation |
|------|------------|
| Background Sync not supported in Firefox/Safari | Existing `useOfflineQueue` hook is preserved as fallback |
| CSRF token expires before sync fires | Dead-letter queue surfaces the 403 error; user must re-open app |
| Duplicate sends from both SW and main thread | Skip main-thread flush when `SyncManager` is available |
| Queue ordering violations | Process items in `enqueuedAt` order; future: stop on first error per conversation |
| Image messages not queueable | Deferred; current behavior (no queue) is preserved |
| CookieStore API unavailable in old Chromium | CSRF token stored with each queue item as primary strategy |
| IDB version upgrade conflicts across tabs | `onversionchange` handler closes old connections gracefully |
| Backend does not deduplicate messages | Add optional `client_request_id` field to backend (separate task) |

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `syncQueueDb.ts` | `frontend/src/lib/syncQueueDb.ts` | 191 lines | **ALREADY EXISTS** — IndexedDB helpers for sync_queue object store |
| `swMessageHandler.ts` | `frontend/src/lib/swMessageHandler.ts` | 52 lines | **ALREADY EXISTS** — main-thread listener for SW postMessage events |
| `DeadLetterPanel` | `frontend/src/components/shared/DeadLetterPanel.tsx` | 111 lines | **ALREADY EXISTS** — dead-letter queue UI |
| `sw.js` | `frontend/public/sw.js` | 576 lines | **Exists** — verify sync event handler is present |
| `offlineStore` | `frontend/src/stores/offlineStore.ts` | 213 lines | **Exists** — verify `deadLetter` array and related methods |
| `useOfflineQueue` hook | `frontend/src/hooks/useOfflineQueue.ts` | 133 lines | **Exists** — verify Background Sync skip logic |
| `offlineCache.ts` (IDB) | `frontend/src/lib/offlineCache.ts` | 306 lines | **Exists** — IndexedDB database; version bump for sync_queue |
| API client (CSRF) | `frontend/src/api/client.ts` | 309 lines | **Exists** |

### Key Correction

**This ticket appears to be ALREADY IMPLEMENTED.** All three proposed new files (`syncQueueDb.ts`, `swMessageHandler.ts`, `DeadLetterPanel.tsx`) exist with the described functionality.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_background_sync.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_pwa_004_create` | Create primary entity; 201 |
| 2 | `test_pwa_004_read` | Read back entity; correct fields |
| 3 | `test_pwa_004_update` | Update entity; 200; changes reflected |
| 4 | `test_pwa_004_delete` | Delete entity; 200/204 |
| 5 | `test_pwa_004_auth_required` | No auth; 401 |
| 6 | `test_pwa_004_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/pwa-sync.spec.ts` -- 10 tests

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
| PWA-002 | Required | Service worker from PWA-002 |
| PWA-003 | Required | Offline cache for queued operations |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| PWA-005 | Required | Optimistic UI consumes sync queue status |

### Merge Strategy

**Sequential** -- Requires PWA-002 and PWA-003 merged first.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/pwa-sync.spec.ts`
