// frontend/src/lib/syncQueueDb.ts
//
// IndexedDB helpers for the Background Sync queue (PWA-004).
// Uses the same "app-offline-cache" database as PWA-003, bumped to version 2
// to add the `sync_queue` object store.

const DB_NAME = "app-offline-cache";
const DB_VERSION = 2;
const SYNC_STORE = "sync_queue";

export interface SyncQueueItem {
  id: string;
  type: "send_message" | "create_post";
  enqueuedAt: number;
  payload: Record<string, unknown>;
  retryCount: number;
  lastRetryAt: number;
  status: "pending" | "retrying" | "dead";
  lastError: string;
  csrfToken: string;
}

/**
 * Open the IndexedDB database at version 2.
 * The upgrade handler creates the sync_queue store without breaking
 * the existing stores from version 1 (api_cache, api_cache_meta).
 */
export function openSyncDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      const oldVersion = event.oldVersion;

      // Version 1 stores (api_cache + api_cache_meta) — create only if upgrading from 0
      if (oldVersion < 1) {
        const apiStore = db.createObjectStore("api_cache", { keyPath: "cacheKey" });
        apiStore.createIndex("cachedAt", "cachedAt", { unique: false });
        apiStore.createIndex("endpoint", "endpoint", { unique: false });
        apiStore.createIndex("userId", "userId", { unique: false });
        apiStore.createIndex("userId_endpoint", ["userId", "endpoint"], { unique: false });

        db.createObjectStore("api_cache_meta", { keyPath: "endpoint" });
      }

      // Version 2 store (sync_queue)
      if (oldVersion < 2) {
        const syncStore = db.createObjectStore(SYNC_STORE, { keyPath: "id" });
        syncStore.createIndex("type", "type", { unique: false });
        syncStore.createIndex("enqueuedAt", "enqueuedAt", { unique: false });
        syncStore.createIndex("status", "status", { unique: false });
      }
    };

    req.onsuccess = () => {
      const db = req.result;
      db.onversionchange = () => {
        db.close();
      };
      resolve(db);
    };

    req.onerror = () => reject(req.error);
  });
}

/**
 * Write an offline action to the sync queue in IndexedDB.
 * Fire-and-forget: errors are silently caught.
 */
export async function writeToSyncQueue(
  action: { id: string; type: string; enqueuedAt: number; payload: unknown },
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
 * Remove a completed or discarded item from the sync queue.
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
 * Partially update an existing sync queue item.
 */
export async function updateSyncQueueItem(
  id: string,
  updates: Partial<SyncQueueItem>,
): Promise<void> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readwrite");
      const store = tx.objectStore(SYNC_STORE);
      const getReq = store.get(id);
      getReq.onsuccess = () => {
        if (getReq.result) {
          store.put({ ...getReq.result, ...updates });
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
 * Get all sync queue items matching a given status.
 * Results are ordered by enqueuedAt ascending.
 */
export async function getQueueItemsByStatus(
  status: "pending" | "retrying" | "dead",
): Promise<SyncQueueItem[]> {
  try {
    const db = await openSyncDb();
    return new Promise((resolve) => {
      const tx = db.transaction(SYNC_STORE, "readonly");
      const store = tx.objectStore(SYNC_STORE);
      const index = store.index("status");
      const items: SyncQueueItem[] = [];
      const req = index.openCursor(IDBKeyRange.only(status));
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          items.push(cursor.value as SyncQueueItem);
          cursor.continue();
        } else {
          items.sort((a, b) => a.enqueuedAt - b.enqueuedAt);
          resolve(items);
        }
      };
      req.onerror = () => resolve([]);
    });
  } catch {
    return [];
  }
}

/**
 * Get the total number of items in the sync queue.
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
