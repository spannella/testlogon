// frontend/src/lib/offlineCache.ts
//
// IndexedDB wrapper for caching API responses offline (PWA-003).
// All IDB operations are wrapped in try/catch so the app degrades
// gracefully when IndexedDB is unavailable (private browsing, etc.).

const DB_NAME = "app-offline-cache";
const DB_VERSION = 2;
const STORE_NAME = "api_cache";
const META_STORE = "api_cache_meta";

/** Cached singleton to avoid repeated open calls */
let dbInstance: IDBDatabase | null = null;

/**
 * Open (or reuse) the IndexedDB database.
 * Creates object stores on first open or version upgrade.
 */
export function openDb(): Promise<IDBDatabase> {
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

      // Version 2: sync_queue store (PWA-004)
      if (oldVersion < 2) {
        const syncStore = db.createObjectStore("sync_queue", { keyPath: "id" });
        syncStore.createIndex("type", "type", { unique: false });
        syncStore.createIndex("enqueuedAt", "enqueuedAt", { unique: false });
        syncStore.createIndex("status", "status", { unique: false });
      }
    };

    req.onsuccess = () => {
      dbInstance = req.result;

      // Clear singleton if the database is unexpectedly closed
      dbInstance.onclose = () => {
        dbInstance = null;
      };
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
      req.onerror = () =>
        resolve({ totalEntries: 0, totalSizeEstimate: 0, byEndpoint: {} });
    });
  } catch {
    return { totalEntries: 0, totalSizeEstimate: 0, byEndpoint: {} };
  }
}
