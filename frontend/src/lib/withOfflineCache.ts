// frontend/src/lib/withOfflineCache.ts
//
// React Query wrapper factory for offline cache fallback (PWA-003).
//
// Strategy: network-first with cache fallback.
// - Online: fetch from network, cache response in IndexedDB, return data
// - Offline: fetch fails, look up cached response in IndexedDB
// - Cache miss: rethrow original network error

import {
  getCachedResponse,
  setCachedResponse,
  evictOldestForEndpoint,
} from "./offlineCache";
import {
  getTtlForEndpoint,
  MAX_ENTRIES_PER_ENDPOINT,
  DEFAULT_MAX_ENTRIES,
} from "./offlineCacheConfig";

export interface OfflineCacheOptions {
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
 * The cached data includes `__cachedAt` and `__fromOfflineCache` metadata
 * fields so the UI can show staleness indicators.
 */
export function withOfflineCache<T>(
  networkFn: () => Promise<T>,
  options: OfflineCacheOptions,
  userId: string,
): () => Promise<T> {
  const ttl = options.ttlSeconds ?? getTtlForEndpoint(options.endpoint);
  const maxEntries =
    MAX_ENTRIES_PER_ENDPOINT[options.endpoint] ?? DEFAULT_MAX_ENTRIES;

  return async () => {
    try {
      // Try network first
      const data = await networkFn();

      // Cache the successful response (fire-and-forget)
      void (async () => {
        try {
          await setCachedResponse(
            options.cacheKey,
            options.endpoint,
            data,
            userId,
            ttl,
          );
          await evictOldestForEndpoint(options.endpoint, userId, maxEntries);
        } catch {
          // Cache write is best-effort
        }
      })();

      return data;
    } catch (err) {
      // Network failed -- try cache
      try {
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
      } catch {
        // Cache read failed -- fall through to rethrow
      }
      // No cache -- rethrow the original error
      throw err;
    }
  };
}

/**
 * Hook-friendly version that builds the cache key from query key parts.
 */
export function buildCacheKeyFromParts(
  parts: (string | undefined)[],
): string {
  return parts.filter(Boolean).join("/");
}
