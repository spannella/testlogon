// frontend/src/lib/offlineCacheConfig.ts
//
// Per-endpoint TTL and max-entries configuration for offline cache (PWA-003).

/**
 * TTL configuration for offline cache per endpoint category.
 * Values are in seconds.
 */
export const CACHE_TTL_CONFIG: Record<string, number> = {
  conversations: 5 * 60, // 5 minutes
  messages: 30 * 60, // 30 minutes
  feed: 60 * 60, // 1 hour
  post_detail: 60 * 60, // 1 hour
  contacts: 15 * 60, // 15 minutes
  calendar_events: 30 * 60, // 30 minutes
  alerts: 10 * 60, // 10 minutes
  profile: 24 * 60 * 60, // 24 hours (rarely changes)
  billing: 10 * 60, // 10 minutes
  catalog: 60 * 60, // 1 hour
};

export const DEFAULT_TTL = 15 * 60; // 15 minutes for unconfigured endpoints

/**
 * Maximum number of entries per endpoint category.
 * Prevents unbounded cache growth for high-volume endpoints.
 */
export const MAX_ENTRIES_PER_ENDPOINT: Record<string, number> = {
  conversations: 1, // Only the conversations list
  messages: 50, // 50 conversation pages
  feed: 10, // 10 feed pages
  post_detail: 20, // 20 individual posts
  contacts: 5, // Contact list pages
  calendar_events: 10, // Calendar event pages
  alerts: 5, // Alert pages
  profile: 5, // Profile variations
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
