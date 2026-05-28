import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { sendHeartbeat, getPresence } from "@/api/endpoints/messaging";

const HEARTBEAT_INTERVAL_MS = 30_000;
const PRESENCE_FALLBACK_POLL_MS = 60_000;

/**
 * Sends a heartbeat every 30s while the app is active.
 * Call once near the app root (e.g., in MessagesPage).
 */
export function useHeartbeat(enabled = true) {
  useEffect(() => {
    if (!enabled) return;

    // Send immediately on mount
    sendHeartbeat().catch(() => {});

    const id = setInterval(() => {
      if (document.visibilityState === "visible") {
        sendHeartbeat().catch(() => {});
      }
    }, HEARTBEAT_INTERVAL_MS);

    return () => clearInterval(id);
  }, [enabled]);
}

/**
 * Returns the online/offline presence status for a single user.
 * Polls every 60s as a fallback — primary updates come via SSE (presence:update event
 * handled in useMessagingStream, which writes directly to this query's cache).
 */
export function usePresenceStatus(userId: string | undefined) {
  const { data } = useQuery({
    queryKey: ["presence", userId],
    queryFn: () => getPresence([userId!]),
    enabled: !!userId,
    refetchInterval: PRESENCE_FALLBACK_POLL_MS,
    staleTime: PRESENCE_FALLBACK_POLL_MS,
  });

  const entry = data?.[0];
  return {
    online: entry?.online ?? false,
    lastSeenAt: entry?.last_seen_at ?? 0,
  };
}

/**
 * Returns online/offline status for multiple users at once.
 * Batches into a single API call. Polls every 60s as fallback.
 */
export function useBatchPresence(userIds: string[]) {
  const key = userIds.slice().sort().join(",");

  const { data } = useQuery({
    queryKey: ["presence", "batch", key],
    queryFn: () => getPresence(userIds),
    enabled: userIds.length > 0,
    refetchInterval: PRESENCE_FALLBACK_POLL_MS,
    staleTime: PRESENCE_FALLBACK_POLL_MS,
  });

  const map = new Map<string, boolean>();
  if (data) {
    for (const entry of data) {
      map.set(entry.user_id, entry.online);
    }
  }
  return map;
}
