import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import {
  startLiveLocation,
  updateLiveLocation,
  stopLiveLocation,
} from "@/api/endpoints/messaging";
import { UPDATE_INTERVAL_SEC, shouldAutoStop } from "@/lib/liveLocation";

interface ActiveShare {
  shareId: string;
  conversationId: string;
  expiresAt: number; // epoch sec
}

export interface UseLiveLocationShare {
  active: ActiveShare | null;
  starting: boolean;
  start: (conversationId: string, durationSec: number) => Promise<void>;
  stop: () => Promise<void>;
}

/**
 * FE-131 active-share session manager. A single-active-share hook owned by the
 * conversation view: it starts a live share, then relays the sharer position to
 * BE-131 while the share is active AND the tab is foregrounded.
 *
 * Watcher/interval:
 *   - navigator.geolocation.watchPosition is the primary source; each fix is
 *     POSTed to /live-location/{id}/update. maximumAge is capped at
 *     UPDATE_INTERVAL_SEC so a fix is never staler than the cadence.
 *   - a belt-and-braces setInterval (UPDATE_INTERVAL_SEC) re-pushes the latest
 *     cached fix even if watchPosition goes quiet (stationary device), and a
 *     1s ticker checks shouldAutoStop.
 *   - both relay timers are suspended while document.hidden (visibilitychange)
 *     so a backgrounded tab stops draining GPS/battery, and resumed on
 *     foreground. The auto-stop ticker runs regardless.
 *
 * Auto-stop: when shouldAutoStop(expiresAt, now) the session self-terminates
 * (calls stop) exactly like the manual button. Cleanup: every timer/watcher/
 * listener is torn down on unmount, manual stop, or expiry -- no leaks, and the
 * geo watch id is always cleared.
 *
 * Degrade-on-404: start surfaces a clear toast and resolves without an active
 * share if BE-131 is absent; it never throws into render and never fabricates a
 * relay that cannot move the pin.
 */
export function useLiveLocationShare(): UseLiveLocationShare {
  const queryClient = useQueryClient();
  const [active, setActive] = useState<ActiveShare | null>(null);
  const [starting, setStarting] = useState(false);

  const watchIdRef = useRef<number | null>(null);
  const intervalRef = useRef<number | null>(null);
  const tickRef = useRef<number | null>(null);
  const lastFixRef = useRef<{ lat: number; lng: number } | null>(null);
  const activeRef = useRef<ActiveShare | null>(null);
  const visibilityRemoverRef = useRef<(() => void) | null>(null);
  const stopRef = useRef<() => Promise<void>>(async () => {});
  activeRef.current = active;

  const invalidate = useCallback(
    (conversationId: string) => {
      queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    [queryClient],
  );

  const stopWatching = useCallback(() => {
    if (
      watchIdRef.current != null &&
      typeof navigator !== "undefined" &&
      navigator.geolocation
    ) {
      navigator.geolocation.clearWatch(watchIdRef.current);
    }
    watchIdRef.current = null;
  }, []);

  const clearTimers = useCallback(() => {
    stopWatching();
    if (intervalRef.current != null) window.clearInterval(intervalRef.current);
    intervalRef.current = null;
    if (tickRef.current != null) window.clearInterval(tickRef.current);
    tickRef.current = null;
  }, [stopWatching]);

  const pushFix = useCallback(
    (lat: number, lng: number) => {
      lastFixRef.current = { lat, lng };
      const cur = activeRef.current;
      if (!cur) return;
      void updateLiveLocation(cur.shareId, lat, lng)
        .then(() => invalidate(cur.conversationId))
        .catch(() => {});
    },
    [invalidate],
  );

  const startWatching = useCallback(() => {
    if (typeof navigator === "undefined" || !navigator.geolocation) return;
    if (watchIdRef.current != null) return;
    watchIdRef.current = navigator.geolocation.watchPosition(
      (pos) => pushFix(pos.coords.latitude, pos.coords.longitude),
      () => {},
      { enableHighAccuracy: true, maximumAge: UPDATE_INTERVAL_SEC * 1000, timeout: 20_000 },
    );
  }, [pushFix]);

  const resumeRelay = useCallback(() => {
    startWatching();
    if (intervalRef.current == null) {
      intervalRef.current = window.setInterval(() => {
        const fix = lastFixRef.current;
        if (fix) pushFix(fix.lat, fix.lng);
      }, UPDATE_INTERVAL_SEC * 1000);
    }
  }, [startWatching, pushFix]);

  const suspendRelay = useCallback(() => {
    stopWatching();
    if (intervalRef.current != null) window.clearInterval(intervalRef.current);
    intervalRef.current = null;
  }, [stopWatching]);

  const stop = useCallback(async () => {
    const cur = activeRef.current;
    clearTimers();
    if (visibilityRemoverRef.current) {
      visibilityRemoverRef.current();
      visibilityRemoverRef.current = null;
    }
    lastFixRef.current = null;
    setActive(null);
    activeRef.current = null;
    if (!cur) return;
    try {
      await stopLiveLocation(cur.shareId);
    } catch {
      // Ending is best-effort; the share also auto-expires server-side.
    }
    invalidate(cur.conversationId);
  }, [clearTimers, invalidate]);
  stopRef.current = stop;

  const start = useCallback(
    async (conversationId: string, durationSec: number) => {
      if (starting || activeRef.current) return;
      setStarting(true);
      try {
        const resp = await startLiveLocation(conversationId, durationSec);
        const share: ActiveShare = {
          shareId: resp.share_id,
          conversationId,
          expiresAt: resp.expires_at,
        };
        setActive(share);
        activeRef.current = share;
        invalidate(conversationId);

        const onVisibility = () => {
          if (typeof document !== "undefined" && document.hidden) suspendRelay();
          else resumeRelay();
        };
        if (typeof document !== "undefined") {
          document.addEventListener("visibilitychange", onVisibility);
          visibilityRemoverRef.current = () =>
            document.removeEventListener("visibilitychange", onVisibility);
        }

        tickRef.current = window.setInterval(() => {
          const cur = activeRef.current;
          if (!cur) return;
          if (shouldAutoStop(cur.expiresAt, Math.floor(Date.now() / 1000))) {
            void stopRef.current();
          }
        }, 1000);

        if (typeof document === "undefined" || !document.hidden) resumeRelay();
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          toast.error("Live location is not available yet on this server.");
        } else if (err instanceof ApiError) {
          toast.error(err.detail || "Could not start live location.");
        } else {
          toast.error("Could not start live location.");
        }
      } finally {
        setStarting(false);
      }
    },
    [starting, invalidate, resumeRelay, suspendRelay],
  );

  // Unmount teardown: kill every timer/watcher/listener and fire-and-forget the
  // server stop (unmount is synchronous; do not await).
  useEffect(() => {
    return () => {
      const cur = activeRef.current;
      clearTimers();
      if (visibilityRemoverRef.current) {
        visibilityRemoverRef.current();
        visibilityRemoverRef.current = null;
      }
      if (cur) void stopLiveLocation(cur.shareId).catch(() => {});
    };
  }, [clearTimers]);

  return { active, starting, start, stop };
}

export default useLiveLocationShare;
