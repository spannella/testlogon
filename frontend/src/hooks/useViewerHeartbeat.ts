import * as React from "react";
import { api } from "@/api/client";

const HEARTBEAT_INTERVAL = 30_000; // 30 seconds

/**
 * Manages viewer lifecycle: join on mount, heartbeat every 30s, leave on unmount.
 * Uses sendBeacon for reliable leave signal on page close.
 */
export function useViewerHeartbeat(sessionId: string | null, enabled = true) {
  const viewerIdRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (!enabled || !sessionId) return;

    let heartbeatTimer: ReturnType<typeof setInterval>;

    // Join
    api
      .post<{ viewer_id: string; session_id: string; viewer_count: number }>(`/broadcast/sessions/${sessionId}/viewers/join`)
      .then((data) => {
        viewerIdRef.current = data.viewer_id;
        // Start heartbeat
        heartbeatTimer = setInterval(() => {
          if (viewerIdRef.current) {
            api
              .post(
                `/broadcast/sessions/${sessionId}/viewers/heartbeat?viewer_id=${encodeURIComponent(viewerIdRef.current)}`,
              )
              .catch(() => {});
          }
        }, HEARTBEAT_INTERVAL);
      })
      .catch(() => {});

    // Leave on page unload (sendBeacon for reliability)
    const handleUnload = () => {
      if (viewerIdRef.current) {
        const url = `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${viewerIdRef.current}`;
        navigator.sendBeacon(url);
      }
    };
    window.addEventListener("beforeunload", handleUnload);

    return () => {
      clearInterval(heartbeatTimer);
      window.removeEventListener("beforeunload", handleUnload);
      // Explicit leave on React unmount (e.g. navigating away)
      if (viewerIdRef.current) {
        api
          .post(
            `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(viewerIdRef.current)}`,
          )
          .catch(() => {});
      }
    };
  }, [sessionId, enabled]);
}
