import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

export interface BroadcastHealthData {
  session_id: string;
  viewer_count: number;
  ingest_bitrate_kbps: number;
  ingest_framerate: number;
  dropped_frames: number;
  dropped_frames_pct: number;
  connection_quality: "excellent" | "good" | "fair" | "poor" | "critical";
  output_errors: number;
  input_loss_seconds: number;
  updated_at: number;
}

/**
 * SSE hook for real-time broadcast session events.
 * Provides viewer count and health metrics via EventSource.
 */
export function useBroadcastStream(sessionId: string | null, enabled = true) {
  const queryClient = useQueryClient();
  const [viewerCount, setViewerCount] = React.useState(0);
  const [health, setHealth] = React.useState<BroadcastHealthData | null>(null);
  const retryCount = React.useRef(0);

  React.useEffect(() => {
    if (!enabled || !sessionId) return;

    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;

    function connect() {
      es = new EventSource(`/broadcast/sessions/${sessionId}/stream`, {
        withCredentials: true,
      });

      es.onopen = () => {
        retryCount.current = 0;
      };

      es.addEventListener("viewer_count", (event: MessageEvent) => {
        const data = JSON.parse(event.data);
        setViewerCount(data.viewer_count);
      });

      es.addEventListener("health_update", (event: MessageEvent) => {
        const data = JSON.parse(event.data) as BroadcastHealthData;
        setHealth(data);
        setViewerCount(data.viewer_count);
      });

      es.addEventListener("session_status", () => {
        queryClient.invalidateQueries({
          queryKey: ["broadcast", "sessions", sessionId],
        });
      });

      es.onerror = () => {
        es?.close();
        es = null;
        const delay = Math.min(1000 * Math.pow(2, retryCount.current), 30_000);
        retryCount.current++;
        retryTimer = setTimeout(connect, delay);
      };
    }

    connect();
    return () => {
      es?.close();
      clearTimeout(retryTimer);
    };
  }, [sessionId, enabled, queryClient]);

  return { viewerCount, health };
}
