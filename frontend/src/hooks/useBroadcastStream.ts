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

export interface AdBreakState {
  active: boolean;
  durationSeconds: number;
  skipAfterSeconds: number;
  startedAt: number;
}

const NO_AD_BREAK: AdBreakState = {
  active: false,
  durationSeconds: 0,
  skipAfterSeconds: 0,
  startedAt: 0,
};

/**
 * SSE hook for real-time broadcast session events.
 * Provides viewer count, health metrics, and ad-break state via EventSource (ADS-006).
 */
export function useBroadcastStream(sessionId: string | null, enabled = true) {
  const queryClient = useQueryClient();
  const [viewerCount, setViewerCount] = React.useState(0);
  const [health, setHealth] = React.useState<BroadcastHealthData | null>(null);
  const [adBreak, setAdBreak] = React.useState<AdBreakState>(NO_AD_BREAK);
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

      // Ad breaks (ADS-006) — the backend sets the SSE event name to the
      // value of the published `_type`, i.e. "ad_break:start" / "ad_break:end".
      es.addEventListener("ad_break:start", (event: MessageEvent) => {
        const data = JSON.parse(event.data) as {
          duration_seconds: number;
          skip_after_seconds: number;
          started_at: number;
        };
        setAdBreak({
          active: true,
          durationSeconds: data.duration_seconds,
          skipAfterSeconds: data.skip_after_seconds,
          startedAt: data.started_at,
        });
      });

      es.addEventListener("ad_break:end", () => {
        setAdBreak(NO_AD_BREAK);
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

  return { viewerCount, health, adBreak, clearAdBreak: () => setAdBreak(NO_AD_BREAK) };
}
