import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { alertStreamUrl } from "@/api/endpoints/alerts";

const MAX_RETRY_DELAY = 30_000;

/** Toast duration by priority level. 0 = persistent (user must dismiss). */
const TOAST_DURATION: Record<string, number> = {
  urgent: 0,       // persistent
  normal: 5_000,   // 5 seconds
  low: 3_000,      // 3 seconds
};

/**
 * SSE hook for real-time alert events.
 * On new alert: shows toast (duration varies by priority), invalidates alert
 * queries, updates unread count.
 * Reconnects with exponential backoff on disconnect.
 */
export function useAlertStream(enabled = true) {
  const queryClient = useQueryClient();
  const retryCount = React.useRef(0);
  const [unreadCount, setUnreadCount] = React.useState(0);

  // Fetch initial unread count on mount
  React.useEffect(() => {
    if (!enabled) return;
    fetch("/ui/alerts/unread-count", { credentials: "include" })
      .then((r) => r.json())
      .then((data) => {
        const count = data?.count ?? data?.unread_count ?? 0;
        setUnreadCount(count);
      })
      .catch(() => {});
  }, [enabled]);

  React.useEffect(() => {
    if (!enabled) return;

    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;

    function connect() {
      es = new EventSource(alertStreamUrl, { withCredentials: true });

      es.onopen = () => {
        retryCount.current = 0;
      };

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === "new_alert" || data.type === "alert") {
            // Invalidate alert queries to refresh lists
            queryClient.invalidateQueries({ queryKey: ["alerts"] });

            // Update unread count from delta or increment
            if (typeof data.unread_delta === "number" && data.unread_delta > 0) {
              setUnreadCount((prev) => prev + data.unread_delta);
            } else {
              setUnreadCount((prev) => prev + 1);
            }

            // Show toast notification with priority-based duration
            if (data.title) {
              const priority = data.toast_priority || data.priority || "normal";
              const duration = TOAST_DURATION[priority] ?? 5_000;
              toast(data.title, {
                description: typeof data.details === "string"
                  ? data.details
                  : undefined,
                duration: duration === 0 ? Infinity : duration,
              });
            }
          }

          if (data.type === "alert_read" || data.type === "alerts_read") {
            queryClient.invalidateQueries({ queryKey: ["alerts"] });
            // Decrement or reset unread count
            if (typeof data.unread_count === "number") {
              setUnreadCount(data.unread_count);
            } else {
              setUnreadCount((prev) => Math.max(0, prev - 1));
            }
          }

          // Allow server to push the current unread count (hello/sync event)
          if (typeof data.unread_count === "number" && (data.type === "sync" || !data.type)) {
            setUnreadCount(data.unread_count);
          }
        } catch {
          // Ignore parse errors from non-JSON events (heartbeats, etc.)
        }
      };

      // Handle named SSE events (event: alert, event: heartbeat, event: hello)
      es.addEventListener("alert", (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);

          // Invalidate alert queries to refresh lists
          queryClient.invalidateQueries({ queryKey: ["alerts"] });

          // Update unread count
          if (typeof data.unread_delta === "number" && data.unread_delta > 0) {
            setUnreadCount((prev) => prev + data.unread_delta);
          } else if (data.alert_id) {
            // It's a real alert event
            setUnreadCount((prev) => prev + 1);
          }

          // Show toast with priority
          if (data.title) {
            const priority = data.toast_priority || data.priority || "normal";
            const duration = TOAST_DURATION[priority] ?? 5_000;
            toast(data.title, {
              description: typeof data.details === "string"
                ? data.details
                : undefined,
              duration: duration === 0 ? Infinity : duration,
            });
          }
        } catch {
          // Ignore parse errors
        }
      });

      es.addEventListener("hello", (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          if (typeof data.unread_count === "number") {
            setUnreadCount(data.unread_count);
          }
        } catch {
          // Ignore
        }
      });

      es.addEventListener("heartbeat", () => {
        // Heartbeat received — reset reconnect backoff
        retryCount.current = 0;
      });

      es.onerror = () => {
        es?.close();
        es = null;

        const delay = Math.min(1000 * Math.pow(2, retryCount.current), MAX_RETRY_DELAY);
        retryCount.current++;
        retryTimer = setTimeout(connect, delay);
      };
    }

    connect();

    return () => {
      es?.close();
      clearTimeout(retryTimer);
    };
  }, [enabled, queryClient]);

  const resetUnread = React.useCallback(() => setUnreadCount(0), []);

  return { unreadCount, resetUnread };
}
