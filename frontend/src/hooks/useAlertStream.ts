import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { alertStreamUrl } from "@/api/endpoints/alerts";

const MAX_RETRY_DELAY = 30_000;

/**
 * SSE hook for real-time alert events.
 * On new alert: shows toast, invalidates alert queries, updates unread count.
 * Reconnects with exponential backoff on disconnect.
 */
export function useAlertStream(enabled = true) {
  const queryClient = useQueryClient();
  const retryCount = React.useRef(0);
  const [unreadCount, setUnreadCount] = React.useState(0);

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

            // Increment unread count
            setUnreadCount((prev) => prev + 1);

            // Show toast notification
            if (data.title) {
              toast(data.title, {
                description: data.details,
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

          // Allow server to push the current unread count
          if (typeof data.unread_count === "number" && data.type === "sync") {
            setUnreadCount(data.unread_count);
          }
        } catch {
          // Ignore parse errors from non-JSON events (heartbeats, etc.)
        }
      };

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
