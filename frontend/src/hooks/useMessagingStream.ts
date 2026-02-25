import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

const MESSAGING_STREAM_URL = "/messaging/events/stream";
const MAX_RETRY_DELAY = 30_000;

/**
 * SSE hook for real-time messaging events.
 * The backend sends typed SSE events (e.g. "event: message:new").
 * EventSource.onmessage only fires for un-typed or "message"-typed events,
 * so we register named listeners for every event type we care about.
 */
export function useMessagingStream(enabled = true) {
  const queryClient = useQueryClient();
  const retryCount = React.useRef(0);

  React.useEffect(() => {
    if (!enabled) return;

    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;

    function handleEvent(event: MessageEvent) {
      try {
        const data = JSON.parse(event.data as string);
        const conversationId = typeof data.conversation_id === "string" ? data.conversation_id : undefined;
        const eventType: string = (event.type ?? "") || (typeof data.type === "string" ? data.type : "");

        // Always refresh the conversations list (unread counts, last message preview)
        if (
          eventType === "message:new" ||
          eventType === "message:revoked" ||
          eventType === "message:edited" ||
          eventType === "conversation_updated" ||
          eventType === "message:reaction" ||
          eventType === "message:expired"
        ) {
          queryClient.invalidateQueries({ queryKey: ["conversations"] });
        }

        // Refresh the specific conversation's message list
        if (conversationId) {
          queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
        }
      } catch {
        // Ignore parse errors (heartbeat comments, etc.)
      }
    }

    // Event types the backend emits
    const EVENT_TYPES = [
      "message:new",
      "message:revoked",
      "message:edited",
      "message:reaction",
      "message:locked",
      "message:unlocked",
      "message:expired",
      "once_media_consumed",
      "once_media_state_changed",
      "conversation_updated",
    ];

    function connect() {
      es = new EventSource(MESSAGING_STREAM_URL, { withCredentials: true });

      es.onopen = () => {
        retryCount.current = 0;
      };

      // Catch un-typed / "message"-typed fallback events
      es.onmessage = handleEvent;

      // Catch all typed events the backend sends
      for (const type of EVENT_TYPES) {
        es.addEventListener(type, handleEvent);
      }

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
}
