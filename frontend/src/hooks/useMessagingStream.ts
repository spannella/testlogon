import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

const MESSAGING_STREAM_URL = "/messaging/events/stream";
const MAX_RETRY_DELAY = 30_000;

/**
 * SSE hook for real-time messaging events.
 * On new messages: invalidates conversation and message queries.
 * Reconnects with exponential backoff on disconnect.
 */
export function useMessagingStream(enabled = true) {
  const queryClient = useQueryClient();
  const retryCount = React.useRef(0);

  React.useEffect(() => {
    if (!enabled) return;

    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;

    function connect() {
      es = new EventSource(MESSAGING_STREAM_URL, { withCredentials: true });

      es.onopen = () => {
        retryCount.current = 0;
      };

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const eventType = typeof data.type === "string" ? data.type : "";
          const conversationId = typeof data.conversation_id === "string" ? data.conversation_id : undefined;

          const shouldRefreshConversation = new Set([
            "new_message",
            "message",
            "message_updated",
            "message_consumed",
            "once_media_consumed",
            "once_media_state_changed",
            "conversation_updated",
          ]).has(eventType);

          if (eventType === "new_message" || eventType === "message") {
            // Invalidate conversations list to update last message / unread
            queryClient.invalidateQueries({ queryKey: ["conversations"] });
          }

          if (eventType === "conversation_updated") {
            queryClient.invalidateQueries({ queryKey: ["conversations"] });
          }

          // Deterministic reconciliation for once-media state and edits:
          // always refetch the specific conversation timeline when possible.
          if (shouldRefreshConversation && conversationId) {
            queryClient.invalidateQueries({
              queryKey: ["messages", conversationId],
            });
          }
        } catch {
          // Ignore parse errors from non-JSON events (heartbeats, etc.)
        }
      };

      es.onerror = () => {
        es?.close();
        es = null;

        // Exponential backoff: 1s, 2s, 4s, 8s ... up to MAX_RETRY_DELAY
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
