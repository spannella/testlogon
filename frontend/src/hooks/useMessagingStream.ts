import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useAuthStore } from "@/stores/authStore";

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
  // Current user id, via a ref so the SSE listener doesn't rebind on change (HMH-005).
  const currentUserId = useAuthStore((s) => s.userId);
  const userIdRef = React.useRef(currentUserId);
  userIdRef.current = currentUserId;

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
          eventType === "message:expired" ||
          eventType === "message:revealed" ||
          eventType === "helpdesk.conversation.alerted" ||
          eventType === "helpdesk.conversation.assigned" ||
          eventType === "helpdesk.conversation.released" ||
          eventType === "helpdesk.conversation.no_agents_online" ||
          eventType.startsWith("call.")
        ) {
          queryClient.invalidateQueries({ queryKey: ["conversations"] });
        }

        // Refresh helpdesk queue on routing state changes
        if (
          eventType === "helpdesk.conversation.alerted" ||
          eventType === "helpdesk.conversation.assigned" ||
          eventType === "helpdesk.conversation.released" ||
          eventType === "helpdesk.conversation.no_agents_online"
        ) {
          queryClient.invalidateQueries({ queryKey: ["helpdesk-queue"] });
        }

        // HMH-005: toast the agent who was just auto-routed a customer. The
        // agent identity is only present in the payload projected to agents, so
        // a customer's event won't match and won't toast.
        if (eventType === "helpdesk.conversation.assigned") {
          const payload = (data.payload ?? {}) as Record<string, unknown>;
          const agent =
            (typeof payload.active_agent_user_id === "string" && payload.active_agent_user_id) ||
            (typeof data.active_agent_user_id === "string" && data.active_agent_user_id) ||
            "";
          if (agent && agent === userIdRef.current) {
            toast.success("You've been connected with a customer");
          }
        }

        // Refresh the specific conversation's message list.
        // Exclude "message:viewed" — read receipts are patched surgically below
        // (see the message:viewed handler) to avoid a full message-list refetch.
        if (conversationId && eventType !== "message:viewed") {
          queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
        }

        // Refresh meeting poll state on vote/confirm
        if (eventType === "poll:vote" || eventType === "poll:confirmed") {
          const pollId = typeof data.poll_id === "string" ? data.poll_id : undefined;
          if (pollId && conversationId) {
            queryClient.invalidateQueries({ queryKey: ["poll", pollId, conversationId] });
          }
        }

        // Refresh Find-a-DateTime state on availability submit / result (MSG-009)
        if (eventType === "fadt:availability" || eventType === "fadt:result") {
          const pollId = typeof data.poll_id === "string" ? data.poll_id : undefined;
          if (pollId) {
            queryClient.invalidateQueries({ queryKey: ["find-datetime", pollId] });
          }
        }

        // Typing indicator — write directly to cache for instant update
        if (eventType === "typing:update" && conversationId) {
          const userId = typeof data.user_id === "string" ? data.user_id : undefined;
          const isTyping = !!data.is_typing;
          const updatedAt = typeof data.updated_at === "number" ? data.updated_at : Math.floor(Date.now() / 1000);
          if (userId) {
            queryClient.setQueryData<Array<{ user_id: string; updated_at: number }>>(
              ["typing", conversationId],
              (prev) => {
                const existing = (prev ?? []).filter((t) => t.user_id !== userId);
                if (isTyping) {
                  existing.push({ user_id: userId, updated_at: updatedAt });
                }
                return existing;
              },
            );
          }
        }

        // Presence — write directly to cache for instant update
        if (eventType === "presence:update") {
          const userId = typeof data.user_id === "string" ? data.user_id : undefined;
          const online = !!data.online;
          const lastSeenAt = typeof data.last_seen_at === "number" ? data.last_seen_at : 0;
          if (userId) {
            queryClient.setQueryData(
              ["presence", userId],
              [{ user_id: userId, online, last_seen_at: lastSeenAt }],
            );
            // Also update any batch presence queries that include this user
            queryClient.setQueriesData<Array<{ user_id: string; online: boolean; last_seen_at: number }>>(
              { queryKey: ["presence", "batch"] },
              (prev) => {
                if (!prev) return prev;
                return prev.map((entry) =>
                  entry.user_id === userId ? { ...entry, online, last_seen_at: lastSeenAt } : entry,
                );
              },
            );
          }
        }

        // Read receipts — surgically patch the message in cache (no refetch)
        if (eventType === "message:viewed" && conversationId) {
          const messageId = typeof data.message_id === "string" ? data.message_id : undefined;
          const viewerId = typeof data.viewer_id === "string" ? data.viewer_id : undefined;
          if (messageId && viewerId) {
            // Narrow per-message detail query — round-trip is acceptable here.
            queryClient.invalidateQueries({ queryKey: ["message-views", conversationId, messageId] });

            // Surgically increment read_by_count / append viewer to read_by_user_ids
            // on the matching message in the infinite-query pages cache, avoiding a
            // full message-list refetch (and the resulting flicker).
            queryClient.setQueriesData<{
              pages: Array<{
                messages: Array<{
                  message_id?: string;
                  read_by_count?: number;
                  read_by_user_ids?: string[];
                }>;
                next_cursor?: string;
              }>;
              pageParams: unknown[];
            }>({ queryKey: ["messages", conversationId] }, (prev) => {
              if (!prev || !Array.isArray(prev.pages)) return prev;
              return {
                ...prev,
                pages: prev.pages.map((page) => {
                  if (!page || !Array.isArray(page.messages)) return page;
                  return {
                    ...page,
                    messages: page.messages.map((msg) => {
                      if (msg.message_id !== messageId) return msg;
                      const existingIds = msg.read_by_user_ids ?? [];
                      if (existingIds.includes(viewerId)) return msg;
                      const updatedIds = [...existingIds, viewerId];
                      return {
                        ...msg,
                        read_by_count: updatedIds.length,
                        read_by_user_ids: updatedIds,
                      };
                    }),
                  };
                }),
              };
            });
          }
        }

        // CALL-014: Voicemail signaling. When a voicemail recording completes,
        // a new voicemail message has been written to the conversation — refresh
        // the message list so it appears for the callee (and any participant).
        if (eventType === "call.voicemail_start" || eventType === "call.voicemail_complete") {
          if (eventType === "call.voicemail_complete" && conversationId) {
            queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
            queryClient.invalidateQueries({ queryKey: ["conversations"] });
          }
        }

        if (eventType.startsWith("call.")) {
          window.dispatchEvent(
            new CustomEvent("messaging:call-event", {
              detail: {
                ...data,
                event_type: eventType,
              },
            }),
          );
        }

        if (eventType.startsWith("webrtc.")) {
          window.dispatchEvent(
            new CustomEvent("messaging:webrtc-signal", {
              detail: {
                ...data,
                event_type: eventType,
              },
            }),
          );
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
      "message:revealed",
      "message:viewed",
      "once_media_consumed",
      "once_media_state_changed",
      "conversation_updated",
      "typing:update",
      "presence:update",
      "poll:vote",
      "poll:confirmed",
      "fadt:availability",
      "fadt:result",
      "helpdesk.conversation.alerted",
      "helpdesk.conversation.assigned",
      "helpdesk.conversation.released",
      "helpdesk.conversation.no_agents_online",
      "call.invite",
      "call.accept",
      "call.decline",
      "call.end",
      "call.missed",
      "call.recording_request",
      "call.recording_accept",
      "call.recording_decline",
      "call.recording_started",
      "call.recording_stopped",
      "call.voicemail_start",
      "call.voicemail_complete",
      "call.billing_tick",
      "call.balance_low",
      "call.balance_depleted",
      "webrtc.offer",
      "webrtc.answer",
      "webrtc.ice_candidate",
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
