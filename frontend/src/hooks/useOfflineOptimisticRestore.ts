/**
 * PWA-005: Restore offline optimistic messages into the React Query cache
 * after a page reload.
 *
 * When the page reloads while offline, the React Query cache is cleared but
 * the Zustand offline store persists in localStorage. This hook re-injects
 * the queued messages so the user sees them in the conversation view.
 *
 * Feed posts do NOT need restoration here because FeedTimeline reads
 * directly from the offline store on every render.
 */

import * as React from "react";
import type { QueryClient, InfiniteData } from "@tanstack/react-query";
import { useOfflineStore } from "@/stores/offlineStore";
import { useAuthStore } from "@/stores/authStore";
import type { Message } from "@/api/types";

type MessagesPage = { messages: Message[]; next_cursor?: string };

export function useOfflineOptimisticRestore(queryClient: QueryClient) {
  const queue = useOfflineStore((s) => s.queue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const userId = useAuthStore((s) => s.userId);
  const restoredIds = React.useRef(new Set<string>());

  React.useEffect(() => {
    if (isOnline || queue.length === 0) return;

    for (const action of queue) {
      if (restoredIds.current.has(action.id)) continue;
      restoredIds.current.add(action.id);

      if (action.type === "send_message") {
        const { conversationId, req } = action.payload;
        const optimistic: Message = {
          message_id: `optimistic-offline-${action.id}`,
          conversation_id: conversationId,
          sender_id: userId ?? "",
          kind: "text",
          text: req.encryption ? "" : (req.text ?? ""),
          is_encrypted: !!req.encryption,
          encryption: req.encryption,
          created_at: action.enqueuedAt / 1000,
          reactions_counts: {},
          reply_to_message_id: req.reply_to_message_id,
          __offline: {
            queueId: action.id,
            status: (action.__status ?? "pending") as "pending" | "sending" | "failed",
            error: action.__error,
            enqueuedAt: action.enqueuedAt,
          },
        };

        queryClient.setQueryData<InfiniteData<MessagesPage>>(
          ["messages", conversationId],
          (old) => {
            if (!old?.pages?.length) {
              return {
                pages: [{ messages: [optimistic], next_cursor: undefined }],
                pageParams: [undefined],
              };
            }
            // Check for duplicate
            const already = old.pages.some((p) =>
              (p.messages ?? []).some((m) => m.message_id === optimistic.message_id),
            );
            if (already) return old;

            const pages = old.pages.map((p, i) =>
              i === 0 ? { ...p, messages: [optimistic, ...(p.messages ?? [])] } : p,
            );
            return { ...old, pages };
          },
        );
      }
    }
  }, [queue, isOnline, userId, queryClient]);
}
