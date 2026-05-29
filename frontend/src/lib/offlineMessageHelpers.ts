/**
 * PWA-005: Helpers for managing offline optimistic messages in the React Query cache.
 *
 * These utilities update, remove, or inspect optimistic messages that were
 * injected when the user sent a message or post while offline.
 */

import type { QueryClient, InfiniteData } from "@tanstack/react-query";
import type { Message } from "@/api/types";

// ─── Type guards ────────────────────────────────────────────────

export function isOfflineOptimistic(item: { __offline?: unknown }): boolean {
  return !!item.__offline;
}

export function isOfflinePending(item: { __offline?: { status: string } }): boolean {
  return item.__offline?.status === "pending";
}

export function isOfflineSending(item: { __offline?: { status: string } }): boolean {
  return item.__offline?.status === "sending";
}

export function isOfflineFailed(item: { __offline?: { status: string } }): boolean {
  return item.__offline?.status === "failed";
}

export function isOptimisticMessageId(messageId: string): boolean {
  return messageId.startsWith("optimistic-");
}

export function isOfflineOptimisticMessageId(messageId: string): boolean {
  return messageId.startsWith("optimistic-offline-");
}

// ─── Cache helpers ──────────────────────────────────────────────

type MessagesPage = { messages: Message[]; next_cursor?: string };

/**
 * Update the __offline.status of an optimistic message across all conversation caches.
 */
export function updateOfflineMessageStatus(
  queryClient: QueryClient,
  queueId: string,
  status: "pending" | "sending" | "failed",
  error?: string,
) {
  const targetMsgId = `optimistic-offline-${queueId}`;

  queryClient.setQueriesData<InfiniteData<MessagesPage>>(
    { queryKey: ["messages"] },
    (old) => {
      if (!old?.pages) return old;
      let found = false;
      const pages = old.pages.map((p) => ({
        ...p,
        messages: (p.messages ?? []).map((m) => {
          if (m.message_id === targetMsgId) {
            found = true;
            return {
              ...m,
              __offline: {
                ...m.__offline!,
                status,
                ...(error !== undefined ? { error } : {}),
              },
            };
          }
          return m;
        }),
      }));
      return found ? { ...old, pages } : old;
    },
  );
}

/**
 * Mark an optimistic message as failed with an error string.
 */
export function markOfflineMessageFailed(
  queryClient: QueryClient,
  queueId: string,
  error: string,
) {
  updateOfflineMessageStatus(queryClient, queueId, "failed", error);
}

/**
 * Remove the __offline field from a message after successful flush.
 * The message stays in the cache as a normal message until invalidateQueries replaces it.
 */
export function removeOfflineField(
  queryClient: QueryClient,
  queueId: string,
) {
  const targetMsgId = `optimistic-offline-${queueId}`;

  queryClient.setQueriesData<InfiniteData<MessagesPage>>(
    { queryKey: ["messages"] },
    (old) => {
      if (!old?.pages) return old;
      let found = false;
      const pages = old.pages.map((p) => ({
        ...p,
        messages: (p.messages ?? []).map((m) => {
          if (m.message_id === targetMsgId) {
            found = true;
            const { __offline: _, ...rest } = m;
            return rest;
          }
          return m;
        }),
      }));
      return found ? { ...old, pages } : old;
    },
  );
}

/**
 * Completely remove an optimistic message from a specific conversation's cache.
 * Used by the "Discard" action on failed messages.
 */
export function removeOptimisticMessage(
  queryClient: QueryClient,
  conversationId: string,
  messageId: string,
) {
  queryClient.setQueryData<InfiniteData<MessagesPage>>(
    ["messages", conversationId],
    (old) => {
      if (!old?.pages) return old;
      return {
        ...old,
        pages: old.pages.map((page) => ({
          ...page,
          messages: (page.messages ?? []).filter(
            (m) => m.message_id !== messageId,
          ),
        })),
      };
    },
  );

  // Refresh sidebar preview
  queryClient.invalidateQueries({ queryKey: ["conversations"] });
}
