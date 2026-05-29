import * as React from "react";
import { toast } from "sonner";
import { useQueryClient } from "@tanstack/react-query";
import { useOfflineStore, type OfflineAction } from "@/stores/offlineStore";
import { sendTextMessage } from "@/api/endpoints/messaging";
import { createPost } from "@/api/endpoints/newsfeed";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";
import {
  updateOfflineMessageStatus,
  removeOfflineField,
  markOfflineMessageFailed,
} from "@/lib/offlineMessageHelpers";

const MAX_RETRIES = 3;

function isPermanentError(error: unknown): boolean {
  if (error && typeof error === "object" && "status" in error) {
    const status = (error as { status: number }).status;
    if (status === 400 || status === 403 || status === 404 ||
        status === 409 || status === 413 || status === 422) return true;
  }
  return false;
}

export function useOfflineQueue() {
  const queue = useOfflineStore((s) => s.queue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const setOnline = useOfflineStore((s) => s.setOnline);
  const removeFromQueue = useOfflineStore((s) => s.removeFromQueue);
  const updateActionStatus = useOfflineStore((s) => s.updateActionStatus);
  const queryClient = useQueryClient();
  const isFlushing = React.useRef(false);

  // ── Sync window.online / window.offline into the store ─────────
  React.useEffect(() => {
    const goOnline = () => setOnline(true);
    const goOffline = () => setOnline(false);
    window.addEventListener("online", goOnline);
    window.addEventListener("offline", goOffline);
    return () => {
      window.removeEventListener("online", goOnline);
      window.removeEventListener("offline", goOffline);
    };
  }, [setOnline]);

  // ── Flush the queue whenever we come back online ────────────────
  // Skip if SyncManager is available — Background Sync handles it.
  React.useEffect(() => {
    if (!isOnline || queue.length === 0 || isFlushing.current) return;

    // When Background Sync is available, the service worker flushes the IDB queue.
    // The main-thread Zustand queue items will be removed via SW postMessage events.
    if ("SyncManager" in window) return;

    const flush = async () => {
      isFlushing.current = true;

      // Snapshot — process only items that existed at flush-start
      const snapshot = [...queue];
      toast.info(`Sending ${snapshot.length} queued item${snapshot.length !== 1 ? "s" : ""}…`);

      let successCount = 0;
      let failCount = 0;

      for (const action of snapshot) {
        // Update to "sending" status
        updateActionStatus(action.id, "sending");
        updateOfflineMessageStatus(queryClient, action.id, "sending");

        try {
          await dispatchAction(action);
          removeFromQueue(action.id);
          removeOfflineField(queryClient, action.id);
          successCount += 1;
        } catch (error) {
          const retryCount = action.__retryCount ?? 0;
          if (!isPermanentError(error) && retryCount < MAX_RETRIES) {
            // Transient error — stay in queue, revert to pending
            updateActionStatus(action.id, "pending");
            updateOfflineMessageStatus(queryClient, action.id, "pending");
          } else {
            // Permanent error or max retries exceeded — mark failed
            const errorMsg = error instanceof Error ? error.message : "Unknown error";
            updateActionStatus(action.id, "failed", errorMsg);
            markOfflineMessageFailed(queryClient, action.id, errorMsg);
          }
          failCount += 1;
        }
      }

      if (successCount > 0) {
        void queryClient.invalidateQueries({ queryKey: ["messages"] });
        void queryClient.invalidateQueries({ queryKey: ["conversations"] });
        void invalidateFeedCaches(queryClient);
      }

      if (successCount > 0 && failCount === 0) {
        toast.success(
          `${successCount} queued item${successCount !== 1 ? "s" : ""} sent successfully`,
        );
      } else if (successCount > 0 && failCount > 0) {
        toast.warning(
          `${successCount} sent, ${failCount} failed`,
        );
      } else if (failCount > 0) {
        toast.error(
          `${failCount} queued item${failCount !== 1 ? "s" : ""} failed to send`,
        );
      }

      isFlushing.current = false;
    };

    void flush();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOnline, queue.length]);
}

// ─── Action dispatcher ────────────────────────────────────────────

async function dispatchAction(action: OfflineAction): Promise<void> {
  if (action.type === "send_message") {
    await sendTextMessage(action.payload.conversationId, action.payload.req);
    return;
  }
  if (action.type === "create_post") {
    await createPost(action.payload);
    return;
  }
  // TypeScript exhaustive check
  const _exhaustive: never = action;
  throw new Error(`Unknown offline action type: ${(_exhaustive as OfflineAction).type}`);
}
