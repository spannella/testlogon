import * as React from "react";
import { toast } from "sonner";
import { useQueryClient } from "@tanstack/react-query";
import { useOfflineStore, type OfflineAction } from "@/stores/offlineStore";
import { sendTextMessage } from "@/api/endpoints/messaging";
import { createPost } from "@/api/endpoints/newsfeed";

export function useOfflineQueue() {
  const queue = useOfflineStore((s) => s.queue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const setOnline = useOfflineStore((s) => s.setOnline);
  const removeFromQueue = useOfflineStore((s) => s.removeFromQueue);
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
  React.useEffect(() => {
    if (!isOnline || queue.length === 0 || isFlushing.current) return;

    const flush = async () => {
      isFlushing.current = true;

      // Snapshot — process only items that existed at flush-start
      const snapshot = [...queue];
      toast.info(`Sending ${snapshot.length} queued item${snapshot.length !== 1 ? "s" : ""}…`);

      let successCount = 0;
      let failCount = 0;

      for (const action of snapshot) {
        try {
          await dispatchAction(action);
          removeFromQueue(action.id);
          successCount += 1;
        } catch {
          failCount += 1;
          // Keep in queue — will retry on next reconnect
        }
      }

      if (successCount > 0) {
        void queryClient.invalidateQueries({ queryKey: ["messages"] });
        void queryClient.invalidateQueries({ queryKey: ["conversations"] });
        void queryClient.invalidateQueries({ queryKey: ["feed"] });
      }

      if (successCount > 0 && failCount === 0) {
        toast.success(
          `${successCount} queued item${successCount !== 1 ? "s" : ""} sent successfully`,
        );
      } else if (successCount > 0 && failCount > 0) {
        toast.warning(
          `${successCount} sent, ${failCount} failed — will retry when back online`,
        );
      } else if (failCount > 0) {
        toast.error(
          `${failCount} queued item${failCount !== 1 ? "s" : ""} failed to send — will retry when back online`,
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
