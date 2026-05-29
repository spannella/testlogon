// frontend/src/lib/swMessageHandler.ts
//
// Listen for postMessage events from the service worker and route them
// to the appropriate Zustand store actions / React Query invalidations (PWA-004).

import type { QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useOfflineStore } from "@/stores/offlineStore";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";

/**
 * Start listening for Background Sync messages from the service worker.
 * Call once after SW registration in main.tsx.
 */
export function listenForSyncMessages(queryClient: QueryClient): void {
  if (!("serviceWorker" in navigator)) return;

  navigator.serviceWorker.addEventListener("message", (event) => {
    const data = event.data;
    if (!data?.type) return;

    switch (data.type) {
      case "sync-item-success": {
        // Item was successfully sent by SW — remove from Zustand queue
        useOfflineStore.getState().removeFromQueue(data.id);
        break;
      }

      case "sync-item-dead": {
        // Item exceeded max retries — move to dead letter
        useOfflineStore
          .getState()
          .moveToDeadLetter(data.id, data.retryCount ?? 0, data.error ?? "Unknown error");
        toast.error("A queued item failed after multiple retries");
        break;
      }

      case "sync-flush-complete": {
        // All items processed — invalidate queries so UI refreshes
        void queryClient.invalidateQueries({ queryKey: ["messages"] });
        void queryClient.invalidateQueries({ queryKey: ["conversations"] });
        void invalidateFeedCaches(queryClient);
        toast.success("Queued items synced");
        break;
      }

      default:
        // Unknown message type — ignore (other handlers will pick it up)
        break;
    }
  });
}
