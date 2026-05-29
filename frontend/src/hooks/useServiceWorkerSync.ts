/**
 * PWA-005: Listen for postMessage events from the service worker (PWA-004
 * Background Sync) and update the offline store + React Query cache accordingly.
 */

import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useOfflineStore } from "@/stores/offlineStore";
import {
  removeOfflineField,
  markOfflineMessageFailed,
} from "@/lib/offlineMessageHelpers";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";

export function useServiceWorkerSync() {
  const removeFromQueue = useOfflineStore((s) => s.removeFromQueue);
  const updateActionStatus = useOfflineStore((s) => s.updateActionStatus);
  const queryClient = useQueryClient();

  React.useEffect(() => {
    const handler = (event: MessageEvent) => {
      const { type, id, error } = event.data ?? {};

      if (type === "sync-item-success" && typeof id === "string") {
        removeFromQueue(id);
        removeOfflineField(queryClient, id);
      }

      if (type === "sync-item-failure" && typeof id === "string") {
        updateActionStatus(id, "failed", error ?? "Background sync failed");
        markOfflineMessageFailed(queryClient, id, error ?? "Background sync failed");
      }

      if (type === "sync-batch-complete") {
        queryClient.invalidateQueries({ queryKey: ["messages"] });
        queryClient.invalidateQueries({ queryKey: ["conversations"] });
        invalidateFeedCaches(queryClient);
      }
    };

    navigator.serviceWorker?.addEventListener("message", handler);
    return () => {
      navigator.serviceWorker?.removeEventListener("message", handler);
    };
  }, [removeFromQueue, updateActionStatus, queryClient]);
}
