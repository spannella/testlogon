// BCAST-010 — Broadcast newsfeed promotion control.
import React from "react";
import {
  promoteBroadcast,
  getBroadcastPromo,
  syncBroadcastPromo,
  unpromoteBroadcast,
} from "@/api/endpoints/broadcastPromo";
import type { BroadcastPromoLink } from "@/api/types";

interface BroadcastPromoControlProps {
  broadcastId: string;
}

export const BroadcastPromoControl: React.FC<BroadcastPromoControlProps> = ({
  broadcastId,
}) => {
  const [link, setLink] = React.useState<BroadcastPromoLink | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    try {
      const res = await getBroadcastPromo(broadcastId);
      setLink(res.link);
    } catch {
      // 404 → not promoted.
      setLink(null);
    }
  }, [broadcastId]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const handlePromote = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await promoteBroadcast(broadcastId);
      setLink(res.link);
    } catch {
      setError("Failed to promote broadcast");
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await syncBroadcastPromo(broadcastId);
      setLink(res.link);
    } catch {
      setError("Failed to sync promotion");
    } finally {
      setLoading(false);
    }
  };

  const handleUnpromote = async () => {
    setLoading(true);
    setError(null);
    try {
      await unpromoteBroadcast(broadcastId);
      setLink(null);
    } catch {
      setError("Failed to unpromote broadcast");
    } finally {
      setLoading(false);
    }
  };

  const isPromoted = link !== null && !link.removed;

  return (
    <div data-testid="broadcast-promo-control">
      <h3>Newsfeed promotion</h3>
      {error ? (
        <p data-testid="broadcast-promo-error" role="alert">
          {error}
        </p>
      ) : null}
      {isPromoted ? (
        <div>
          <p data-testid="broadcast-promo-status">
            Promoted to newsfeed (post {link!.post_id}, status{" "}
            {link!.last_synced_status})
          </p>
          <button type="button" onClick={handleSync} disabled={loading}>
            Sync status
          </button>
          <button type="button" onClick={handleUnpromote} disabled={loading}>
            Remove from newsfeed
          </button>
        </div>
      ) : (
        <div>
          <p data-testid="broadcast-promo-status">Not promoted</p>
          <button type="button" onClick={handlePromote} disabled={loading}>
            Promote to newsfeed
          </button>
        </div>
      )}
    </div>
  );
};
