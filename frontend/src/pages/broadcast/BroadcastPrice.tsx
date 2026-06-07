import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import type { ShelfItem } from "@/api/endpoints/broadcast-shelf";

// ─── Helpers ──────────────────────────────────────────────────────

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

/**
 * Live countdown label for a broadcast-price expiry timestamp.
 * Returns null when there is no expiry, "Expired" once the deadline passes,
 * and a "Xm Ys" / "Ys" label otherwise. Ticks every second.
 */
function useExpiryCountdown(expiresAt: number | null | undefined): string | null {
  const [label, setLabel] = useState<string | null>(null);

  useEffect(() => {
    if (!expiresAt) {
      setLabel(null);
      return;
    }
    const update = () => {
      const seconds = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
      if (seconds === 0) {
        setLabel("Expired");
        return;
      }
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      setLabel(m > 0 ? `${m}m ${s}s` : `${s}s`);
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  return label;
}

// ─── BroadcastPrice ───────────────────────────────────────────────

interface BroadcastPriceProps {
  item: ShelfItem;
}

/**
 * Viewer-facing price display for a shelf product. When a broadcast-exclusive
 * discount is active (`is_broadcast_price`), renders the effective price, the
 * struck-through original price, a "LIVE DEAL X% OFF" badge, and a live expiry
 * countdown. Otherwise falls back to the plain catalog price.
 */
export function BroadcastPrice({ item }: BroadcastPriceProps) {
  const countdown = useExpiryCountdown(item.broadcast_price_expires_at);
  const effectiveCents = item.effective_price_cents ?? item.price_cents;
  const isDiscounted =
    item.is_broadcast_price === true &&
    item.broadcast_price_cents !== null &&
    item.broadcast_price_cents !== undefined;

  if (!isDiscounted) {
    return (
      <p
        className="text-sm font-semibold text-primary"
        aria-label={`Price: ${formatPrice(effectiveCents, item.currency)}`}
      >
        {formatPrice(effectiveCents, item.currency)}
      </p>
    );
  }

  return (
    <div className="space-y-0.5" data-testid={`broadcast-price-${item.item_id}`}>
      <div className="flex items-center gap-1.5 flex-wrap">
        <p
          className="text-sm font-bold text-green-400"
          data-testid="broadcast-price-effective"
          aria-label={`Broadcast price: ${formatPrice(effectiveCents, item.currency)}`}
        >
          {formatPrice(effectiveCents, item.currency)}
        </p>
        <span
          className="text-xs line-through text-muted-foreground"
          data-testid="broadcast-price-original"
        >
          {formatPrice(item.price_cents, item.currency)}
        </span>
        <Badge
          variant="destructive"
          className="text-[10px] px-1 py-0 h-4"
          data-testid="broadcast-price-badge"
        >
          LIVE DEAL {item.discount_pct ?? 0}% OFF
        </Badge>
      </div>
      {countdown && countdown !== "Expired" && (
        <p
          className="text-[10px] text-amber-400"
          data-testid="broadcast-price-countdown"
          aria-label={`Deal expires in ${countdown}`}
        >
          Ends in {countdown}
        </p>
      )}
      {countdown === "Expired" && (
        <p className="text-[10px] text-muted-foreground">Deal ended</p>
      )}
    </div>
  );
}
