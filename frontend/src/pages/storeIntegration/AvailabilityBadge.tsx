import { Badge } from "@/components/ui/badge";
import type { StorefrontAvailability } from "@/api/endpoints/storeIntegration";

interface Props {
  availability?: StorefrontAvailability | null;
  // Legacy fallback when live availability is disabled.
  stockStatus?: string;
  stockCount?: number | null;
}

const STATUS_LABEL: Record<string, string> = {
  in_stock: "In stock",
  low_stock: "Low stock",
  out_of_stock: "Out of stock",
  unlimited: "Available",
};

/**
 * Live availability badge. When the ECM live-availability sub-flag is on the
 * `availability` projection is present (available = on_hand - reserved). When
 * off we fall back to the legacy scalar stock_status / stock_count.
 */
export function AvailabilityBadge({ availability, stockStatus, stockCount }: Props) {
  const status = availability?.stock_status ?? stockStatus ?? "unlimited";
  const label = STATUS_LABEL[status] ?? status;

  const variant: "default" | "secondary" | "destructive" | "outline" =
    status === "out_of_stock"
      ? "destructive"
      : status === "low_stock"
        ? "secondary"
        : "default";

  return (
    <div className="flex flex-col gap-1">
      <Badge variant={variant} data-testid="availability-badge">
        {label}
      </Badge>
      {availability ? (
        <span className="text-xs text-muted-foreground" data-testid="availability-detail">
          {availability.available} available ({availability.on_hand} on hand
          {availability.reserved > 0 ? `, ${availability.reserved} reserved` : ""})
        </span>
      ) : stockCount != null ? (
        <span className="text-xs text-muted-foreground">{stockCount} in stock</span>
      ) : null}
    </div>
  );
}
