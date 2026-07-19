import { Package, Truck, ExternalLink, CheckCircle2, Circle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { OrderShipment } from "@/api/endpoints/orderLifecycle";

// ─────────────────────────────────────────────────────────────────────────────
// ECOMX-SELLDASH-E2 — buyer-facing shipment tracking render.
//
// Renders the E1 inline shipment(s) surfaced on the buyer order (carrier,
// tracking number as a carrier-URL link when present, status, and a simple
// timeline from last_event) so the buyer can see WHERE their order is without
// ever needing the ship_group_id.
// ─────────────────────────────────────────────────────────────────────────────

/** Coarse label for a shipment/tracking status string. */
function prettyTrackingStatus(status: string | null | undefined): string {
  if (!status) return "—";
  return status
    .split(/[_\s]+/)
    .map((w) => (w ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/** Map a shipment status to a badge variant. */
function statusVariant(status: string): "default" | "secondary" | "outline" {
  const s = status.toLowerCase();
  if (s.includes("deliver")) return "default";
  if (s.includes("transit") || s.includes("out_for") || s.includes("shipped")) return "secondary";
  return "outline";
}

/** Ordered coarse tracking milestones for the mini progress timeline. */
const TRACKING_MILESTONES: Array<{ key: string; label: string; match: (s: string) => boolean }> = [
  { key: "label", label: "Label created", match: (s) => s.includes("label") || s.includes("pre_transit") },
  { key: "transit", label: "In transit", match: (s) => s.includes("transit") || s.includes("shipped") },
  { key: "out", label: "Out for delivery", match: (s) => s.includes("out_for") || s.includes("out for") },
  { key: "delivered", label: "Delivered", match: (s) => s.includes("deliver") },
];

function milestoneIndex(status: string): number {
  const s = status.toLowerCase();
  let idx = 0;
  TRACKING_MILESTONES.forEach((m, i) => {
    if (m.match(s)) idx = i;
  });
  return idx;
}

function fmtTs(ts?: number | null): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString();
}

export function ShipmentTrackingCard({ shipment }: { shipment: OrderShipment }) {
  const status = shipment.status || "";
  const activeIdx = milestoneIndex(status);
  const delivered = status.toLowerCase().includes("deliver");
  const lastEventDesc =
    (shipment.last_event && (shipment.last_event.description as string)) || "";
  const lastEventTs =
    shipment.last_event && typeof shipment.last_event.ts === "number"
      ? (shipment.last_event.ts as number)
      : shipment.updated_at;

  return (
    <div className="rounded-md border p-4 space-y-4" data-testid="shipment-tracking">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Truck className="h-4 w-4 text-muted-foreground" />
            {shipment.carrier ? (
              <span className="uppercase" data-testid="shipment-carrier">
                {shipment.carrier}
              </span>
            ) : (
              <span className="text-muted-foreground">Carrier pending</span>
            )}
          </div>
          {shipment.tracking_number ? (
            <div className="text-xs text-muted-foreground">
              Tracking:{" "}
              {shipment.tracking_url ? (
                <a
                  href={shipment.tracking_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 font-mono text-foreground underline hover:no-underline"
                  data-testid="shipment-tracking-link"
                >
                  {shipment.tracking_number}
                  <ExternalLink className="h-3 w-3" />
                </a>
              ) : (
                <span className="font-mono text-foreground" data-testid="shipment-tracking-number">
                  {shipment.tracking_number}
                </span>
              )}
            </div>
          ) : (
            <div className="text-xs text-muted-foreground">Tracking number pending</div>
          )}
        </div>
        <Badge variant={statusVariant(status)} data-testid="shipment-status">
          {prettyTrackingStatus(status)}
        </Badge>
      </div>

      {/* Mini progress timeline */}
      <ol className="flex items-center">
        {TRACKING_MILESTONES.map((m, i) => {
          const reached = delivered ? true : i <= activeIdx;
          const isLast = i === TRACKING_MILESTONES.length - 1;
          return (
            <li key={m.key} className="flex flex-1 items-center last:flex-none">
              <div className="flex flex-col items-center gap-1">
                {reached ? (
                  <CheckCircle2 className="h-4 w-4 text-primary" />
                ) : (
                  <Circle className="h-4 w-4 text-muted-foreground/40" />
                )}
                <span
                  className={
                    "whitespace-nowrap text-[10px] " +
                    (reached ? "text-foreground" : "text-muted-foreground/60")
                  }
                >
                  {m.label}
                </span>
              </div>
              {!isLast && (
                <div
                  className={
                    "mx-1 h-0.5 flex-1 " + (i < activeIdx || delivered ? "bg-primary" : "bg-muted")
                  }
                />
              )}
            </li>
          );
        })}
      </ol>

      {(lastEventDesc || lastEventTs) && (
        <p className="text-xs text-muted-foreground">
          {lastEventDesc || prettyTrackingStatus(status)}
          {lastEventTs ? ` · ${fmtTs(lastEventTs)}` : ""}
        </p>
      )}
    </div>
  );
}

/**
 * Renders the whole inline-shipment block for a buyer order. Returns null when
 * there are no shipments to surface (order not yet shipped) so callers can gate
 * on it cleanly.
 */
export function OrderShipmentTracking({
  shipments,
  fulfillmentStatus,
}: {
  shipments: OrderShipment[] | null | undefined;
  fulfillmentStatus?: string | null;
}) {
  const withData = (shipments || []).filter(
    (s) => s.carrier || s.tracking_number || s.status,
  );
  if (withData.length === 0) return null;
  return (
    <div className="space-y-3" data-testid="order-shipment-tracking">
      {fulfillmentStatus && (
        <div className="flex items-center gap-2 text-sm">
          <Package className="h-4 w-4 text-muted-foreground" />
          <span className="text-muted-foreground">Fulfilment:</span>
          <span className="font-medium">{prettyTrackingStatus(fulfillmentStatus)}</span>
        </div>
      )}
      {withData.map((s) => (
        <ShipmentTrackingCard key={s.ship_group_id || s.tracking_number} shipment={s} />
      ))}
    </div>
  );
}
