import type { ShipmentStatus } from "@/api/endpoints/shipping";

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtCents(cents?: number | null, currency = "usd"): string {
  if (cents == null) return "—";
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: currency.toUpperCase(),
    }).format(cents / 100);
  } catch {
    return `$${(cents / 100).toFixed(2)}`;
  }
}

export const STATUS_LABELS: Record<ShipmentStatus, string> = {
  pending_fulfillment: "Pending fulfillment",
  label_created: "Label created",
  picked_up: "Picked up",
  in_transit: "In transit",
  out_for_delivery: "Out for delivery",
  delivered: "Delivered",
  exception: "Exception",
  returned: "Returned",
  cancelled: "Cancelled",
};

// Mirrors app/services/shipments.py _TRANSITIONS
export const STATUS_TRANSITIONS: Record<ShipmentStatus, ShipmentStatus[]> = {
  pending_fulfillment: ["label_created", "cancelled"],
  label_created: ["picked_up", "cancelled"],
  picked_up: ["in_transit"],
  in_transit: ["out_for_delivery", "exception", "returned"],
  out_for_delivery: ["delivered", "exception"],
  delivered: ["returned"],
  exception: ["returned", "in_transit"],
  returned: [],
  cancelled: [],
};

export function statusVariant(
  status: ShipmentStatus,
): "default" | "secondary" | "destructive" | "outline" {
  if (status === "delivered") return "default";
  if (status === "cancelled" || status === "exception" || status === "returned")
    return "destructive";
  if (status === "pending_fulfillment") return "outline";
  return "secondary";
}

export const CARRIER_CODES = ["ups", "fedex", "usps", "dhl", "manual"] as const;
export const METHOD_CODES = [
  "ground",
  "express",
  "overnight",
  "economy",
  "flat_rate",
] as const;

export function isAddressObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

export function formatAddress(addr: Record<string, unknown> | undefined): string {
  if (!addr) return "—";
  const parts = [
    addr.name,
    addr.line1 ?? addr.address1 ?? addr.street,
    addr.line2 ?? addr.address2,
    [addr.city, addr.state ?? addr.region, addr.zip ?? addr.postal_code]
      .filter(Boolean)
      .join(", "),
    addr.country,
  ]
    .filter((p) => p != null && String(p).trim() !== "")
    .map((p) => String(p));
  return parts.length ? parts.join("\n") : "—";
}
