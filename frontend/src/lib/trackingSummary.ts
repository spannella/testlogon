import type { CarrierTrackingView, CarrierEvent } from "@/api/types";

/**
 * Normalized, view-ready summary of a shipment-tracking payload.
 *
 * Pure logic extracted from the transaction-detail tracking view so it can be
 * unit-tested without React. The backend `/tracking` endpoint returns null-ish
 * fields when the order has no carrier/tracking number yet (honest-empty), so
 * this collapses that into a single `hasTracking` flag the UI can branch on.
 */
export interface TrackingSummary {
  /** True only when both a carrier and a tracking number are present. */
  hasTracking: boolean;
  /** Uppercased carrier code, or empty string when absent. */
  carrierLabel: string;
  /** Raw tracking number, or empty string when absent. */
  trackingNumber: string;
  /** Deep link to the carrier's tracking page, or null when unavailable. */
  trackingUrl: string | null;
  /** Human-friendly status label (e.g. "In Transit"), or "Unknown". */
  statusLabel: string;
  /** Estimated-delivery string as provided by the carrier, or null. */
  estimatedDelivery: string | null;
  /** Carrier scan events, newest-first, always an array (never null). */
  events: CarrierEvent[];
}

/** Title-case a raw status token such as `in_transit` -> `In Transit`. */
export function formatTrackingStatus(status: string | null | undefined): string {
  const raw = (status ?? "").trim();
  if (!raw) return "Unknown";
  return raw
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Build a display-ready {@link TrackingSummary} from a raw tracking payload.
 *
 * Accepts `null`/`undefined` (e.g. a degraded 404 read) and returns an
 * honest-empty summary rather than throwing.
 */
export function summarizeTracking(
  view: CarrierTrackingView | null | undefined,
): TrackingSummary {
  const carrier = (view?.carrier ?? "").trim();
  const trackingNumber = (view?.tracking_number ?? "").trim();
  const trackingUrl = (view?.tracking_url ?? "").trim();
  const estimated = (view?.estimated_delivery ?? "").trim();
  const rawEvents = Array.isArray(view?.carrier_events) ? view!.carrier_events! : [];

  return {
    hasTracking: carrier.length > 0 && trackingNumber.length > 0,
    carrierLabel: carrier.toUpperCase(),
    trackingNumber,
    trackingUrl: trackingUrl.length > 0 ? trackingUrl : null,
    statusLabel: formatTrackingStatus(view?.status),
    estimatedDelivery: estimated.length > 0 ? estimated : null,
    events: rawEvents,
  };
}
