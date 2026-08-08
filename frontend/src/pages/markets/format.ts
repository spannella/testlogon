/** Display helpers for market data. Raw values are integers scaled by price_scaler. */

export function formatPrice(value: number | undefined, scaler = 1): string {
  if (value == null || !Number.isFinite(value)) return "—";
  const scaled = value / (scaler || 1);
  return scaled.toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  });
}

export function formatQty(value: number | undefined, scaler = 1): string {
  if (value == null || !Number.isFinite(value)) return "—";
  const scaled = value / (scaler || 1);
  return scaled.toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 4,
  });
}

/** Nanosecond epoch -> local HH:MM:SS. */
export function formatTimeNs(tsNs: number | undefined): string {
  if (tsNs == null || !Number.isFinite(tsNs)) return "—";
  const ms = Math.floor(tsNs / 1_000_000);
  return new Date(ms).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
