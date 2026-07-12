// Local helpers for the Fixed Assets cluster (kept in-cluster — no shared edits).

export function fmtCents(cents?: number | null): string {
  if (cents === null || cents === undefined) return "—";
  const sign = cents < 0 ? "-" : "";
  const abs = Math.abs(cents);
  return `${sign}$${(abs / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function fmtTsTime(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Convert a YYYY-MM-DD date input value into a Unix timestamp (seconds). */
export function dateInputToTs(value: string): number {
  if (!value) return 0;
  return Math.floor(new Date(`${value}T00:00:00`).getTime() / 1000);
}

/** Convert a dollar string (e.g. "1,200.50") into integer cents. */
export function dollarsToCents(value: string): number {
  const cleaned = value.replace(/[^0-9.]/g, "");
  const num = parseFloat(cleaned);
  if (isNaN(num)) return 0;
  return Math.round(num * 100);
}

export function statusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "active":
      return "default";
    case "fully_depreciated":
      return "secondary";
    case "disposed":
      return "destructive";
    case "posted":
      return "default";
    case "scheduled":
      return "outline";
    case "cancelled":
      return "destructive";
    case "open":
      return "outline";
    case "in_progress":
      return "default";
    case "completed":
      return "secondary";
    default:
      return "secondary";
  }
}

export function prettyStatus(status: string): string {
  return status
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
