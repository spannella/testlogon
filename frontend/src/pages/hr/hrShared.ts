import { ApiError } from "@/api/client";

/** Format an integer-cents amount as a currency string. */
export function fmtCents(cents: number, currency = "USD"): string {
  const code = (currency || "USD").toUpperCase();
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: code,
    }).format((cents || 0) / 100);
  } catch {
    return `${((cents || 0) / 100).toFixed(2)} ${code}`;
  }
}

/** Format a Unix timestamp (seconds) as a human-readable date. */
export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

/** Format a Unix timestamp (seconds) as a human-readable date+time. */
export function fmtDateTime(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Convert a yyyy-mm-dd date input value to a Unix timestamp (seconds, UTC midnight). */
export function dateInputToTs(value: string): number {
  if (!value) return 0;
  return Math.floor(new Date(`${value}T00:00:00Z`).getTime() / 1000);
}

/** Convert a Unix timestamp (seconds) to a yyyy-mm-dd date input value. */
export function tsToDateInput(ts?: number | null): string {
  if (!ts) return "";
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

/** True when the error means the HR/payroll feature flag is OFF (404/503). */
export function isFeatureDisabled(err: unknown): boolean {
  if (err instanceof ApiError) {
    return err.status === 404 || err.status === 503;
  }
  return false;
}
