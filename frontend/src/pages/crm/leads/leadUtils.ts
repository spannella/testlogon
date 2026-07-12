// Shared helpers for the SuiteCRM Leads UI cluster.
import type { ApiError } from "@/api/client";

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtCents(cents?: number | null, currency = "USD"): string {
  if (cents == null) return "—";
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(cents / 100);
  } catch {
    return `$${(cents / 100).toFixed(2)}`;
  }
}

export function humanize(s?: string | null): string {
  if (!s) return "—";
  return s
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// Tailwind classes for status badges.
export function statusVariant(status: string): string {
  switch (status) {
    case "new":
      return "bg-blue-500/15 text-blue-700 dark:text-blue-300";
    case "assigned":
      return "bg-purple-500/15 text-purple-700 dark:text-purple-300";
    case "in_process":
      return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
    case "converted":
      return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
    case "recycled":
      return "bg-slate-500/15 text-slate-700 dark:text-slate-300";
    case "dead":
      return "bg-red-500/15 text-red-700 dark:text-red-300";
    default:
      return "bg-muted text-muted-foreground";
  }
}

export function isNotEnabled(err: unknown): boolean {
  const e = err as ApiError | undefined;
  return !!e && (e.status === 404 || e.status === 503);
}

export function fullName(first?: string | null, last?: string | null): string {
  return [first, last].filter(Boolean).join(" ").trim() || "(no name)";
}
