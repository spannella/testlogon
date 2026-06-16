/**
 * Shared helpers for the ATS Pipeline UI cluster (PIP-001..PIP-010).
 */
import type { ApiError } from "@/api/client";
import type { PipelineStatusItem } from "@/api/endpoints/atsPipeline";

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

/** Format integer cents as USD currency string. */
export function formatCents(cents: number | null | undefined): string {
  if (cents == null) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

export function humanize(s?: string | null): string {
  if (!s) return "—";
  return s
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Returns true when the error represents a disabled / missing feature. */
export function isNotEnabled(err: unknown): boolean {
  const e = err as ApiError | undefined;
  return !!e && (e.status === 503 || e.status === 404);
}

/** Tailwind badge colour for a pipeline status key. */
export function statusBadgeClass(statusKey: string, config: PipelineStatusItem | undefined): string {
  if (!config) return "bg-muted text-muted-foreground";
  if (config.is_placed) return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
  if (config.is_terminal) return "bg-red-500/15 text-red-600 dark:text-red-400";
  if (config.is_submitted) return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
  if (config.color) {
    // Use inline style; return class for structure
    return "";
  }
  // Rank-based heuristic colours for default statuses
  if (statusKey.startsWith("1")) return "bg-slate-500/15 text-slate-600 dark:text-slate-400";
  if (statusKey.startsWith("2")) return "bg-sky-500/15 text-sky-700 dark:text-sky-300";
  if (statusKey.startsWith("3")) return "bg-violet-500/15 text-violet-700 dark:text-violet-300";
  if (statusKey.startsWith("4")) return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
  if (statusKey.startsWith("5")) return "bg-orange-500/15 text-orange-700 dark:text-orange-300";
  if (statusKey.startsWith("6")) return "bg-blue-500/15 text-blue-700 dark:text-blue-300";
  return "bg-muted text-muted-foreground";
}

/** Render 0–5 star rating as a string of star chars. */
export function starRating(rating: number): string {
  if (!rating) return "—";
  return "★".repeat(rating) + "☆".repeat(5 - rating);
}
