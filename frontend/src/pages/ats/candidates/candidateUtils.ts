// Shared helpers for the ATS Candidates UI cluster (CND-001..007).
import type { ApiError } from "@/api/client";

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function humanize(s?: string | null): string {
  if (!s) return "—";
  return s
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function fullName(first?: string | null, last?: string | null): string {
  return [first, last].filter(Boolean).join(" ").trim() || "(no name)";
}

export function isNotEnabled(err: unknown): boolean {
  const e = err as ApiError | undefined;
  return !!e && (e.status === 404 || e.status === 503);
}

/** Tailwind class string for a candidate status badge. */
export function statusColor(status: string): string {
  switch (status) {
    case "active":
      return "bg-blue-500/15 text-blue-700 dark:text-blue-300";
    case "qualified":
      return "bg-violet-500/15 text-violet-700 dark:text-violet-300";
    case "submitted":
      return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
    case "interviewing":
      return "bg-orange-500/15 text-orange-700 dark:text-orange-300";
    case "placed":
      return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
    case "on_hold":
      return "bg-yellow-500/15 text-yellow-700 dark:text-yellow-300";
    case "not_in_search":
      return "bg-slate-500/15 text-slate-600 dark:text-slate-400";
    case "archived":
      return "bg-red-500/10 text-red-600 dark:text-red-400";
    default:
      return "bg-muted text-muted-foreground";
  }
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
