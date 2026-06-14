import { ApiError } from "@/api/client";
import type {
  CrmProjectStatus,
  CrmProjectMemberRole,
} from "@/api/endpoints/crmProjects";

/** A flag-off backend returns 404; treat as "feature not enabled". */
export function isNotEnabled(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

/** YYYY-MM-DD for <input type="date"> from a unix-seconds timestamp. */
export function toDateInput(ts?: number | null): string {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const m = `${d.getMonth() + 1}`.padStart(2, "0");
  const day = `${d.getDate()}`.padStart(2, "0");
  return `${d.getFullYear()}-${m}-${day}`;
}

/** unix-seconds (UTC midnight) from a YYYY-MM-DD <input type="date"> string. */
export function fromDateInput(value: string): number | null {
  if (!value) return null;
  const ms = Date.parse(`${value}T00:00:00Z`);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

export const PROJECT_STATUSES: CrmProjectStatus[] = [
  "draft",
  "in_review",
  "underway",
  "completed",
  "deferred",
];

export const PROJECT_STATUS_LABELS: Record<CrmProjectStatus, string> = {
  draft: "Draft",
  in_review: "In Review",
  underway: "Underway",
  completed: "Completed",
  deferred: "Deferred",
};

export function statusVariant(
  status: CrmProjectStatus,
): "default" | "secondary" | "outline" | "destructive" {
  switch (status) {
    case "completed":
      return "default";
    case "underway":
      return "secondary";
    case "deferred":
      return "destructive";
    default:
      return "outline";
  }
}

export const PRIORITY_LABELS: Record<number, string> = {
  0: "None",
  1: "Low",
  2: "Medium",
  3: "High",
  4: "Urgent",
};

export function priorityLabel(p: number): string {
  return PRIORITY_LABELS[p] ?? `P${p}`;
}

export const MEMBER_ROLES: CrmProjectMemberRole[] = ["owner", "member", "viewer"];

export const MEMBER_ROLE_LABELS: Record<CrmProjectMemberRole, string> = {
  owner: "Owner",
  member: "Member",
  viewer: "Viewer",
};
