// Shared helpers for the SuiteCRM Activities (ACT) cluster pages.
// Kept local to the cluster namespace — no shared-file edits.

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function fmtDuration(seconds?: number | null): string {
  if (!seconds || seconds <= 0) return "0s";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const parts: string[] = [];
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (s || parts.length === 0) parts.push(`${s}s`);
  return parts.join(" ");
}

/** Convert a datetime-local input value to Unix epoch seconds (or null). */
export function localDateTimeToTs(value: string): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / 1000);
}

/** Convert a Unix epoch (seconds) to a datetime-local input value. */
export function tsToLocalDateTime(ts?: number | null): string {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export const TASK_STATUS_LABELS: Record<string, string> = {
  not_started: "Not started",
  in_progress: "In progress",
  completed: "Completed",
  deferred: "Deferred",
  waiting: "Waiting",
};

export const TASK_PRIORITY_LABELS: Record<string, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  urgent: "Urgent",
};

export const CALL_OUTCOME_LABELS: Record<string, string> = {
  connected: "Connected",
  not_connected: "Not connected",
  left_message: "Left message",
  wrong_number: "Wrong number",
  busy: "Busy",
};

export const ACTIVITY_TYPE_LABELS: Record<string, string> = {
  call: "Call",
  task: "Task",
  note: "Note",
  calendar_event: "Calendar event",
  email: "Email",
};

export function taskPriorityVariant(
  priority: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (priority) {
    case "urgent":
      return "destructive";
    case "high":
      return "default";
    case "medium":
      return "secondary";
    default:
      return "outline";
  }
}

export function taskStatusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "completed":
      return "default";
    case "in_progress":
      return "secondary";
    case "deferred":
    case "waiting":
      return "outline";
    default:
      return "outline";
  }
}
