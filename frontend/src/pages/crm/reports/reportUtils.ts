import { ApiError } from "@/api/client";
import type { ReportModule } from "@/api/endpoints/crmReports";

/** True when the error represents a disabled-feature response (404 or 503). */
export function isNotEnabled(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

/** Format a Unix-seconds timestamp for display. */
export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Format integer cents as a USD currency string. */
export function fmtCents(cents?: number | null): string {
  const n = typeof cents === "number" ? cents : 0;
  return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(n / 100);
}

/** Coerce an arbitrary report cell value to a display string. */
export function fmtCell(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

/** Heuristic: does a column name look like it holds integer cents? */
export function looksLikeCents(col: string): boolean {
  return /(_cents|amount_cents|cents)$/i.test(col);
}

/** Human label for a report module. */
export function moduleLabel(module: ReportModule | string): string {
  switch (module) {
    case "tickets":
      return "Tickets";
    case "contacts":
      return "Contacts";
    case "billing_ledger":
      return "Billing Ledger";
    case "orders":
      return "Orders";
    case "subscriptions":
      return "Subscriptions";
    case "questionnaire_responses":
      return "Questionnaire Responses";
    default:
      return String(module);
  }
}

/** Sensible default fields per module to bootstrap the report builder. */
export const MODULE_DEFAULT_FIELDS: Record<string, string[]> = {
  tickets: ["ticket_id", "subject", "status", "created_at"],
  contacts: ["contact_id", "name", "email", "phone"],
  billing_ledger: ["sk", "type", "amount_cents", "ts"],
  orders: ["order_id", "status", "total_cents", "created_at"],
  subscriptions: ["sk", "plan_id", "status", "created_at"],
  questionnaire_responses: ["response_id", "questionnaire_id", "submitted_at"],
};
