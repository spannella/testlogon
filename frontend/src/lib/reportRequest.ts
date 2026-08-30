// FE-171 (EPIC H) — pure, DOM-free helpers for the "Statements & reports"
// request/download flow on the trading/reporting screen. Given a chosen report
// type + params it VALIDATES the request, decides whether it is served as an
// immediate CLIENT-SIDE CSV (fills / pnl, built from live fills) or a
// backend-generated PDF (statement / 1099, requested via BE-170 then downloaded
// from Trading Documents / BE-172), and produces the request payload + a safe
// download filename. No I/O, no React — trivially unit-testable
// (see reportRequest.test.ts).
import type { TradingDocType, TradingDocFormat } from "@/api/endpoints/tradingDocuments";

// ── catalog ──────────────────────────────────────────────────────────

/** The report types offered by the request UI (subset of TradingDocType). */
export type ReportType = "statement" | "pnl" | "fills" | "1099";

export const REPORT_TYPES: ReportType[] = ["statement", "pnl", "fills", "1099"];

/** What params a report type needs before it can be requested. */
export type ParamNeed = "period" | "taxYear";

export interface ReportTypeMeta {
  type: ReportType;
  label: string;
  /** Rendered file format. */
  format: TradingDocFormat;
  /** Which params must be supplied (empty = none). */
  paramsNeeded: ParamNeed[];
  /** One-line helper describing the report. */
  description: string;
}

export const REPORT_TYPE_META: Record<ReportType, ReportTypeMeta> = {
  statement: {
    type: "statement",
    label: "Account statement",
    format: "pdf",
    paramsNeeded: ["period"],
    description: "A point-in-time balance & position statement for a chosen period (PDF).",
  },
  pnl: {
    type: "pnl",
    label: "P&L report",
    format: "csv",
    paramsNeeded: ["period"],
    description: "Per-symbol realized P&L over a period, built from your fills (CSV).",
  },
  fills: {
    type: "fills",
    label: "Fills / trade history",
    format: "csv",
    paramsNeeded: ["period"],
    description: "Every executed fill over a period, built from your fills (CSV).",
  },
  "1099": {
    type: "1099",
    label: "Tax form (1099)",
    format: "pdf",
    paramsNeeded: ["taxYear"],
    description: "Consolidated 1099 for a tax year (PDF).",
  },
};

/** Human label for a report type (falls back to the raw type). */
export function reportTypeLabel(type: ReportType): string {
  return REPORT_TYPE_META[type]?.label ?? String(type);
}

/** The rendered format (pdf|csv) for a report type. */
export function reportFormat(type: ReportType): TradingDocFormat {
  return REPORT_TYPE_META[type]?.format ?? "pdf";
}

/**
 * True for report types built + downloaded ENTIRELY client-side from live fills
 * (a guaranteed real download, no backend). PDF types (statement / 1099) are
 * server-generated and go through the BE-170 request → Trading Documents path.
 */
export function isClientSideCsv(type: ReportType): boolean {
  return type === "fills" || type === "pnl";
}

// ── request shape ────────────────────────────────────────────────────

export interface ReportRequest {
  type: ReportType;
  /** ISO date (YYYY-MM-DD) — required for period reports. */
  periodStart?: string;
  /** ISO date (YYYY-MM-DD) — required for period reports. */
  periodEnd?: string;
  /** Four-digit tax year — required for 1099. */
  taxYear?: number;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Parse an ISO YYYY-MM-DD to epoch ms (UTC midnight), or null if malformed. */
function isoToMs(s: string | undefined): number | null {
  if (!s || !ISO_DATE.test(s)) return null;
  const ms = Date.parse(s + "T00:00:00Z");
  return Number.isNaN(ms) ? null : ms;
}

/** Current year (kept as a param for deterministic tests). */
export function currentYear(now = Date.now()): number {
  return new Date(now).getUTCFullYear();
}

/**
 * Validate a report request, returning a list of human-readable error strings
 * (empty = valid). Rules:
 *  - period reports (statement / fills / pnl) need BOTH a start and end date,
 *    with start <= end;
 *  - 1099 needs a plausible four-digit tax year (2000..currentYear).
 */
export function validateReportRequest(req: ReportRequest, now = Date.now()): string[] {
  const errors: string[] = [];
  const meta = REPORT_TYPE_META[req.type];
  if (!meta) {
    errors.push(`Unknown report type "${String(req.type)}".`);
    return errors;
  }

  if (meta.paramsNeeded.includes("period")) {
    const start = isoToMs(req.periodStart);
    const end = isoToMs(req.periodEnd);
    if (start == null) errors.push("A valid start date is required.");
    if (end == null) errors.push("A valid end date is required.");
    if (start != null && end != null && start > end) {
      errors.push("The start date must be on or before the end date.");
    }
  }

  if (meta.paramsNeeded.includes("taxYear")) {
    const y = req.taxYear;
    const max = currentYear(now);
    if (y == null || !Number.isInteger(y) || y < 2000 || y > max) {
      errors.push(`A tax year between 2000 and ${max} is required.`);
    }
  }

  return errors;
}

/** True when a request passes validation. */
export function isValidReportRequest(req: ReportRequest, now = Date.now()): boolean {
  return validateReportRequest(req, now).length === 0;
}

// ── request payload (BE-170 POST /ui/trading-documents/request) ──────

export interface ReportRequestPayload {
  type: TradingDocType;
  period_start?: string;
  period_end?: string;
  tax_year?: number;
}

/**
 * Build the POST body for BE-170. Only the params the type needs are included
 * (so a 1099 never sends a period, and a statement never sends a tax_year).
 */
export function requestPayload(req: ReportRequest): ReportRequestPayload {
  const meta = REPORT_TYPE_META[req.type];
  const payload: ReportRequestPayload = { type: req.type };
  if (meta?.paramsNeeded.includes("period")) {
    if (req.periodStart) payload.period_start = req.periodStart;
    if (req.periodEnd) payload.period_end = req.periodEnd;
  }
  if (meta?.paramsNeeded.includes("taxYear") && req.taxYear != null) {
    payload.tax_year = req.taxYear;
  }
  return payload;
}

// ── filenames ────────────────────────────────────────────────────────

/** Filename-safe download name for a report request (correct extension). */
export function reportFilename(req: ReportRequest): string {
  const ext = reportFormat(req.type) === "csv" ? "csv" : "pdf";
  let scope = "";
  if (req.type === "1099") {
    scope = req.taxYear != null ? String(req.taxYear) : "unknown-year";
  } else if (req.periodStart && req.periodEnd) {
    scope = `${req.periodStart}_${req.periodEnd}`;
  } else if (req.periodStart) {
    scope = req.periodStart;
  } else {
    scope = "all";
  }
  return `testlogon-${req.type}-${scope}.${ext}`;
}
