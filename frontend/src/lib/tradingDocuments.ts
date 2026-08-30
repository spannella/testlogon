// FE-170 (EPIC H) — pure, DOM-free helpers for the Trading Documents area.
// Every function here is a pure transform over a TradingDocument so they are
// trivially unit-testable (see tradingDocuments.test.ts). No I/O, no React.
import type {
  TradingDocument,
  TradingDocType,
  TradingDocFormat,
} from "@/api/endpoints/tradingDocuments";

// ── type catalog ─────────────────────────────────────────────────────

export const TRADING_DOC_TYPES: TradingDocType[] = [
  "statement",
  "1099",
  "confirmation",
  "fills",
  "pnl",
];

/** Human labels per document type. */
const TYPE_LABELS: Record<TradingDocType, string> = {
  statement: "Account Statements",
  "1099": "Tax Forms (1099)",
  confirmation: "Trade Confirmations",
  fills: "Fills Reports",
  pnl: "P&L Statements",
};

/** lucide icon KEY per type (the UI maps these to actual components). */
export const TRADING_DOC_ICONS: Record<TradingDocType, string> = {
  statement: "FileText",
  "1099": "Receipt",
  confirmation: "FileCheck",
  fills: "FileSpreadsheet",
  pnl: "TrendingUp",
};

/** Label for a document type (falls back to a titleised raw type). */
export function docTypeLabel(type: string): string {
  const known = (TYPE_LABELS as Record<string, string | undefined>)[type];
  if (known) return known;
  return type
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// ── time helpers (pure) ──────────────────────────────────────────────

const MS_THRESHOLD = 1e12;

/** Parse a doc timestamp (ISO string, or epoch seconds/ms) to ms, or null. */
function toMs(value: string | number | undefined | null): number | null {
  if (value == null || value === "") return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    return value < MS_THRESHOLD ? value * 1000 : value;
  }
  const asNum = Number(value);
  if (value.trim() !== "" && Number.isFinite(asNum) && /^\d+$/.test(value.trim())) {
    return asNum < MS_THRESHOLD ? asNum * 1000 : asNum;
  }
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/** Sort key for "newest first" — docs without a date sort last. */
function createdMs(doc: TradingDocument): number {
  const ms = toMs(doc.created_at);
  return ms == null ? -Infinity : ms;
}

/** Best-effort year from a doc (tax_year, else period_start, else created_at). */
function docYear(doc: TradingDocument): number | null {
  if (doc.tax_year != null && Number.isFinite(doc.tax_year)) return doc.tax_year;
  const ms = toMs(doc.period_start) ?? toMs(doc.created_at);
  return ms == null ? null : new Date(ms).getUTCFullYear();
}

/** ISO date (YYYY-MM-DD) for a timestamp value, or "". */
function isoDate(value: string | number | undefined | null): string {
  const ms = toMs(value);
  if (ms == null) return "";
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

// ── grouping ─────────────────────────────────────────────────────────

export interface TradingDocGroup {
  type: TradingDocType;
  label: string;
  documents: TradingDocument[];
}

/**
 * Group documents by type (in TRADING_DOC_TYPES order, unknown types after),
 * each group sorted newest-first. Empty groups are omitted.
 */
export function groupDocuments(docs: TradingDocument[]): TradingDocGroup[] {
  const byType = new Map<string, TradingDocument[]>();
  for (const doc of docs) {
    const key = doc.type;
    const arr = byType.get(key);
    if (arr) arr.push(doc);
    else byType.set(key, [doc]);
  }

  const orderedKeys: string[] = [
    ...TRADING_DOC_TYPES.filter((t) => byType.has(t)),
    ...[...byType.keys()].filter((k) => !TRADING_DOC_TYPES.includes(k as TradingDocType)),
  ];

  return orderedKeys.map((key) => {
    const documents = [...(byType.get(key) ?? [])].sort((a, b) => createdMs(b) - createdMs(a));
    return {
      type: key as TradingDocType,
      label: docTypeLabel(key),
      documents,
    };
  });
}

// ── titles / filenames ───────────────────────────────────────────────

/** Human-readable title for a document (uses the explicit title when present). */
export function docTitle(doc: TradingDocument): string {
  if (doc.title && doc.title.trim()) return doc.title.trim();
  const year = docYear(doc);
  switch (doc.type) {
    case "statement":
      return year != null ? `${year} Account Statement` : "Account Statement";
    case "1099":
      return year != null ? `1099-B ${year}` : "1099-B";
    case "confirmation": {
      const day = isoDate(doc.period_start) || isoDate(doc.created_at);
      return day ? `Trade Confirmation — ${day}` : "Trade Confirmation";
    }
    case "fills":
      return year != null ? `${year} Fills Report` : "Fills Report";
    case "pnl":
      return year != null ? `${year} P&L Statement` : "P&L Statement";
    default:
      return docTypeLabel(doc.type);
  }
}

const EXT_BY_FORMAT: Record<TradingDocFormat, string> = { pdf: "pdf", csv: "csv" };

/** Slugify a title into a filesystem-safe base name. */
function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-") || "document";
}

/** Safe download filename with the correct extension for the doc format. */
export function docFilename(doc: TradingDocument): string {
  const ext = doc.format && EXT_BY_FORMAT[doc.format] ? EXT_BY_FORMAT[doc.format] : "pdf";
  return `${slug(docTitle(doc))}.${ext}`;
}

// ── status / metadata ────────────────────────────────────────────────

/** True when a doc is ready AND has something to download (url or id). */
export function isDownloadable(doc: TradingDocument): boolean {
  if (doc.status === "generating") return false;
  const hasSource = Boolean(doc.download_url) || Boolean(doc.doc_id);
  return hasSource;
}

/** Format bytes into a compact human size (e.g. "1.2 MB"), or "". */
export function formatBytes(bytes: number | undefined | null): string {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let val = bytes / 1024;
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i += 1;
  }
  const rounded = val >= 10 || Number.isInteger(val) ? Math.round(val) : Math.round(val * 10) / 10;
  return `${rounded} ${units[i]}`;
}

/**
 * One-line metadata: period (or date), file size, and format — joined with " · ".
 * Empty parts are dropped so there are never dangling separators.
 */
export function formatDocMeta(doc: TradingDocument): string {
  const parts: string[] = [];

  const start = isoDate(doc.period_start);
  const end = isoDate(doc.period_end);
  if (start && end) parts.push(`${start} – ${end}`);
  else if (start) parts.push(start);
  else {
    const created = isoDate(doc.created_at);
    if (created) parts.push(created);
  }

  const size = formatBytes(doc.size_bytes);
  if (size) parts.push(size);

  if (doc.format) parts.push(doc.format.toUpperCase());

  return parts.join(" · ");
}
