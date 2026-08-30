// FE-170 (EPIC H) — Trading Documents feed for the file manager.
// Mirrors the tax-docs / 1099 pattern (list endpoint + a download that is EITHER
// a presigned {download_url} OR streamed bytes). Both calls DEGRADE-ON-404 so the
// UI shows an honest empty state on backends where BE-171/172 are not deployed.
import { api, ApiError } from "@/api/client";

// ── contract (assumed BE-171/172) ────────────────────────────────────

export type TradingDocType = "statement" | "1099" | "confirmation" | "fills" | "pnl";
export type TradingDocFormat = "pdf" | "csv";
export type TradingDocStatus = "ready" | "generating";

export interface TradingDocument {
  doc_id: string;
  type: TradingDocType;
  title?: string;
  period_start?: string;
  period_end?: string;
  tax_year?: number;
  format?: TradingDocFormat;
  size_bytes?: number;
  status?: TradingDocStatus;
  created_at?: string;
  download_url?: string;
}

export interface TradingDocumentList {
  documents: TradingDocument[];
}

export interface TradingDocumentDownload {
  download_url: string;
}

const EMPTY: TradingDocumentList = { documents: [] };

/** Absent-backend statuses that DEGRADE to an honest empty feed. */
function isAbsent(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 501 || err.status === 0);
}

/**
 * List the caller trading documents, optionally filtered by `type`.
 * DEGRADES-ON-404 (endpoint absent) to `{documents:[]}` so the UI renders the
 * empty state rather than crashing. Other errors propagate.
 */
export async function listTradingDocuments(type?: TradingDocType): Promise<TradingDocumentList> {
  try {
    return await api.get<TradingDocumentList>(
      "/ui/trading-documents",
      type ? { type } : undefined,
    );
  } catch (err) {
    if (isAbsent(err)) return EMPTY;
    throw err;
  }
}

/**
 * Resolve a presigned download URL for one document. When the backend streams
 * bytes instead of returning a URL, callers fall back to fetching the download
 * path directly (see the page performDownload path). DEGRADES-ON-404 to null.
 */
export async function getTradingDocumentDownloadUrl(docId: string): Promise<string | null> {
  try {
    const res = await api.get<TradingDocumentDownload>(
      `/ui/trading-documents/${encodeURIComponent(docId)}/download`,
    );
    return res?.download_url ?? null;
  } catch (err) {
    if (isAbsent(err)) return null;
    throw err;
  }
}

/** The raw streamed-bytes download path (used when no presigned URL is returned). */
export function tradingDocumentDownloadPath(docId: string): string {
  return `/ui/trading-documents/${encodeURIComponent(docId)}/download`;
}
