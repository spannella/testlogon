import { api } from "@/api/client";
import type {
  SpendingSummary,
  YearComparison,
  TaxDocument,
  TaxDocumentList,
} from "@/api/types";

export interface TaxRangeParams {
  year?: number;
  date_from?: number;
  date_to?: number;
}

function toQuery(params: TaxRangeParams): Record<string, string> {
  const qp: Record<string, string> = {};
  if (params.year != null) qp.year = String(params.year);
  if (params.date_from != null) qp.date_from = String(params.date_from);
  if (params.date_to != null) qp.date_to = String(params.date_to);
  return qp;
}

export const getSpendingSummary = (params: TaxRangeParams) =>
  api.get<SpendingSummary>("/ui/tax-documents/summary", toQuery(params));

export const getYearComparison = (year: number) =>
  api.get<YearComparison>("/ui/tax-documents/comparison", { year: String(year) });

export const getDocumentHistory = () =>
  api.get<TaxDocumentList>("/ui/tax-documents/history");

export const generateTaxDocument = (year: number, regenerate = false) =>
  api.post<TaxDocument>("/ui/tax-documents/generate", { year, regenerate });

function buildQs(params: TaxRangeParams): string {
  const qp = toQuery(params);
  const qs = new URLSearchParams(qp).toString();
  return qs ? `?${qs}` : "";
}

async function downloadBlob(path: string, filename: string): Promise<void> {
  const res = await fetch(path, { method: "GET", credentials: "include" });
  if (!res.ok) {
    throw new Error(`Download failed (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function downloadSummaryPdf(params: TaxRangeParams): Promise<void> {
  const name = params.year != null ? `earnings-summary-${params.year}.pdf` : "earnings-summary.pdf";
  await downloadBlob(`/ui/tax-documents/summary/pdf${buildQs(params)}`, name);
}

export async function downloadDocumentPdf(year: number): Promise<void> {
  await downloadBlob(`/ui/tax-documents/document/${year}/pdf`, `earnings-summary-${year}.pdf`);
}
