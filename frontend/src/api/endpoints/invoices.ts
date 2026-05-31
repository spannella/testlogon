import { api } from "@/api/client";
import type { Invoice, InvoiceList, InvoiceEmailResult } from "@/api/types";

export interface InvoiceListParams {
  type?: string;
  date_from?: number;
  date_to?: number;
  limit?: number;
  cursor?: string;
}

export const listInvoices = (params: InvoiceListParams = {}) => {
  const qp: Record<string, string> = {};
  if (params.type) qp.type = params.type;
  if (params.date_from != null) qp.date_from = String(params.date_from);
  if (params.date_to != null) qp.date_to = String(params.date_to);
  if (params.limit != null) qp.limit = String(params.limit);
  if (params.cursor) qp.cursor = params.cursor;
  return api.get<InvoiceList>("/ui/invoices", qp);
};

export const getInvoice = (invoiceNumber: string) =>
  api.get<Invoice>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}`);

export const emailInvoice = (invoiceNumber: string) =>
  api.post<InvoiceEmailResult>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}/email`);

/**
 * Download an invoice PDF. Uses a raw fetch (the JSON api wrapper can't return a
 * blob) and triggers a browser download. Carries cookies for the session.
 */
export async function downloadInvoicePdf(invoiceNumber: string): Promise<void> {
  const res = await fetch(`/ui/invoices/${encodeURIComponent(invoiceNumber)}/pdf`, {
    method: "GET",
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(`Download failed (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${invoiceNumber}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
