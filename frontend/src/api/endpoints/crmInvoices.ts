// SuiteCRM AOS Invoices + Currency + Tax-rate admin (INV cluster).
//
// Live backend contracts:
//   - Invoices:  app/routers/invoices.py            (/ui/invoices, /ui/admin/invoices)
//   - Convert:   app/routers/aos_quotes.py          (/ui/quotes/{id}/convert-to-invoice)
//   - Currency:  app/routers/crm_currencies.py      (/ui/admin/currencies)
//   - Tax rates: app/routers/crm_tax_rates.py       (/ui/admin/tax-rates)
//
// Types are defined INLINE here (mirroring app/models.py) — NOT in shared api/types.ts.

import { api } from "@/api/client";

// ─── Invoices (mirror app/models.py InvoiceOut / InvoiceLineItemOut) ────────

export interface CrmInvoiceLineItem {
  description: string;
  quantity: number;
  amount_cents: number;
  unit_price_cents: number;
}

export interface CrmInvoice {
  invoice_id: string;
  invoice_number: string;
  invoice_type: string; // tip, unlock, subscription, shop, deposit
  user_sub: string;
  amount_cents: number;
  tax_cents: number;
  total_cents: number;
  currency: string;
  status: string; // generated, emailed, sent, paid, void
  seller_id: string;
  seller_name: string;
  buyer_name: string;
  buyer_email: string;
  line_items: CrmInvoiceLineItem[];
  payment_method_summary: string;
  ledger_entry_id: string;
  created_at: number;
  aos_quote_id: string;
  payment_terms_days: number | null;
  due_date: number | null;
  voided_at: number | null;
}

export interface CrmInvoiceListOut {
  invoices: CrmInvoice[];
  next_cursor: string | null;
}

export interface CrmInvoiceEmailOut {
  ok: boolean;
  emailed_to: string;
  message: string;
}

// Mirror app/models.py ManualInvoiceCreateIn / ManualInvoiceLineItemIn
export interface ManualInvoiceLineItemIn {
  description: string;
  quantity: number;
  unit_price_cents: number;
  tax_rate_bps: number;
}

export interface ManualInvoiceBillingAddressIn {
  street: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
}

export interface ManualInvoiceCreateIn {
  buyer_user_sub?: string;
  buyer_name: string;
  buyer_email: string;
  billing_address?: ManualInvoiceBillingAddressIn;
  line_items: ManualInvoiceLineItemIn[];
  currency?: string;
  payment_terms_days?: number;
  notes?: string;
}

// ─── Currencies (mirror app/models.py Currency*) ────────────────────────────

export interface CrmCurrency {
  iso_code: string;
  name: string;
  symbol: string;
  rate_to_usd: number;
  decimal_places: number;
  is_active: boolean;
  is_default: boolean;
  created_at: number;
  updated_at: number;
}

export interface CrmCurrencyListOut {
  currencies: CrmCurrency[];
}

export interface CurrencyCreateIn {
  iso_code: string;
  name: string;
  symbol: string;
  rate_to_usd: number;
  decimal_places?: number;
  is_active?: boolean;
}

export interface CurrencyPatchIn {
  name?: string;
  symbol?: string;
  rate_to_usd?: number;
  decimal_places?: number;
  is_active?: boolean;
}

// ─── Tax rates (mirror app/models.py TaxRate*) ──────────────────────────────

export interface CrmTaxRate {
  tax_rate_id: string;
  name: string;
  rate_bps: number;
  jurisdiction: string;
  description: string;
  is_active: boolean;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface CrmTaxRateListOut {
  tax_rates: CrmTaxRate[];
  next_cursor: string | null;
}

export interface TaxRateCreateIn {
  name: string;
  rate_bps: number;
  jurisdiction: string;
  description?: string;
}

export interface TaxRatePatchIn {
  name?: string;
  rate_bps?: number;
  jurisdiction?: string;
  description?: string;
  is_active?: boolean;
}

// ─── Quote (subset, for convert-from-quote source list) ─────────────────────

export interface CrmQuoteLineItem {
  catalog_item_id: string;
  description: string;
  qty: number;
  unit_price_cents: number;
  discount_bps: number;
  tax_rate_bps: number;
  line_total_cents: number;
}

export interface CrmQuote {
  quote_id: string;
  quote_number: string;
  title: string;
  stage: string;
  currency: string;
  line_items: CrmQuoteLineItem[];
  subtotal_cents: number;
  discount_cents: number;
  tax_cents: number;
  total_cents: number;
  converted_to_invoice_number: string;
  converted_to_contract_id: string;
  created_at: number;
  updated_at: number;
}

export interface CrmQuoteListOut {
  quotes: CrmQuote[];
  next_cursor: string | null;
}

// ─── Invoice endpoints ──────────────────────────────────────────────────────

export const listCrmInvoices = (opts?: {
  type?: string;
  date_from?: number;
  date_to?: number;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.type) params["type"] = opts.type;
  if (opts?.date_from != null) params["date_from"] = String(opts.date_from);
  if (opts?.date_to != null) params["date_to"] = String(opts.date_to);
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmInvoiceListOut>("/ui/invoices", params);
};

export const getCrmInvoice = (invoiceNumber: string) =>
  api.get<CrmInvoice>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}`);

export const sendCrmInvoice = (invoiceNumber: string) =>
  api.post<CrmInvoice>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}/send`, {});

export const voidCrmInvoice = (invoiceNumber: string) =>
  api.post<CrmInvoice>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}/void`, {});

export const payCrmInvoice = (invoiceNumber: string, payment_ref?: string) =>
  api.post<CrmInvoice>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}/pay`, {
    payment_ref: payment_ref ?? "",
  });

export const emailCrmInvoice = (invoiceNumber: string) =>
  api.post<CrmInvoiceEmailOut>(`/ui/invoices/${encodeURIComponent(invoiceNumber)}/email`, {});

export const crmInvoicePdfUrl = (invoiceNumber: string) =>
  `/ui/invoices/${encodeURIComponent(invoiceNumber)}/pdf`;

// Admin create (manual B2B invoice) — app/routers/invoices.py admin /manual
export const createManualCrmInvoice = (body: ManualInvoiceCreateIn) =>
  api.post<CrmInvoice>("/ui/admin/invoices/manual", body);

export const adminListCrmInvoices = (opts?: {
  user_sub?: string;
  type?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.user_sub) params["user_sub"] = opts.user_sub;
  if (opts?.type) params["type"] = opts.type;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmInvoiceListOut>("/ui/admin/invoices", params);
};

// ─── Convert-from-quote (source list + conversion) ──────────────────────────

export const listCrmQuotes = (opts?: { stage?: string; limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.stage) params["stage"] = opts.stage;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmQuoteListOut>("/ui/quotes", params);
};

export const convertQuoteToInvoice = (quoteId: string) =>
  api.post<CrmInvoice>(`/ui/quotes/${encodeURIComponent(quoteId)}/convert-to-invoice`, {});

// ─── Currency endpoints ─────────────────────────────────────────────────────

export const listCrmCurrencies = (activeOnly = false) =>
  api.get<CrmCurrencyListOut>("/ui/admin/currencies", { active_only: String(activeOnly) });

export const getCrmCurrency = (isoCode: string) =>
  api.get<CrmCurrency>(`/ui/admin/currencies/${encodeURIComponent(isoCode)}`);

export const createCrmCurrency = (body: CurrencyCreateIn) =>
  api.post<CrmCurrency>("/ui/admin/currencies", body);

export const updateCrmCurrency = (isoCode: string, body: CurrencyPatchIn) =>
  api.patch<CrmCurrency>(`/ui/admin/currencies/${encodeURIComponent(isoCode)}`, body);

// ─── Tax-rate endpoints ─────────────────────────────────────────────────────

export const listCrmTaxRates = (opts?: {
  jurisdiction?: string;
  active_only?: boolean;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.jurisdiction) params["jurisdiction"] = opts.jurisdiction;
  if (opts?.active_only != null) params["active_only"] = String(opts.active_only);
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmTaxRateListOut>("/ui/admin/tax-rates", params);
};

export const getCrmTaxRate = (taxRateId: string) =>
  api.get<CrmTaxRate>(`/ui/admin/tax-rates/${encodeURIComponent(taxRateId)}`);

export const createCrmTaxRate = (body: TaxRateCreateIn) =>
  api.post<CrmTaxRate>("/ui/admin/tax-rates", body);

export const updateCrmTaxRate = (taxRateId: string, body: TaxRatePatchIn) =>
  api.patch<CrmTaxRate>(`/ui/admin/tax-rates/${encodeURIComponent(taxRateId)}`, body);

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Integer cents -> formatted currency string. Falls back to USD-style. */
export function formatCents(cents: number, currency = "usd"): string {
  const code = (currency || "usd").toUpperCase();
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: code,
    }).format((cents || 0) / 100);
  } catch {
    return `${code} ${((cents || 0) / 100).toFixed(2)}`;
  }
}

/** basis points -> percent string, e.g. 825 -> "8.25%" */
export function formatBps(bps: number): string {
  return `${((bps || 0) / 100).toFixed(2)}%`;
}
