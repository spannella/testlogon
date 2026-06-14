import { api } from "@/api/client";

// ─── Types (mirror app/models.py QUO-001..QUO-005) ───────────────────────────

export type QuoteStage =
  | "draft"
  | "sent"
  | "accepted"
  | "rejected"
  | "expired"
  | "converted";

export type ContractStage =
  | "draft"
  | "active"
  | "expired"
  | "terminated"
  | "renewed";

export interface QuoteAddress {
  street: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
}

export interface QuoteLineItemIn {
  catalog_item_id?: string;
  description: string;
  qty: number;
  unit_price_cents: number;
  discount_bps?: number;
  tax_rate_bps?: number;
}

export interface QuoteLineItemOut {
  catalog_item_id: string;
  description: string;
  qty: number;
  unit_price_cents: number;
  discount_bps: number;
  tax_rate_bps: number;
  line_total_cents: number;
}

export interface Quote {
  quote_id: string;
  quote_number: string;
  title: string;
  stage: QuoteStage;
  valid_until?: number | null;
  assigned_user_sub: string;
  account_id: string;
  contact_id: string;
  currency: string;
  billing_address: Partial<QuoteAddress>;
  shipping_address: Partial<QuoteAddress>;
  notes: string;
  line_items: QuoteLineItemOut[];
  subtotal_cents: number;
  discount_cents: number;
  tax_cents: number;
  total_cents: number;
  converted_to_invoice_number: string;
  converted_to_contract_id: string;
  created_at: number;
  updated_at: number;
}

export interface QuoteListResp {
  quotes: Quote[];
  next_cursor?: string | null;
}

export interface QuoteCreateIn {
  title: string;
  valid_until?: number | null;
  assigned_user_sub?: string;
  account_id?: string;
  contact_id?: string;
  currency?: string;
  billing_address?: Partial<QuoteAddress>;
  shipping_address?: Partial<QuoteAddress>;
  notes?: string;
  line_items: QuoteLineItemIn[];
}

export interface QuotePatchIn {
  title?: string;
  valid_until?: number | null;
  assigned_user_sub?: string;
  account_id?: string;
  contact_id?: string;
  currency?: string;
  billing_address?: Partial<QuoteAddress>;
  shipping_address?: Partial<QuoteAddress>;
  notes?: string;
  line_items?: QuoteLineItemIn[];
}

export interface InvoiceLineItemOut {
  description?: string;
  quantity?: number;
  unit_price_cents?: number;
  amount_cents?: number;
}

export interface Invoice {
  invoice_id: string;
  invoice_number: string;
  invoice_type: string;
  user_sub: string;
  amount_cents: number;
  tax_cents: number;
  total_cents: number;
  currency: string;
  status: string;
  seller_id: string;
  seller_name: string;
  buyer_name: string;
  buyer_email: string;
  line_items: InvoiceLineItemOut[];
  payment_method_summary: string;
  ledger_entry_id: string;
  created_at: number;
  aos_quote_id: string;
  payment_terms_days?: number | null;
  due_date?: number | null;
  voided_at?: number | null;
}

export interface Contract {
  contract_id: string;
  contract_number: string;
  title: string;
  stage: ContractStage;
  account_id: string;
  contact_id: string;
  aos_quote_id: string;
  start_date: number;
  end_date?: number | null;
  value_cents: number;
  currency: string;
  description: string;
  renewal_notice_days: number;
  renewal_notified_at?: number | null;
  billing_address: Partial<QuoteAddress>;
  shipping_address: Partial<QuoteAddress>;
  created_at: number;
  updated_at: number;
}

export interface ContractListResp {
  contracts: Contract[];
  count: number;
  next_cursor?: string | null;
}

export interface ContractCreateIn {
  title: string;
  start_date: number;
  end_date?: number | null;
  value_cents?: number;
  currency?: string;
  description?: string;
  account_id?: string;
  contact_id?: string;
  renewal_notice_days?: number;
  billing_address?: Partial<QuoteAddress>;
  shipping_address?: Partial<QuoteAddress>;
}

export interface ContractPatchIn {
  title?: string;
  end_date?: number | null;
  value_cents?: number;
  currency?: string;
  description?: string;
  renewal_notice_days?: number;
  billing_address?: Partial<QuoteAddress>;
  shipping_address?: Partial<QuoteAddress>;
}

// ─── Quotes (QUO-001 / QUO-003) ──────────────────────────────────────────────

export const listQuotes = (opts?: {
  stage?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.stage) params["stage"] = opts.stage;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<QuoteListResp>("/ui/quotes", params);
};

export const getQuote = (quoteId: string) =>
  api.get<Quote>(`/ui/quotes/${encodeURIComponent(quoteId)}`);

export const createQuote = (body: QuoteCreateIn) =>
  api.post<Quote>("/ui/quotes", body);

export const patchQuote = (quoteId: string, body: QuotePatchIn) =>
  api.patch<Quote>(`/ui/quotes/${encodeURIComponent(quoteId)}`, body);

export const transitionQuoteStage = (quoteId: string, stage: QuoteStage) =>
  api.post<Quote>(`/ui/quotes/${encodeURIComponent(quoteId)}/stage`, { stage });

export const convertQuoteToInvoice = (quoteId: string) =>
  api.post<Invoice>(`/ui/quotes/${encodeURIComponent(quoteId)}/convert-to-invoice`, {});

export const convertQuoteToContract = (quoteId: string) =>
  api.post<Contract>(`/ui/quotes/${encodeURIComponent(quoteId)}/convert-to-contract`, {});

// ─── Contracts (QUO-004) ─────────────────────────────────────────────────────

export const listContracts = (opts?: {
  stage?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.stage) params["stage"] = opts.stage;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<ContractListResp>("/ui/contracts", params);
};

export const getContract = (contractId: string) =>
  api.get<Contract>(`/ui/contracts/${encodeURIComponent(contractId)}`);

export const createContract = (body: ContractCreateIn) =>
  api.post<Contract>("/ui/contracts", body);

export const patchContract = (contractId: string, body: ContractPatchIn) =>
  api.patch<Contract>(`/ui/contracts/${encodeURIComponent(contractId)}`, body);

export const transitionContractStage = (contractId: string, stage: ContractStage) =>
  api.post<Contract>(`/ui/contracts/${encodeURIComponent(contractId)}/stage`, { stage });
