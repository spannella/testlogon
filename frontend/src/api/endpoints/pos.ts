import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz Point-of-Sale (POS) — endpoint wrappers + inline TS types.
// Mirrors app/routers/pos.py (LIVE) + app/models.py POS models.
// All amounts are integer cents.
// ─────────────────────────────────────────────────────────────────────────────

export interface RegisterConfig {
  register_id?: string | null;
  label: string;
  location_id: string;
  default_currency: string;
  created_at: number;
  updated_at: number;
  created_by?: string | null;
}

export interface RegisterCreateIn {
  label: string;
  location_id: string;
  default_currency?: string;
}

export type TenderKind = "cash" | "card" | "wallet";

export interface TenderOut {
  kind: string; // cash | card | wallet
  amount_cents: number;
  change_due_cents: number; // only meaningful for kind=cash
  payment_method_id?: string | null;
  card_ref?: string | null;
}

export interface RegisterSessionOut {
  session_id: string;
  register_id: string;
  cashier_sub: string;
  status: string; // open | closed
  opening_float_cents: number;
  closing_float_cents?: number | null;
  expected_cash_cents?: number | null;
  counted_cash_cents?: number | null;
  over_short_cents?: number | null; // signed: positive = over
  opened_at: number;
  closed_at?: number | null;
}

export interface PosTransactionOut {
  txn_id: string;
  session_id: string;
  cart_id?: string | null;
  order_id?: string | null;
  status: string; // draft | tendered | voided | refunded
  subtotal_cents: number;
  discount_cents: number;
  tax_cents: number;
  total_cents: number;
  tenders: TenderOut[];
  receipt_id?: string | null;
  created_at: number;
  updated_at: number;
}

export interface PosTxnDraftOut {
  txn_id: string;
  session_id: string;
  cashier_sub: string;
  status: string;
  cart_id: string;
  subtotal_cents: number;
  tax_cents: number;
  discount_cents: number;
  total_cents: number;
  created_at: number;
  updated_at: number;
}

/** Cart line item shape (from shoppingcart._item_from_item). */
export interface PosLineItem {
  sku: string;
  name: string;
  quantity: number;
  unit_price_cents: number;
  line_total_cents: number;
  updated_at?: number | null;
  image_url?: string;
  category_id?: string;
  item_id?: string;
}

/** Response from add/set/remove line item helpers. */
export interface PosLineMutationOut {
  txn_id: string;
  total_cents: number;
  item?: PosLineItem;
}

export interface OpenSessionIn {
  register_id: string;
  opening_float_cents?: number;
  idempotency_key?: string | null;
}

export interface CloseSessionIn {
  counted_cash_cents: number;
}

export interface PosBindTxnIn {
  correlation_id: string;
}

export interface PosAddLineItemIn {
  item_id?: string | null;
  category_id?: string | null;
  sku?: string | null;
  name?: string | null;
  unit_price_cents?: number | null;
  quantity?: number;
}

export interface PosSetLineQtyIn {
  quantity: number;
}

export interface PosCashTenderIn {
  amount_tendered_cents: number;
  idempotency_key: string;
}

export interface PosCardTenderIn {
  amount_tendered_cents: number;
  payment_method_id: string;
  idempotency_key: string;
  card_kind?: string | null;
  last4?: string | null;
}

export interface PosWalletTenderIn {
  amount_tendered_cents: number;
  idempotency_key: string;
}

export interface PosTxnVoidIn {
  reason: string;
}

export interface RefundTxnIn {
  txn_id: string;
  reason: string;
}

export interface ReceiptLinkOut {
  txn_id: string;
  receipt_path: string;
  receipt_url: string;
  generated_at: number;
}

export interface PosSessionReportOut {
  session_id: string;
  register_id: string;
  cashier_sub: string;
  status: string;
  opening_float_cents: number;
  closing_float_cents?: number | null;
  expected_cash_cents?: number | null;
  counted_cash_cents?: number | null;
  over_short_cents?: number | null;
  opened_at: number;
  closed_at?: number | null;
  transaction_count: number;
  total_sales_cents: number;
  total_cash_tendered_cents: number;
  total_change_given_cents: number;
}

// ── X/Z till-summary report models (POS-010) ──────────────────────────────────

export interface TenderBreakdownItem {
  kind: string; // cash | card | wallet
  gross_cents: number;
  refund_cents: number;
  net_cents: number;
  transaction_count: number;
}

export interface SessionReportCashSection {
  opening_float_cents: number;
  cash_in_cents: number;
  change_out_cents: number;
  expected_cash_cents: number;
  counted_cash_cents?: number | null;
  over_short_cents?: number | null;
}

export interface SessionReportOut {
  report_kind: string; // "x" | "z"
  session_id: string;
  register_id: string;
  cashier_sub: string;
  opened_at: number;
  closed_at?: number | null;
  generated_at: number;
  z_report_printed_at?: number | null;
  gross_sales_cents: number;
  discount_cents: number;
  tax_cents: number;
  net_sales_cents: number;
  refund_total_cents: number;
  void_count: number;
  transaction_count: number;
  tender_breakdown: TenderBreakdownItem[];
  cash: SessionReportCashSection;
}

// ─── Registers ────────────────────────────────────────────────────────────────

export const createRegister = (body: RegisterCreateIn) =>
  api.post<RegisterConfig>("/ui/pos/registers", body);

export const getRegister = (registerId: string) =>
  api.get<RegisterConfig>(`/ui/pos/registers/${registerId}`);

// ─── Sessions ───────────────────────────────────────────────────────────────

export const openSession = (body: OpenSessionIn) =>
  api.post<RegisterSessionOut>("/ui/pos/sessions", body);

export const getOpenSession = (registerId: string) =>
  api.get<RegisterSessionOut>(`/ui/pos/registers/${registerId}/open-session`);

export const getSession = (sessionId: string) =>
  api.get<RegisterSessionOut>(`/ui/pos/sessions/${sessionId}`);

export const closeSession = (sessionId: string, body: CloseSessionIn) =>
  api.post<RegisterSessionOut>(`/ui/pos/sessions/${sessionId}/close`, body);

// ─── Session reports ──────────────────────────────────────────────────────────

export const getSessionReport = (sessionId: string) =>
  api.get<PosSessionReportOut>(`/ui/pos/sessions/${sessionId}/report`);

export const getXReport = (sessionId: string) =>
  api.get<SessionReportOut>(`/ui/pos/sessions/${sessionId}/report/x`);

export const getZReport = (sessionId: string) =>
  api.get<SessionReportOut>(`/ui/pos/sessions/${sessionId}/report/z`);

export const listSessionTxns = (sessionId: string) =>
  api.get<PosTransactionOut[]>(`/ui/pos/sessions/${sessionId}/transactions`);

// ─── Transaction drafts (cart binding + line items) ───────────────────────────

export const bindTxn = (sessionId: string, body: PosBindTxnIn) =>
  api.post<PosTxnDraftOut>(`/ui/pos/sessions/${sessionId}/txns`, body);

export const getTxn = (txnId: string) =>
  api.get<PosTxnDraftOut>(`/ui/pos/txns/${txnId}`);

export const addLineItem = (txnId: string, body: PosAddLineItemIn) =>
  api.post<PosLineMutationOut>(`/ui/pos/txns/${txnId}/lines`, body);

export const listTxnLines = (txnId: string) =>
  api.get<PosLineItem[]>(`/ui/pos/txns/${txnId}/lines`);

export const setLineQty = (txnId: string, sku: string, body: PosSetLineQtyIn) =>
  api.patch<PosLineMutationOut>(`/ui/pos/txns/${txnId}/lines/${encodeURIComponent(sku)}`, body);

export const removeLineItem = (txnId: string, sku: string, decrement = 1) =>
  api.del<PosLineMutationOut>(`/ui/pos/txns/${txnId}/lines/${encodeURIComponent(sku)}`, {
    decrement: String(decrement),
  });

// ─── Tender / void / refund ───────────────────────────────────────────────────

export const tenderCash = (sessionId: string, txnId: string, body: PosCashTenderIn) =>
  api.post<PosTransactionOut>(
    `/ui/pos/sessions/${sessionId}/transactions/${txnId}/tender-cash`,
    body,
  );

export const tenderCard = (sessionId: string, txnId: string, body: PosCardTenderIn) =>
  api.post<PosTransactionOut>(
    `/ui/pos/sessions/${sessionId}/transactions/${txnId}/tender-card`,
    body,
  );

export const tenderWallet = (sessionId: string, txnId: string, body: PosWalletTenderIn) =>
  api.post<PosTransactionOut>(
    `/ui/pos/sessions/${sessionId}/transactions/${txnId}/tender-wallet`,
    body,
  );

export const voidTxn = (txnId: string, body: PosTxnVoidIn) =>
  api.post<PosTransactionOut>(`/ui/pos/txns/${txnId}/void`, body);

export const refundTxn = (txnId: string, body: RefundTxnIn) =>
  api.post<PosTransactionOut>(`/ui/pos/txns/${txnId}/refund`, body);

// ─── Receipt ──────────────────────────────────────────────────────────────────

export const getReceiptLink = (txnId: string) =>
  api.get<ReceiptLinkOut>(`/ui/pos/txns/${txnId}/receipt`);

/** Absolute path for the receipt PDF (download / preview). */
export const receiptPdfUrl = (txnId: string) =>
  `/ui/pos/txns/${txnId}/receipt/pdf`;

// ─── Currency helper ──────────────────────────────────────────────────────────

export function fmtCents(cents: number | null | undefined, currency = "USD"): string {
  const v = (cents ?? 0) / 100;
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(v);
  } catch {
    return `$${v.toFixed(2)}`;
  }
}
