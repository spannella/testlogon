import { api } from "@/api/client";
import type {
  PurchaseTransactionSummary,
  PurchaseTransactionInfo,
  PurchaseShipping,
  CarrierTrackingView,
} from "@/api/types";

// ─── List & Search ──────────────────────────────────────────────

export const listTransactions = (params?: { limit?: number; status?: string }) => {
  const qs: Record<string, string> = {};
  if (params?.limit) qs.limit = String(params.limit);
  if (params?.status) qs.status = params.status;
  return api.get<PurchaseTransactionSummary[]>(
    "/ui/purchase-history/transactions",
    Object.keys(qs).length > 0 ? qs : undefined,
  );
};

export const searchTransactions = (q: string, limit?: number) => {
  const qs: Record<string, string> = { q };
  if (limit) qs.limit = String(limit);
  return api.get<PurchaseTransactionSummary[]>(
    "/ui/purchase-history/transactions/search",
    qs,
  );
};

// ─── Detail ─────────────────────────────────────────────────────

export const getTransaction = (txnId: string) =>
  api.get<PurchaseTransactionInfo>(`/ui/purchase-history/transactions/${txnId}`);

// ─── Actions ────────────────────────────────────────────────────

export const updateShipping = (txnId: string, shipping: PurchaseShipping) =>
  api.put<PurchaseTransactionInfo>(
    `/ui/purchase-history/transactions/${txnId}/shipping`,
    { shipping },
  );

export const markComplete = (txnId: string, note?: string) =>
  api.post<PurchaseTransactionInfo>(
    `/ui/purchase-history/transactions/${txnId}/complete`,
    { note },
  );

export const markReverted = (txnId: string, reason?: string) =>
  api.post<PurchaseTransactionInfo>(
    `/ui/purchase-history/transactions/${txnId}/revert`,
    { reason },
  );

export const requestCancel = (txnId: string, reason?: string) =>
  api.post<PurchaseTransactionInfo>(
    `/ui/purchase-history/transactions/${txnId}/cancel/request`,
    { reason },
  );

export const respondCancel = (txnId: string, decision: string, note?: string) =>
  api.post<PurchaseTransactionInfo>(
    `/ui/purchase-history/transactions/${txnId}/cancel/respond`,
    { decision, note },
  );

// ─── Events & Receipt ───────────────────────────────────────────

export interface TransactionEvent {
  event_name?: string;
  event_type?: string;
  created_at?: number;
  ts?: number;
  detail?: string;
  [key: string]: unknown;
}

export const listEvents = (txnId: string, limit?: number) => {
  const qs: Record<string, string> = {};
  if (limit) qs.limit = String(limit);
  return api.get<{ txn_id: string; events: TransactionEvent[] }>(
    `/ui/purchase-history/transactions/${txnId}/events`,
    Object.keys(qs).length > 0 ? qs : undefined,
  );
};

export interface ReceiptLink {
  txn_id: string;
  receipt_path: string;
  receipt_url: string;
  generated_at: number;
}

export const getReceipt = (txnId: string) =>
  api.get<ReceiptLink>(`/ui/purchase-history/transactions/${txnId}/receipt`);

// ─── Shipment Tracking ────────────────────────────────

/**
 * Read the constructed shipment-tracking view (carrier, tracking URL/number,
 * status, carrier scan events). Returns an honest-empty payload (null fields)
 * when the order has no carrier/tracking number yet.
 */
export const getTransactionTracking = (txnId: string) =>
  api.get<CarrierTrackingView>(
    `/ui/purchase-history/transactions/${txnId}/tracking`,
  );
