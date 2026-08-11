import { api } from "@/api/client";

/**
 * Trader order-entry (`/me/*`) endpoints — the web mirror of the Android TradingApi.
 *
 * A prediction market is just a symbol traded through the same order book (price in
 * [0, face_value] = implied YES probability x face). Fields are the engine's raw snake_case
 * shapes; ack `status` is "ack" | "nak" | "killed" | "rejected". Auth (cookie + bearer + CSRF)
 * is handled by [api]. There is NO server-side list of working orders or fills history — callers
 * track their own from these acks + the exec-events drain (parity with Android).
 */

export type OrderSide = "buy" | "sell";
export type TimeInForce = "GTC" | "IOC" | "FOK" | "GTD";

export interface Fill {
  price?: number;
  qty?: number;
  ts_ns?: number;
  side?: string;
  aggressor?: string;
}

// ── Requests ─────────────────────────────────────────────────────────

export interface PlaceOrderRequest {
  symbolid: number;
  side: OrderSide;
  price: number;
  qty: number;
  clordid: string;
  market?: boolean;
  tif?: TimeInForce;
  post_only?: boolean;
  hidden?: boolean;
  aon?: boolean;
  display_qty?: number;
  min_qty?: number;
  expiry_ns?: number;
}

export interface AmendRequest {
  new_qty: number;
  new_price?: number;
  symbolid?: number;
}

export interface QuoteRequest {
  symbolid: number;
  bid_price: number;
  ask_price: number;
  bid_qty: number;
  ask_qty: number;
}

export interface AlgoRequest {
  algo_type: "stop" | "stop_limit" | "stop_market" | "take_profit";
  symbolid: number;
  side: OrderSide;
  qty: number;
  stop_price?: number;
  limit_price?: number;
}

export interface OtoRequest {
  symbolid: number;
  parent_side: OrderSide;
  parent_price: number;
  parent_qty: number;
  child_side: OrderSide;
  child_price: number;
  child_qty: number;
}

export interface OcoLeg {
  side: OrderSide;
  price: number;
  qty: number;
}

export interface FundingRequest {
  rate_bps: number;
  qty: number;
  is_borrow: boolean;
  duration_seconds?: number;
  symbolid?: number;
}

// ── Acks / reads ─────────────────────────────────────────────────────

export interface OrderAck {
  status?: string;
  type?: string;
  clordid?: string;
  orderid?: number;
  symbolid?: number;
  cancelled_qty?: number;
  fills?: Fill[];
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
}

export interface MarginAccount {
  available_balance?: number;
  balance?: number;
  reserved_margin?: number;
  num_positions?: number;
  pos_symbol_idx?: number;
  pos_qty?: number;
  pos_entry_price?: number;
  pos_liquidation_price?: number;
  pos_unrealized_pnl?: number;
  distress_level?: number;
  is_liquidating?: number;
  margin_mode?: number;
  mpid?: string;
  status?: string;
  type?: string;
}

export interface DepositAck {
  status?: string;
  new_balance?: number;
  available_balance?: number;
  asset?: number;
  detail?: string;
  error?: string;
}

export interface BulkCancelAck {
  status?: string;
  type?: string;
  cancelled_count?: number;
}

export interface QuoteAck {
  status?: string;
  type?: string;
  quote_id?: string;
  bid_orderid?: number;
  ask_orderid?: number;
  fills?: Fill[];
  reasoncode?: number;
  note?: string;
  detail?: string;
  error?: string;
}

export interface AlgoAck {
  status?: string;
  type?: string;
  algo_id?: number;
  clordid?: string;
  reasoncode?: number;
  detail?: string;
  error?: string;
  note?: string;
}

export interface OtoAck {
  status?: string;
  type?: string;
  oto_id?: number;
  parent_orderid?: number;
  parent_clordid?: string;
  child_clordid?: string;
  fills?: Fill[];
  reasoncode?: number;
  detail?: string;
  error?: string;
  note?: string;
}

export interface FundingAck {
  status?: string;
  type?: string;
  funding_id?: number;
  clordid?: string;
  reason?: number;
  reasoncode?: number;
  detail?: string;
  error?: string;
  note?: string;
}

export interface Trigger {
  algo_id?: number;
  oto_id?: number;
  clordid?: string;
  orderid?: number;
  symbolid?: number;
}

export interface ExecEvents {
  fills?: Fill[];
  triggered?: Trigger[];
  oto_triggered?: Trigger[];
}

/** Binary prediction-market state. `state` = "trading" | "resolved"; `outcome` 1 = YES. */
export interface PmState {
  symbolid?: number;
  is_binary?: boolean;
  state?: string;
  outcome?: number;
  face_value?: number;
  resolve_ts?: number;
  resolver_id?: string;
  status?: string;
  error?: string;
  detail?: string;
}

export interface SpotAsset {
  asset?: number;
  symbol?: string;
  balance?: number;
  available?: number;
}

export interface SpotBalance {
  balances?: SpotAsset[];
  mpid?: string;
}

// ── Calls ────────────────────────────────────────────────────────────

export const placeOrder = (body: PlaceOrderRequest) => api.post<OrderAck>("/me/orders", body);

export const amendOrder = (clordid: string, body: AmendRequest) =>
  api.patch<OrderAck>(`/me/orders/${encodeURIComponent(clordid)}`, body);

export const cancelOrder = (clordid: string, symbolId: number) =>
  api.del<OrderAck>(`/me/orders/${encodeURIComponent(clordid)}`, { symbolid: String(symbolId) });

export const bulkCancel = () => api.post<BulkCancelAck>("/me/bulk_cancel", {});

export const getMarginAccount = () => api.get<MarginAccount>("/me/margin_account");

export const marginDeposit = (amount: number) => api.post<DepositAck>("/me/margin_deposit", { amount });

export const placeQuote = (body: QuoteRequest) => api.post<QuoteAck>("/me/quote", body);

export const placeAlgo = (body: AlgoRequest) => api.post<AlgoAck>("/me/algo", body);

export const placeOto = (body: OtoRequest) => api.post<OtoAck>("/me/oto", body);

export const getExecEvents = () => api.get<ExecEvents>("/me/algo/events");

export const getPmState = (symbolId: number) =>
  api.get<PmState>("/me/pm_state", { symbolid: String(symbolId) });

// Staged surfaces (edge/config-blocked today; gated in the UI waves):
export const placeOco = (symbolid: number, legs: OcoLeg[]) =>
  api.post<OrderAck>("/me/oco", { symbolid, legs });

export const placeFunding = (body: FundingRequest) => api.post<FundingAck>("/me/funding_order", body);

export const getSpotBalance = () => api.get<SpotBalance>("/me/spot_balance");

export const spotDeposit = (asset: number, amount: number) =>
  api.post<DepositAck>("/me/spot_deposit", { asset, amount });

// ── Helpers ──────────────────────────────────────────────────────────

/** ack.status === "ack" */
export const isAck = (a: { status?: string } | null | undefined): boolean => a?.status === "ack";

/** Best human message off any ack (rejection reason / engine note). */
export const ackMessage = (
  a: { detail?: string; error?: string; note?: string; reason?: string | number; reasoncode?: number } | null | undefined,
): string | undefined => {
  if (!a) return undefined;
  if (a.detail) return a.detail;
  if (a.error) return a.error;
  if (a.note) return a.note;
  const code = a.reason ?? a.reasoncode;
  return code != null ? `rejected (code ${code})` : undefined;
};

/** Implied YES probability (0..1) for a prediction market at `price`. */
export const impliedYes = (price: number | null | undefined, faceValue: number | undefined): number | null => {
  if (!faceValue || faceValue <= 0 || price == null) return null;
  return Math.min(1, Math.max(0, price / faceValue));
};

/** Fraction of balance locked as margin (0..1). */
export const marginUsedFraction = (a: MarginAccount | undefined): number => {
  const bal = a?.balance ?? 0;
  const res = a?.reserved_margin ?? 0;
  return bal > 0 ? Math.min(1, Math.max(0, res / bal)) : 0;
};
