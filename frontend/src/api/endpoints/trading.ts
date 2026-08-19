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

export interface MarginConfigRequest {
  symbolid: number;
  initial_margin_bps: number;
  maintenance_margin_bps: number;
  liquidation_fee_bps: number;
  hourly_borrow_rate_bps: number;
  maker_fee_bps: number;
  taker_fee_bps: number;
  max_position_qty: number;
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

export interface MarginConfigAck {
  status?: "ack" | "rejected" | string;
  type?: string;
  symbolid?: number;
  /** 0 = applied; non-zero = rejected. */
  result?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
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

/** Admin-only: set per-symbol margin / fee parameters on the engine. */
export const marginConfig = (body: MarginConfigRequest) =>
  api.post<MarginConfigAck>("/me/margin_config", body);

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

// ── Exchange account feeds (`/me/fills/fees`, `/me/liquidations`, `/me/funding/payments`) ──
// REAL per-caller feeds served by the exchange edge. Every field (price/qty/fee/
// pnl/payment/mark) is an int64 engine tick — scale/format with the markets
// `formatPrice`/`formatQty` scaler. `ts` is a timestamp (seconds OR ms — detect).
// `symbolid` maps to a symbol via the /md/symbols catalog. All THREE routes MAY
// 404 until the edge deploys — callers must degrade gracefully (retry:false).

export type Liquidity = "maker" | "taker";

/** One executed fill enriched with its REAL engine-charged fee. */
export interface FillFee {
  symbolid: number;
  /** int64 engine tick. */
  price: number;
  /** int64 engine tick. */
  qty: number;
  side: OrderSide;
  liquidity: Liquidity;
  /** int64 engine tick — the fee actually charged (NOT an estimate). */
  fee: number;
  /** Asset id the fee was charged in. */
  fee_asset: number;
  /** Timestamp (seconds or ms — detect). */
  ts: number;
}

export interface FillsFeesResult {
  status: string;
  type: "fills";
  mpid?: string;
  count: number;
  fills: FillFee[];
}

/** One forced-liquidation event on the caller's account. */
export interface Liquidation {
  symbolid: number;
  /** int64 engine tick (position size closed). */
  qty: number;
  /** int64 engine tick. */
  mark_price: number;
  /** int64 engine tick (signed — green when >0, red when <0). */
  realized_pnl: number;
  /** int64 engine tick — the liquidation fee. */
  fee: number;
  /** Timestamp (seconds or ms — detect). */
  ts: number;
}

export interface LiquidationsResult {
  status: string;
  type: "liquidations";
  mpid?: string;
  count: number;
  liquidations: Liquidation[];
}

/** One periodic funding payment on a perpetual position. */
export interface FundingPayment {
  symbolid: number;
  /** Funding rate in basis points. */
  funding_rate_bps: number;
  /** int64 engine tick. */
  mark_price: number;
  /** int64 engine tick (signed position size). */
  position_qty: number;
  /** int64 engine tick, SIGNED — negative = paid, positive = received. */
  payment: number;
  /** Convenience flag: true when this account received the payment. */
  received: boolean;
  /** Timestamp (seconds or ms — detect). */
  ts: number;
}

export interface FundingPaymentsResult {
  status: string;
  type: "funding";
  mpid?: string;
  count: number;
  funding: FundingPayment[];
}

/**
 * Recent fills with the REAL engine-charged fee + maker/taker flag per fill.
 * Replaces the former client-side estimate. 404s until the edge deploys.
 */
export const getFillsFees = () => api.get<FillsFeesResult>("/me/fills/fees");

/** The caller's forced-liquidation events (newest first). 404s until edge deploys. */
export const getLiquidations = () => api.get<LiquidationsResult>("/me/liquidations");

/** The caller's periodic funding payments (newest first). 404s until edge deploys. */
export const getFundingPayments = () =>
  api.get<FundingPaymentsResult>("/me/funding/payments");


// ── Admin engine-config surfaces (`/me/*`) ───────────────────────────
// Six admin-only POST routes that tune the matching engine per-symbol. Each
// returns an engine ack `{ status, ... }` where status is "ack" | "rejected"
// (or carries a `result`/computed field). NOT deployed to every backend — the
// route MAY 404; callers degrade gracefully (surface the failure inline, no crash).

/** Generic admin engine-config ack. `status` "ack" | "rejected"; extra fields per-route. */
export interface EngineConfigAck {
  status?: "ack" | "rejected" | string;
  type?: string;
  symbolid?: number;
  /** 0 = applied; non-zero = rejected (mirrors MarginConfigAck). */
  result?: number;
  /** Recomputed funding rate returned by /me/spot_index. */
  funding_rate_bps?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
}

/** Per-symbol matching algorithm. algo 0 = price-time (default); 1+ = pro-rata / specialist. */
export interface MatchingAlgoRequest {
  symbolid: number;
  algo: number;
  specialist_mpid?: string;
  specialist_pct?: number;
}

/** Two-leg spread definition. leg1_ratio defaults 1, leg2_ratio defaults -1. */
export interface SpreadConfigRequest {
  spread_symbolid: number;
  leg1: number;
  leg2: number;
  leg1_ratio?: number;
  leg2_ratio?: number;
}

/** Per-symbol trading limits / bands / circuit breaker. */
export interface TradingParamsRequest {
  symbolid: number;
  max_qty?: number;
  max_notional?: number;
  price_band_pct?: number;
  circuit_breaker_pct?: number;
  min_block_size?: number;
}

/** Per-MPID notional kill switch over a rolling window. */
export interface RiskConfigRequest {
  max_notional: number;
  window_seconds: number;
  mpid?: string;
}

/** Sets the perp funding index; engine recomputes funding_rate_bps (returned in ack). */
export interface SpotIndexRequest {
  symbolid: number;
  spot_index_price: number;
}

/** Marks a symbol spot-enforced with a base/quote asset pair. */
export interface SpotConfigRequest {
  symbolid: number;
  base_asset: number;
  quote_asset: number;
}

/** Admin-only: set the per-symbol matching algorithm. */
export const setMatchingAlgo = (body: MatchingAlgoRequest) =>
  api.post<EngineConfigAck>("/me/matching_algo", body);

/** Admin-only: define a two-leg spread symbol. */
export const setSpreadConfig = (body: SpreadConfigRequest) =>
  api.post<EngineConfigAck>("/me/spread_config", body);

/** Admin-only: set per-symbol trading limits / price bands / circuit breaker. */
export const setTradingParams = (body: TradingParamsRequest) =>
  api.post<EngineConfigAck>("/me/trading_params", body);

/** Admin-only: set a per-MPID notional kill switch over a rolling window. */
export const setRiskConfig = (body: RiskConfigRequest) =>
  api.post<EngineConfigAck>("/me/risk_config", body);

/** Admin-only: set the perp funding index; ack echoes the recomputed funding_rate_bps. */
export const setSpotIndex = (body: SpotIndexRequest) =>
  api.post<EngineConfigAck>("/me/spot_index", body);

/** Admin-only: mark a symbol spot-enforced with a base/quote asset pair. */
export const setSpotConfig = (body: SpotConfigRequest) =>
  api.post<EngineConfigAck>("/me/spot_config", body);


// ── Prediction-market admin surfaces (`/me/pm_*`) ────────────────────
// Admin-only routes that create/configure & resolve prediction markets. A binary
// PM trades YES shares in (0, face_value); a YES share pays face_value on YES
// resolution else 0 (implied probability = price / face_value). A categorical
// market is N linked binaries sharing a group_id where exactly one wins. Each
// route returns an engine ack `{ status, ... }` ("ack" | "rejected"); pm_resolve
// / pm_group_resolve return 403 when the caller is not the designated resolver.
// NOT deployed to every backend — the route MAY 404; callers degrade gracefully.

/** Create/config a binary prediction market. `face_value` must be > 1. */
export interface PmConfigRequest {
  symbolid: number;
  face_value: number;
  resolver?: string;
}

/** Create/config a categorical (group of linked binary outcomes). */
export interface PmGroupConfigRequest {
  group_id: number;
  outcomes: number[];
  face_value: number;
  resolver?: string;
}

/** Settle a binary PM: "yes" pays face, "no" pays 0. */
export interface PmResolveRequest {
  symbolid: number;
  outcome: "yes" | "no";
  source?: string;
}

/** Resolve a categorical: winning_symbolid pays face, the rest pay 0. */
export interface PmGroupResolveRequest {
  group_id: number;
  winning_symbolid: number;
  source?: string;
}

/** Generic PM admin ack. `status` "ack" | "rejected"; 403 surfaces via detail/error. */
export interface PmAdminAck {
  status?: "ack" | "rejected" | string;
  type?: string;
  symbolid?: number;
  group_id?: number;
  outcome?: string;
  /** 0 = applied; non-zero = rejected (mirrors EngineConfigAck). */
  result?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
}

/** One entry in the resolution audit log. */
export interface PmResolution {
  symbolid?: number;
  group_id?: number;
  outcome?: string;
  winning_symbolid?: number;
  resolver_id?: string;
  ts?: number;
  source?: string;
}

/** The resolution audit log (array). 404s until the PM surface deploys. */
export interface PmResolutionsResult {
  status?: string;
  type?: string;
  resolutions?: PmResolution[];
}

/** Admin-only: create/config a binary prediction market. */
export const pmConfig = (body: PmConfigRequest) => api.post<PmAdminAck>("/me/pm_config", body);

/** Admin-only: create/config a categorical (N linked binary outcomes). */
export const pmGroupConfig = (body: PmGroupConfigRequest) =>
  api.post<PmAdminAck>("/me/pm_group_config", body);

/** Admin-only: settle a binary PM (403 if not the designated resolver). */
export const pmResolve = (body: PmResolveRequest) => api.post<PmAdminAck>("/me/pm_resolve", body);

/** Admin-only: resolve a categorical PM (403 if not the designated resolver). */
export const pmGroupResolve = (body: PmGroupResolveRequest) =>
  api.post<PmAdminAck>("/me/pm_group_resolve", body);

/** The prediction-market resolution audit log. 404s until the PM surface deploys. */
export const getPmResolutions = () => api.get<PmResolutionsResult>("/me/pm_resolutions");


// ── Staking & Auctions trader surfaces (`/me/*`) ─────────────────────
// Two PEER trader mechanisms on the matching engine (NOT admin): a collateral
// staking market and distressed-position auctions. Each POST returns an engine
// ack `{ status, ... }` that surfaces the created id (`request_id` / `auction_id`)
// when present. There is NO server-side list/GET of open stake requests or open
// auctions — callers can create + act-by-id but cannot browse open items.
// Amounts/prices/qty are int64 engine ticks. Routes are NOT deployed to prod →
// they MAY 404; callers degrade gracefully (surface the failure inline, no crash).

/** Create an outstanding stake request (peer collateral-staking market). */
export interface StakeRequestRequest {
  symbolid?: number;
  min_collateral: number;
  max_stake_pct: number;
  lockup_seconds: number;
  duration_seconds: number;
}

/** Offer collateral to fill an outstanding stake request by id. */
export interface StakeOfferRequest {
  request_id: number;
  collateral_amount: number;
  stake_pct: number;
}

/** Create an auction of a (distressed) position qty. */
export interface AuctionRequestRequest {
  symbolid?: number;
  qty: number;
  reserve_price?: number;
  duration_seconds?: number;
}

/** Bid into an open auction by id. */
export interface AuctionBidRequest {
  auction_id: number;
  price: number;
  qty: number;
}

/** Ack for a created stake request — surfaces `request_id` when present. */
export interface StakeRequestAck {
  status?: string;
  type?: string;
  request_id?: number;
  symbolid?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
}

/** Ack for an offer on a stake request. */
export interface StakeOfferAck {
  status?: string;
  type?: string;
  request_id?: number;
  offer_id?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
}

/** Ack for a created auction — surfaces `auction_id` when present. */
export interface AuctionRequestAck {
  status?: string;
  type?: string;
  auction_id?: number;
  symbolid?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
}

/** Ack for a bid into an auction. */
export interface AuctionBidAck {
  status?: string;
  type?: string;
  auction_id?: number;
  bid_id?: number;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
  reasoncode?: number;
}

/** Trader: create an outstanding stake request. 404s until the surface deploys. */
export const stakeRequest = (body: StakeRequestRequest) =>
  api.post<StakeRequestAck>("/me/stake_request", body);

/** Trader: offer collateral to fill an outstanding stake request by id. */
export const stakeOffer = (body: StakeOfferRequest) =>
  api.post<StakeOfferAck>("/me/stake_offer", body);

/** Trader: create an auction of a position qty. 404s until the surface deploys. */
export const auctionRequest = (body: AuctionRequestRequest) =>
  api.post<AuctionRequestAck>("/me/auction_request", body);

/** Trader: bid into an open auction by id. */
export const auctionBid = (body: AuctionBidRequest) =>
  api.post<AuctionBidAck>("/me/auction_bid", body);
