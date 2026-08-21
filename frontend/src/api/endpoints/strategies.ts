import { api } from "@/api/client";

/**
 * USER-CREATED STRATEGIES / BASKETS surface (`/me/strategies/*`).
 *
 * A creator defines a STRATEGY: a basket of target weights (from a static
 * ETF-like allocation through a simple rule set) that others can PAPER-TRADE,
 * BACKTEST, then INVEST real capital into. The creator sets a minimum
 * investment, a maximum total AUM (capacity cap), a redemption / profit-taking
 * policy, and a DUAL FEE — a management fee on AUM (`mgmt_fee_bps`, annual) AND
 * a performance fee on profit (`perf_fee_bps`, gated by a high-water mark).
 *
 * ASSUMPTION (labelled in-UI so it can be flipped): the fund is a POOLED FUND
 * WITH NAV UNITS — investors subscribe/redeem at NAV and own units; it is NOT
 * copy / replication trading.
 *
 * CONVENTIONS (locked): every monetary amount is INTEGER CENTS; every `_bps`
 * field is BASIS POINTS (100% = 10_000). NONE of these endpoints exist on the
 * backend yet — every GET degrades on 404/absent to an empty-but-honest state
 * (callers use `retry:false` + render a "pending backend" note), and every
 * mutation surfaces a clear error toast on 404 (never silently "succeeds").
 */

export type StrategyKind = "basket" | "rule";
export type StrategyStatus = "draft" | "paper" | "published" | "closed";
export type RebalanceCadence = "none" | "daily" | "weekly" | "monthly" | "threshold";
export type RedemptionType = "instant" | "notice";

/** One basket leg: a symbol and its target weight in basis points. */
export interface StrategyLeg {
  symbol_id: number;
  weight_bps: number;
}

/** The redemption / profit-taking policy the creator sets. */
export interface RedemptionPolicy {
  type: RedemptionType;
  /** Notice period before a redemption settles (notice type). */
  notice_days?: number;
  /** Initial lock-up before any redemption is allowed. */
  lockup_days?: number;
}

/** A user-created investable strategy / basket fund. */
export interface Strategy {
  strategy_id: string;
  creator_sub: string;
  name: string;
  description: string;
  kind: StrategyKind;
  status: StrategyStatus;
  legs: StrategyLeg[];
  rebalance: RebalanceCadence;
  /** Rebalance trigger drift (threshold cadence), in bps. */
  threshold_bps?: number;
  min_investment_cents: number;
  /** Capacity cap; 0 (or absent) = uncapped. */
  max_aum_cents: number;
  mgmt_fee_bps: number;
  perf_fee_bps: number;
  high_water_mark: boolean;
  redemption: RedemptionPolicy;
  created_ts: number;
  /** NAV per unit in cents (present once the fund is live). */
  nav_per_unit?: number;
  /** Assets under management in cents. */
  aum_cents?: number;
  investor_count?: number;
  /** Return since inception, in bps. */
  inception_return_bps?: number;
}

export interface StrategiesResult {
  strategies: Strategy[];
}

/** Live NAV snapshot for a published fund. */
export interface StrategyNav {
  nav_per_unit: number;
  aum_cents: number;
  units_outstanding: number;
  /** Snapshot timestamp (seconds). */
  as_of: number;
}

/** One holding row in the fund's current composition. */
export interface HoldingLeg {
  symbol_id: number;
  weight_bps: number;
  value_cents: number;
}

export interface StrategyHoldings {
  legs: HoldingLeg[];
}

/** An investor's position in a strategy. */
export interface InvestorPosition {
  strategy_id: string;
  units: number;
  nav_per_unit: number;
  invested_cents: number;
  current_value_cents: number;
  unrealized_pnl_cents: number;
  fees_paid_cents: number;
  high_water_mark: number;
}

/** The creator's fee-accrual snapshot for the fund. */
export interface StrategyFees {
  mgmt_accrued_cents: number;
  perf_accrued_cents: number;
  high_water_mark: number;
}

/** Result of an invest (subscribe) action. */
export interface InvestResult {
  units: number;
  nav_per_unit: number;
}

/** Result of a redeem action. */
export interface RedeemResult {
  proceeds_cents: number;
}

// -- Requests ---------------------------------------------------------

export interface CreateStrategyRequest {
  name: string;
  description: string;
  kind: StrategyKind;
  legs: StrategyLeg[];
  rebalance: RebalanceCadence;
  threshold_bps?: number;
  min_investment_cents: number;
  max_aum_cents: number;
  mgmt_fee_bps: number;
  perf_fee_bps: number;
  high_water_mark: boolean;
  redemption: RedemptionPolicy;
}

export type UpdateStrategyRequest = CreateStrategyRequest;

export interface InvestRequest {
  amount_cents: number;
}

export interface RedeemRequest {
  units: number;
}

/** Generic mutation ack; carries a message on the failure paths. */
export interface StrategyAck {
  status?: string;
  strategy_id?: string;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
}

// -- Calls (all 404 until the backend ships — callers degrade) --------

/** Create a draft strategy. */
export const createStrategy = (body: CreateStrategyRequest) =>
  api.post<Strategy>("/me/strategies", body);

/** Strategies I created. */
export const getMyStrategies = () => api.get<StrategiesResult>("/me/strategies");

/** Published strategies to browse. */
export const getStrategyMarket = () => api.get<StrategiesResult>("/me/strategies/market");

export const getStrategy = (id: string) =>
  api.get<Strategy>(`/me/strategies/${encodeURIComponent(id)}`);

/** Edit a draft strategy (creator only). */
export const updateStrategy = (id: string, body: UpdateStrategyRequest) =>
  api.put<Strategy>(`/me/strategies/${encodeURIComponent(id)}`, body);

/** Publish a strategy (opens it for investment). */
export const publishStrategy = (id: string) =>
  api.post<Strategy>(`/me/strategies/${encodeURIComponent(id)}/publish`, {});

export const getStrategyNav = (id: string) =>
  api.get<StrategyNav>(`/me/strategies/${encodeURIComponent(id)}/nav`);

export const getStrategyHoldings = (id: string) =>
  api.get<StrategyHoldings>(`/me/strategies/${encodeURIComponent(id)}/holdings`);

/** Subscribe real capital at NAV. */
export const investStrategy = (id: string, body: InvestRequest) =>
  api.post<InvestResult>(`/me/strategies/${encodeURIComponent(id)}/invest`, body);

/** Redeem units at NAV (respecting the redemption policy). */
export const redeemStrategy = (id: string, body: RedeemRequest) =>
  api.post<RedeemResult>(`/me/strategies/${encodeURIComponent(id)}/redeem`, body);

export const getStrategyPosition = (id: string) =>
  api.get<InvestorPosition>(`/me/strategies/${encodeURIComponent(id)}/position`);

export const getStrategyFees = (id: string) =>
  api.get<StrategyFees>(`/me/strategies/${encodeURIComponent(id)}/fees`);

// -- Helpers ----------------------------------------------------------

/** Best human message off any strategy ack (error / detail / reject reason). */
export const strategyAckMessage = (a: StrategyAck | null | undefined): string | undefined => {
  if (!a) return undefined;
  if (a.detail) return a.detail;
  if (a.error) return a.error;
  if (a.note) return a.note;
  return a.reason != null ? `rejected (${a.reason})` : undefined;
};
