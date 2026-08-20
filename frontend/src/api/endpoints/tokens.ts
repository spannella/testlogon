import { api } from "@/api/client";

/**
 * CREATOR REVENUE-SHARE TOKEN surface (`/me/tokens/*`).
 *
 * A content-selling creator tokenizes their revenue share into a tradeable coin:
 *  - MINT: create a token, hold 100% of supply, pay a $100 creation fee. The
 *    token is a REAL revenue-share claim — holders receive PRO-RATA distributions
 *    of `revenue_share_bps` of the creator's ongoing content revenue.
 *  - LIST (IPO): sell N% via a single-clearing-price sealed-bid auction (one
 *    clearing price, all fills at that price); after clearing it trades on a
 *    continuous book (that book plugs into the existing trade surfaces later).
 *  - UPKEEP: $100/month to keep the book tradeable, charged to holders pro-rata
 *    by holding as a SHORTFALL top-up: amount_due = max(0, $100 - fees_this_month).
 *    Non-payment -> book frozen (reversible on payment).
 *
 * CONVENTIONS: every monetary amount is INTEGER CENTS; every `_bps` field is
 * BASIS POINTS (100% = 10_000). NONE of these endpoints exist on the backend
 * yet — every GET degrades on 404/absent to an empty-but-honest state (callers
 * use `retry:false` + render a "pending backend" note), and every mutation
 * surfaces a clear error toast on 404 (never silently "succeeds").
 */

export type TokenStatus = "draft" | "minted" | "listed" | "frozen" | "delisted";
export type AuctionStatus = "open" | "cleared" | "cancelled";
export type UpkeepStatus = "covered" | "due" | "paid" | "delinquent" | "frozen";

/** A creator revenue-share token. */
export interface Token {
  token_id: string;
  /** Continuous-book symbol id, once listed (plugs into the trade surfaces). */
  symbol_id?: number;
  creator_sub: string;
  name: string;
  ticker: string;
  /** Total token supply (whole tokens). */
  total_supply: number;
  /** The revenue-share claim, in basis points of the creator's content revenue. */
  revenue_share_bps: number;
  status: TokenStatus;
  created_ts: number;
  /** % of supply offered in the IPO, in bps (present once listing opens). */
  offered_pct_bps?: number;
  /** Uniform IPO clearing price in cents (present once the auction cleared). */
  clearing_price?: number;
}

export interface TokensResult {
  tokens: Token[];
}

/** One holder row in a token cap table. */
export interface CapTableHolder {
  sub: string;
  qty: number;
  pct_bps: number;
}

export interface CapTable {
  token_id: string;
  /** Creator retained % in bps. */
  creator_pct_bps: number;
  holders: CapTableHolder[];
}

/** One sealed IPO bid. */
export interface AuctionBid {
  sub: string;
  qty: number;
  /** Limit price in cents. */
  limit_price: number;
}

/** The single-clearing-price IPO auction. */
export interface TokenAuction {
  auction_id: string;
  token_id: string;
  /** % of supply offered, in bps. */
  offered_pct_bps: number;
  /** Reserve (floor) clearing price in cents. */
  reserve_price: number;
  status: AuctionStatus;
  /** Uniform clearing price in cents (present once cleared). */
  clearing_price?: number;
  /** Total qty filled at the clearing price (present once cleared). */
  filled_qty?: number;
  /** Auction close timestamp (seconds). */
  close_ts: number;
  bids?: AuctionBid[];
}

/** One pro-rata revenue distribution to holders. */
export interface Distribution {
  ts: number;
  /** Total distributed this event, in cents. */
  total_amount: number;
  /** Per-token amount, in cents. */
  per_token_amount: number;
  source: string;
}

export interface RevenueSummary {
  token_id: string;
  my_qty: number;
  my_pct_bps: number;
  /** My unclaimed distribution balance, in cents. */
  my_claimable: number;
  distributions: Distribution[];
}

export interface UpkeepSummary {
  token_id: string;
  /** e.g. "2026-08". */
  month: string;
  /** Trading fees the book generated this month, in cents. */
  fees_generated: number;
  /** The flat monthly threshold, in cents (server-authoritative; $100 today). */
  threshold: number;
  /** Shortfall bill for the book this month = max(0, threshold - fees), in cents. */
  amount_due: number;
  /** MY pro-rata slice of `amount_due`, in cents. */
  my_share: number;
  status: UpkeepStatus;
}

/** Generic mutation ack. `status` "ok"/"ack" on success; carries a message otherwise. */
export interface TokenAck {
  status?: string;
  token_id?: string;
  auction_id?: string;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
}

// ── Requests ─────────────────────────────────────────────────────────

export interface MintTokenRequest {
  name: string;
  ticker: string;
  total_supply: number;
  revenue_share_bps: number;
}

export interface ListTokenRequest {
  /** % of supply to offer, in bps. */
  offered_pct_bps: number;
  /** Reserve (floor) price in cents. */
  reserve_price: number;
  /** Auction close timestamp (seconds). */
  close_ts: number;
}

export interface PlaceBidRequest {
  qty: number;
  /** Limit price in cents. */
  limit_price: number;
}

// ── Calls (all 404 until the backend ships — callers degrade gracefully) ──

/** Mint a new token (server charges the $100 creation fee). */
export const mintToken = (body: MintTokenRequest) => api.post<Token>("/me/tokens", body);

/** Tokens I issued. */
export const getMyTokens = () => api.get<TokensResult>("/me/tokens");

/** All listed creator tokens to browse. */
export const getTokenMarket = () => api.get<TokensResult>("/me/tokens/market");

export const getToken = (id: string) => api.get<Token>(`/me/tokens/${encodeURIComponent(id)}`);

export const getCapTable = (id: string) =>
  api.get<CapTable>(`/me/tokens/${encodeURIComponent(id)}/captable`);

/** Open the IPO (issuer only). */
export const listToken = (id: string, body: ListTokenRequest) =>
  api.post<TokenAuction>(`/me/tokens/${encodeURIComponent(id)}/list`, body);

export const getAuction = (id: string) =>
  api.get<TokenAuction>(`/me/tokens/${encodeURIComponent(id)}/auction`);

/** Place a sealed IPO bid (non-issuers). */
export const placeAuctionBid = (id: string, body: PlaceBidRequest) =>
  api.post<TokenAck>(`/me/tokens/${encodeURIComponent(id)}/auction/bid`, body);

/** Trigger clearing (issuer only). */
export const clearAuction = (id: string) =>
  api.post<TokenAuction>(`/me/tokens/${encodeURIComponent(id)}/auction/clear`, {});

export const getRevenue = (id: string) =>
  api.get<RevenueSummary>(`/me/tokens/${encodeURIComponent(id)}/revenue`);

/** Claim my accrued pro-rata distributions. */
export const claimRevenue = (id: string) =>
  api.post<TokenAck>(`/me/tokens/${encodeURIComponent(id)}/revenue/claim`, {});

export const getUpkeep = (id: string) =>
  api.get<UpkeepSummary>(`/me/tokens/${encodeURIComponent(id)}/upkeep`);

/** Pay my pro-rata upkeep share (un-freezes a frozen book). */
export const payUpkeep = (id: string) =>
  api.post<TokenAck>(`/me/tokens/${encodeURIComponent(id)}/upkeep/pay`, {});

// ── Helpers ──────────────────────────────────────────────────────────

/** Best human message off any token ack (error / detail / reject reason). */
export const tokenAckMessage = (a: TokenAck | null | undefined): string | undefined => {
  if (!a) return undefined;
  if (a.detail) return a.detail;
  if (a.error) return a.error;
  if (a.note) return a.note;
  return a.reason != null ? `rejected (${a.reason})` : undefined;
};
