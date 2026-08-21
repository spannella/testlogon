import { api } from "@/api/client";

/**
 * MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION surface (`/me/margin/distress`,
 * `/me/bailouts/*`, `/me/positions/{symbolId}/bailout`, `/me/prefs/bailout`).
 *
 * A leveraged margin position approaching a margin call can open a BAILOUT
 * AUCTION to raise rescue capital and avoid forced liquidation. It exists only
 * in a narrow window: the position is in a volatility-scaled DISTRESS band but
 * STILL SOLVENT (`equity > maintenance`). Rescuers inject capital in exchange
 * for a position-SHARE (co-owning a slice of the position + its future uPnL) via
 * a sealed single-clearing-price auction (least total share given up). Breaching
 * maintenance mid-auction auto-cancels -> normal liquidation.
 *
 * SERVER-AUTHORITATIVE: distress (marks / volatility / equity) is computed on the
 * server; the client only RENDERS the read and NEVER fabricates a distress
 * signal. CONVENTIONS: every monetary amount is INTEGER CENTS; every `_bps`
 * field is BASIS POINTS (100% = 10_000). NONE of these endpoints exist on the
 * backend yet — every GET degrades on 404/absent to an honest "pending backend"
 * state (callers use `retry:false`), and every mutation surfaces a clear error
 * (never silently "succeeds").
 */

export type BailoutStatus = "open" | "cleared" | "cancelled" | "liquidated";

/** One margin position with its SERVER-COMPUTED distress read. */
export interface DistressPosition {
  symbol_id: number;
  symbol: string;
  side: "long" | "short" | string;
  /** Position size (whole/base units as the server reports). */
  qty: number;
  /** Entry price in cents. */
  entry_price: number;
  /** Current mark price in cents. */
  mark_price: number;
  /** Liquidation price in cents. */
  liq_price: number;
  /** Position equity in cents. */
  equity_cents: number;
  /** Maintenance-margin requirement in cents (solvent when equity > this). */
  maintenance_cents: number;
  /** Distance-to-liq as bps of the mark = |mark - liq| / mark. */
  buffer_bps: number;
  /** Volatility in bps used to scale the danger line. */
  volatility_bps: number;
  /** The volatility-scaled danger line in bps (in-band when buffer <= this). */
  danger_bps: number;
  /** Server verdict: buffer <= danger AND still solvent. */
  in_band: boolean;
  /** Server verdict: a bailout auction may be opened for this position. */
  eligible: boolean;
  /** The open auction id, when one already exists for this position. */
  auction_id?: string;
}

export interface DistressResult {
  positions: DistressPosition[];
}

/** One rescuer who injected capital for a position-share. */
export interface BailoutRescuer {
  sub: string;
  /** Capital escrowed, in cents. */
  capital_cents: number;
  /** Position-share granted (or bid), in bps. */
  share_bps: number;
}

/** A pre-emptive bailout auction on a distressed (still-solvent) position. */
export interface BailoutAuction {
  auction_id: string;
  symbol_id: number;
  owner_sub: string;
  side: "long" | "short" | string;
  qty: number;
  /** Rescue capital target, in cents. */
  capital_needed_cents: number;
  /** Owner's ceiling on total position-share given up, in bps. */
  max_share_bps: number;
  status: BailoutStatus;
  /** Single uniform clearing share given up, in bps (present once cleared). */
  clearing_share_bps?: number;
  /** Total capital raised, in cents (present once cleared). */
  raised_cents?: number;
  rescuers?: BailoutRescuer[];
  /** Liquidation price in cents — if the mark hits this first the auction cancels. */
  liq_price: number;
  /** Current mark price in cents. */
  mark_price: number;
  /** Auction close timestamp (seconds). */
  close_ts: number;
}

export interface BailoutsResult {
  auctions: BailoutAuction[];
}

/** Account preference: auto-open a bailout on band-entry + a default ceiling. */
export interface BailoutPrefs {
  auto_enabled: boolean;
  default_max_share_bps: number;
}

/** Generic mutation ack (rescue bid / clear). Carries a message on rejection. */
export interface BailoutAck {
  status?: string;
  auction_id?: string;
  detail?: string;
  error?: string;
  note?: string;
  reason?: string | number;
}

// -- Requests ----------------------------------------------------------

/** Owner opens a bailout auction on an eligible, in-band position. */
export interface OpenBailoutRequest {
  /** Ceiling on total position-share given up, in bps. */
  max_share_bps: number;
  /** Optional auction close timestamp (seconds). */
  close_ts?: number;
}

/** Rescuer bid: escrow capital for a position-share. */
export interface RescueBidRequest {
  capital_cents: number;
  share_bps: number;
}

// -- Calls (all 404 until the backend ships — callers degrade gracefully) --

/** The caller's margin positions with their server-computed distress read. */
export const getDistress = () => api.get<DistressResult>("/me/margin/distress");

/** Open opportunity board — every open bailout auction to browse/rescue. */
export const getBailouts = () => api.get<BailoutsResult>("/me/bailouts");

/** The bailout auction for one of the caller's positions (by symbol id). */
export const getPositionBailout = (symbolId: number) =>
  api.get<BailoutAuction>(`/me/positions/${encodeURIComponent(String(symbolId))}/bailout`);

/** Owner: open a bailout auction (server rejects if not eligible / in-band). */
export const openBailout = (symbolId: number, body: OpenBailoutRequest) =>
  api.post<BailoutAuction>(
    `/me/positions/${encodeURIComponent(String(symbolId))}/bailout`,
    body,
  );

/** Rescuer: escrow capital for a position-share in an auction. */
export const placeRescueBid = (auctionId: string, body: RescueBidRequest) =>
  api.post<BailoutAck>(`/me/bailouts/${encodeURIComponent(auctionId)}/bid`, body);

/** Owner: trigger sealed clearing at the least-dilutive single price. */
export const clearBailout = (auctionId: string) =>
  api.post<BailoutAuction>(`/me/bailouts/${encodeURIComponent(auctionId)}/clear`, {});

/** Read the auto-bailout account preference. */
export const getBailoutPrefs = () => api.get<BailoutPrefs>("/me/prefs/bailout");

/** Persist the auto-bailout account preference. */
export const putBailoutPrefs = (body: BailoutPrefs) =>
  api.put<BailoutPrefs>("/me/prefs/bailout", body);

// -- Helpers -----------------------------------------------------------

/** Best human message off any bailout ack (error / detail / reject reason). */
export const bailoutAckMessage = (a: BailoutAck | null | undefined): string | undefined => {
  if (!a) return undefined;
  if (a.detail) return a.detail;
  if (a.error) return a.error;
  if (a.note) return a.note;
  return a.reason != null ? `rejected (${a.reason})` : undefined;
};
