// Trading blotter data model — mirrors the Raven manual_order_protocolN
// order_element_t / trade_element_t plus a few derived fields for display.

export type Side = 'B' | 'S';
export type OrderStatus =
  | 'pending'
  | 'live'
  | 'partial'
  | 'filled'
  | 'cancelled'
  | 'rejected';
export type Venue =
  | 'ARCA'
  | 'NYSE'
  | 'NASDAQ'
  | 'BZX'
  | 'BYX'
  | 'EDGA'
  | 'EDGX'
  | 'IEX'
  | 'MEMX';

// Individual lot inside an order (partial fills) — populates the rich
// hover tooltip.  Real system: from OeSessionCorsoFill or per-Fill events.
export interface Lot {
  ts: number;         // ns since epoch
  qty: number;
  px: number;
  liq: 'A' | 'R';     // added / removed liquidity
}

export interface Order {
  clord: string;           // client order id (u64 hex)
  sym: string;             // symbol
  side: Side;
  venue: Venue;
  px: number;              // limit price
  qty: number;             // original qty
  cumQty: number;          // filled so far
  leaves: number;          // remaining
  avgPx: number;           // volume-weighted avg fill px
  status: OrderStatus;
  tif: 'DAY' | 'IOC' | 'GTX' | 'MOC';
  tRcv: number;            // ns since epoch — order received
  tLastUpd: number;        // ns since epoch — last state change
  subacct: number;
  lots: Lot[];             // fills that comprise cumQty
  parentClord?: string;    // set on replaces
  rejectReason?: string;
  // Fill source tag — 4-char slug from corso_etf_fill.feecode. Values:
  //   'QUOT' — ETF quoter/drainer (primary-side fill)
  //   'HDGE' — HedgerSet hedge on canonical hedge instrument
  //   'VWAP' — manual VWAP order (once wired)
  //   'MANL' — manual limit/market order (once wired)
  //   ''     — legacy / unknown
  source?: string;
  // Fill-quality analytics (populated on wire fills; undefined elsewhere).
  // Sign convention across all *derived* values: + = FAVOURABLE for us,
  // − = adverse. Filled the same way for hedges and quoter fills so
  // aggregations (means, histograms) don't mix conventions.
  fairAtPlace?:  number;  // fair-value snapshot at order-send time (px, not nanos)
  fairAtExec?:   number;  // fair-value at fill time
  edgeToPlace?:  number;  // side-aware: fair_at_place vs fill_px, + = better
  edgeToExec?:   number;  // side-aware: fair_at_exec  vs fill_px, + = better
  liq?:          string;  // 1-char venue liquidity code (A/R/H/U/O/?)
  linkExecid?:   string;  // hedge lineage: quoter execid this hedge traces to (hex string)
  impliedPx?:    number;  // implied hedge price from linked quoter fill
  slipBp?:       number;  // + = FAVOURABLE (we did better than implied), − = adverse
  // Computed taker fee for the fill = round(avgPx*cumQty*takerFeeBps/10000),
  // sourced from the /me/fills/fees taker rate. Undefined until enriched;
  // the Fee column hides entirely when no fee rate is available.
  fee?:          number;
  // display-only derived: milliseconds since last update, refreshed each tick.
  // Not stored in mock data — computed at render time.
}

export interface PositionRow {
  sym: string;
  netQty: number;
  avgCost: number;
  markPx: number;
  realized: number;
  unrealized: number;
  lastTradeTs: number;
  lots: Lot[];   // FIFO lot breakdown for the tooltip
}
