// Pure, framework-free client-side PAPER-TRADING engine. Everything stays in the
// exchange engine's int64 "tick" space (prices/qtys/money are integer ticks; the
// UI scales for display with the markets format helpers). NOTHING here touches
// the network or the real /me/orders — this is an isolated local simulation.
//
// Kept pure so it is unit-testable in isolation (see paperEngine.test.ts). Every
// mutating function returns a NEW account object (immutably); callers persist.

export type PaperSide = "buy" | "sell";
export type PaperOrderType = "market" | "limit";

/** A working (resting) or already-filled paper order. */
export interface PaperOrder {
  id: string;
  symbolId: number;
  side: PaperSide;
  type: PaperOrderType;
  /** Limit price in ticks (undefined for market orders). */
  price?: number;
  /** Order qty in ticks (always positive). */
  qty: number;
  status: "working" | "filled" | "cancelled";
  /** Creation time (ms epoch). */
  createdAt: number;
}

/** One executed paper fill. */
export interface PaperFill {
  id: string;
  orderId: string;
  symbolId: number;
  side: PaperSide;
  /** Fill price in ticks. */
  price: number;
  /** Fill qty in ticks (always positive). */
  qty: number;
  /** Realized PnL (ticks) attributed to this fill (0 when purely opening/adding). */
  realized: number;
  ts: number;
}

/** An open position under average-cost accounting. */
export interface PaperPosition {
  /** Signed qty in ticks — negative = short, positive = long, 0 = flat. */
  qty: number;
  /** Average entry price in ticks (0 when flat). */
  avgEntry: number;
}

export interface PaperAccount {
  /** Free quote cash in ticks. */
  cash: number;
  /** Open positions keyed by symbolId. */
  positions: Record<number, PaperPosition>;
  /** All orders (working + terminal), newest last. */
  orders: PaperOrder[];
  /** All fills, newest last. */
  fills: PaperFill[];
  /** Cumulative realized PnL in ticks. */
  realizedPnl: number;
  /** The cash the account was seeded with (for reset / return-% display). */
  startingCash: number;
}

/** Default seed: 100,000 quote units. Callers pass the value already in ticks. */
export const DEFAULT_STARTING_CASH = 100_000;

let idCounter = 0;
/** Monotonic-ish unique id; not persisted, only needs per-session uniqueness. */
function nextId(prefix: string): string {
  idCounter += 1;
  return `${prefix}_${Date.now().toString(36)}_${idCounter.toString(36)}`;
}

/** A fresh, empty paper account seeded with `startingCash` ticks. */
export function newAccount(startingCash: number = DEFAULT_STARTING_CASH): PaperAccount {
  const seed =
    Number.isFinite(startingCash) && startingCash > 0
      ? Math.floor(startingCash)
      : DEFAULT_STARTING_CASH;
  return {
    cash: seed,
    positions: {},
    orders: [],
    fills: [],
    realizedPnl: 0,
    startingCash: seed,
  };
}

/** Shallow-clone an account into a fresh mutable working copy. */
function cloneAccount(acct: PaperAccount): PaperAccount {
  const positions: Record<number, PaperPosition> = {};
  for (const [k, v] of Object.entries(acct.positions)) {
    positions[Number(k)] = { qty: v.qty, avgEntry: v.avgEntry };
  }
  return {
    cash: acct.cash,
    positions,
    orders: acct.orders.slice(),
    fills: acct.fills.slice(),
    realizedPnl: acct.realizedPnl,
    startingCash: acct.startingCash,
  };
}

/**
 * Apply one execution against the working account copy IN PLACE. Updates the
 * position via average-cost, realizes PnL when reducing/closing (with clean
 * flips), moves cash (buy: -price*qty, sell: +price*qty), and appends a fill.
 * Returns the realized PnL of this fill.
 */
function applyFill(
  acct: PaperAccount,
  order: PaperOrder,
  fillPrice: number,
  fillQty: number,
  ts: number,
): number {
  const side = order.side;
  const signed = side === "buy" ? fillQty : -fillQty;

  // Cash leg.
  acct.cash += side === "buy" ? -fillPrice * fillQty : fillPrice * fillQty;

  const pos = acct.positions[order.symbolId] ?? { qty: 0, avgEntry: 0 };
  const netQty = pos.qty;
  let realized = 0;

  if (netQty === 0 || Math.sign(signed) === Math.sign(netQty)) {
    // Opening from flat or adding in the same direction — weighted-average entry.
    const newQty = netQty + signed;
    const totalCost = pos.avgEntry * Math.abs(netQty) + fillPrice * Math.abs(signed);
    pos.avgEntry = Math.abs(newQty) === 0 ? 0 : totalCost / Math.abs(newQty);
    pos.qty = newQty;
  } else {
    // Opposite side — reduce/close, and maybe flip.
    const dir = netQty > 0 ? 1 : -1;
    const closedQty = Math.min(Math.abs(signed), Math.abs(netQty));
    realized = (fillPrice - pos.avgEntry) * closedQty * dir;
    acct.realizedPnl += realized;

    const residual = Math.abs(signed) - Math.abs(netQty);
    if (residual > 0) {
      // Closed the old leg entirely then flipped — open a fresh leg.
      pos.qty = Math.sign(signed) * residual;
      pos.avgEntry = fillPrice;
    } else {
      pos.qty = netQty + signed;
      if (pos.qty === 0) pos.avgEntry = 0;
    }
  }

  if (pos.qty === 0) {
    delete acct.positions[order.symbolId];
  } else {
    acct.positions[order.symbolId] = pos;
  }

  acct.fills.push({
    id: nextId("fill"),
    orderId: order.id,
    symbolId: order.symbolId,
    side,
    price: fillPrice,
    qty: fillQty,
    realized,
    ts,
  });

  return realized;
}

export interface PlaceOrderInput {
  symbolId: number;
  side: PaperSide;
  type: PaperOrderType;
  /** Required for limit orders; ignored for market. */
  price?: number;
  qty: number;
}

export interface PlaceOrderResult {
  account: PaperAccount;
  order: PaperOrder;
  /** The immediate fill, when the order executed on placement. */
  fill?: PaperFill;
}

/**
 * Place a paper order.
 * - MARKET: fills immediately at `marketPrice`.
 * - LIMIT: if it already crosses `marketPrice` it fills immediately at the
 *   limit price; otherwise it rests as a working order and fills later on tick.
 *   (buy crosses when marketPrice <= limit; sell crosses when marketPrice >= limit)
 */
export function placeOrder(
  acct: PaperAccount,
  input: PlaceOrderInput,
  marketPrice: number | undefined,
  ts: number = Date.now(),
): PlaceOrderResult {
  const next = cloneAccount(acct);
  const qty = Math.floor(input.qty);

  const order: PaperOrder = {
    id: nextId("ord"),
    symbolId: input.symbolId,
    side: input.side,
    type: input.type,
    price: input.type === "limit" ? input.price : undefined,
    qty,
    status: "working",
    createdAt: ts,
  };

  if (!(qty > 0)) {
    // Nothing to do — reject by returning a cancelled order, no state change.
    order.status = "cancelled";
    next.orders.push(order);
    return { account: next, order };
  }

  if (order.type === "market") {
    if (!(marketPrice != null && marketPrice > 0)) {
      // No market to fill against — cannot rest a market order, so cancel it.
      order.status = "cancelled";
      next.orders.push(order);
      return { account: next, order };
    }
    applyFill(next, order, marketPrice, qty, ts);
    order.status = "filled";
    next.orders.push(order);
    const fill = next.fills[next.fills.length - 1];
    return { account: next, order, fill };
  }

  // Limit order.
  const limit = order.price;
  if (!(limit != null && limit > 0)) {
    order.status = "cancelled";
    next.orders.push(order);
    return { account: next, order };
  }

  const crosses =
    marketPrice != null &&
    marketPrice > 0 &&
    ((order.side === "buy" && marketPrice <= limit) ||
      (order.side === "sell" && marketPrice >= limit));

  if (crosses) {
    applyFill(next, order, limit, qty, ts);
    order.status = "filled";
    next.orders.push(order);
    const fill = next.fills[next.fills.length - 1];
    return { account: next, order, fill };
  }

  // Rests as a working order.
  next.orders.push(order);
  return { account: next, order };
}

/**
 * Feed a new market price for `symbolId`; fills every working order the price now
 * satisfies (limit BUY fills when marketPrice <= limit; limit SELL fills when
 * marketPrice >= limit), each at ITS limit price. Returns a new account.
 */
export function onTick(
  acct: PaperAccount,
  symbolId: number,
  marketPrice: number | undefined,
  ts: number = Date.now(),
): PaperAccount {
  if (!(marketPrice != null && marketPrice > 0)) return acct;

  const working = acct.orders.filter(
    (o) =>
      o.status === "working" &&
      o.symbolId === symbolId &&
      o.type === "limit" &&
      o.price != null,
  );
  if (working.length === 0) return acct;

  const willFill = working.filter((o) =>
    o.side === "buy" ? marketPrice <= o.price! : marketPrice >= o.price!,
  );
  if (willFill.length === 0) return acct;

  const next = cloneAccount(acct);
  // Deterministic order: oldest working order first.
  const fillIds = new Set(willFill.map((o) => o.id));
  const ordered = next.orders
    .filter((o) => fillIds.has(o.id))
    .sort((a, b) => a.createdAt - b.createdAt);

  for (const o of ordered) {
    applyFill(next, o, o.price!, o.qty, ts);
    o.status = "filled";
  }
  return next;
}

/** Cancel a working order by id (no-op if not working). Returns a new account. */
export function cancelOrder(acct: PaperAccount, id: string): PaperAccount {
  const target = acct.orders.find((o) => o.id === id);
  if (!target || target.status !== "working") return acct;
  const next = cloneAccount(acct);
  const o = next.orders.find((x) => x.id === id)!;
  o.status = "cancelled";
  return next;
}

/** Reset to a fresh account, preserving the original starting cash by default. */
export function resetAccount(startingCash?: number): PaperAccount {
  return newAccount(startingCash ?? DEFAULT_STARTING_CASH);
}

/** Mark-to-market value of a single position at `mark` (ticks). */
export function positionMtm(pos: PaperPosition, mark: number | undefined): number {
  if (pos.qty === 0 || mark == null || !Number.isFinite(mark)) return 0;
  return pos.qty * mark;
}

/**
 * Unrealized PnL across all positions given a map of symbolId -> mark price.
 * A position with no mark contributes 0.
 */
export function unrealized(
  acct: PaperAccount,
  marks: Record<number, number | undefined>,
): number {
  let total = 0;
  for (const [k, pos] of Object.entries(acct.positions)) {
    const mark = marks[Number(k)];
    if (mark == null || !Number.isFinite(mark)) continue;
    total += (mark - pos.avgEntry) * pos.qty;
  }
  return total;
}

/** Account equity = cash + Σ position mark-to-market. */
export function equity(
  acct: PaperAccount,
  marks: Record<number, number | undefined>,
): number {
  let total = acct.cash;
  for (const [k, pos] of Object.entries(acct.positions)) {
    const mark = marks[Number(k)];
    if (mark == null || !Number.isFinite(mark)) continue;
    total += positionMtm(pos, mark);
  }
  return total;
}
