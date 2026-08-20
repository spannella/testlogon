// Trading Workspace — a dockable/splittable/floatable panel layout (dockview)
// hosting the testlogon blotter: Orders, Fills, Positions, Liquidations, and
// Funding panels. Drag tabs to split or float; the "+ Panel" menu reopens closed
// panels; layout persists. Orders/Positions are a live mock generator; Fills,
// Liquidations and Funding are wired to the REAL exchange account feeds
// (/me/fills/fees · /me/liquidations · /me/funding/payments) and degrade
// gracefully (empty "unavailable" state) while those routes 404.
import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  DockviewReact,
  type DockviewReadyEvent,
  type DockviewApi,
} from "dockview-react";
import "dockview-react/dist/styles/dockview.css";
import type { ColumnDef } from "@tanstack/react-table";
import { Blotter } from "@/components/blotter/grid";
import type { Order, Side, OrderStatus, Venue, Lot } from "@/components/blotter/types";
import { useFillsFees, useLiquidations, useFundingPayments } from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import type { FillFee, Liquidation, FundingPayment } from "@/api/endpoints/trading";
import WorkingOrdersPanel from "@/pages/blotter/WorkingOrdersPanel";
import TradeHistoryPanel from "@/pages/blotter/TradeHistoryPanel";
import { formatPrice, formatQty } from "@/pages/markets/format";
import "@/components/blotter/dock.css";
import { orderColumns } from "@/components/blotter/grid/columns";
import { fillsColumns } from "@/components/blotter/grid/fillsColumns";
import { usePaperMode } from "@/lib/paperMode";
import {
  paperOrdersToBlotter,
  paperFillsToBlotter,
  paperPositionsToBlotter,
  type PaperMarks,
  type SymName,
} from "@/lib/paperBlotter";
import { usePaperAccount, usePaperMarks } from "@/hooks/usePaperMarks";
import type { PaperAccount } from "@/lib/paperEngine";
import { Badge } from "@/components/ui/badge";

const SYMS = ["BTC-USD", "ETH-USD", "SOL-USD", "PMKT-2028"];
const REF: Record<string, number> = { "BTC-USD": 64000, "ETH-USD": 3400, "SOL-USD": 145, "PMKT-2028": 0.62 };
const VENUES: Venue[] = ["ARCA", "NYSE", "NASDAQ", "BZX", "IEX", "MEMX", "EDGX"];
const TIFS = ["DAY", "IOC", "GTX", "MOC"] as const;
const SOURCES = ["MANL", "VWAP", "QUOT", ""];
let seq = 0x2000;
const rnd = () => Math.random();
const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
const nowNs = () => Date.now() * 1e6;

function makeOrder(): Order {
  const sym = pick(SYMS), ref = REF[sym]!;
  const side: Side = rnd() < 0.5 ? "B" : "S";
  const px = +(ref * (1 + (rnd() - 0.5) * 0.004)).toFixed(2);
  const qty = 100 * (1 + Math.floor(rnd() * 20));
  const cumQty = rnd() < 0.35 ? Math.floor(qty * rnd()) : rnd() < 0.5 ? 0 : qty;
  const leaves = qty - cumQty;
  const status: OrderStatus = cumQty === qty ? "filled" : cumQty > 0 ? "partial" : rnd() < 0.9 ? "live" : pick(["pending", "cancelled", "rejected"] as OrderStatus[]);
  const lots: Lot[] = [];
  let done = 0;
  while (done < cumQty) {
    const slice = Math.min(cumQty - done, Math.max(1, Math.floor(rnd() * 200)));
    lots.push({ ts: nowNs(), qty: slice, px: +(px + (rnd() - 0.5) * ref * 0.0004).toFixed(2), liq: rnd() < 0.5 ? "A" : "R" });
    done += slice;
  }
  const avgPx = cumQty > 0 ? lots.reduce((s, l) => s + l.px * l.qty, 0) / cumQty : 0;
  const t = nowNs();
  return {
    clord: "0x" + (seq++).toString(16).padStart(12, "0"), sym, side, venue: pick(VENUES),
    px, qty, cumQty, leaves, avgPx: +avgPx.toFixed(2), status, tif: pick(TIFS),
    tRcv: t - Math.floor(rnd() * 3e11), tLastUpd: t, subacct: 1 + Math.floor(rnd() * 3), lots, source: pick(SOURCES),
  };
}

interface PosRow { sym: string; netQty: number; avgCost: number; markPx: number; unrealized: number; }
const posColumns: ColumnDef<any>[] = [
  { id: "sym", header: "Sym", accessorKey: "sym", size: 90 },
  { id: "netQty", header: "Net", accessorKey: "netQty", size: 90, cell: (c) => Math.round(c.getValue<number>()) },
  { id: "avgCost", header: "Avg Cost", accessorKey: "avgCost", size: 100 },
  { id: "markPx", header: "Mark", accessorKey: "markPx", size: 100 },
  { id: "unrealized", header: "uPnL", accessorKey: "unrealized", size: 110 },
];

// ── Real-feed shared helpers (int64 engine ticks + ts detection + symbol lookup) ──
// `ts` may be seconds or ms — anything below this threshold (~ year 2001 in ms)
// is treated as seconds and scaled up.
const MS_THRESHOLD = 1e12;
function formatFeedTime(ts: number | undefined): string {
  if (ts == null || !Number.isFinite(ts)) return "—";
  const ms = ts < MS_THRESHOLD ? ts * 1000 : ts;
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
const POS = "var(--pos)";
const NEG = "var(--neg)";
const signColor = (v: number | undefined) => (v == null || v === 0 ? undefined : v > 0 ? POS : NEG);

/** Look up a symbol's display name + price scaler from the /md/symbols catalog. */
type SymLookup = (symbolid: number) => { name: string; scaler: number };
function makeSymLookup(symbols: MarketSymbol[] | undefined): SymLookup {
  const byId = new Map<number, MarketSymbol>();
  for (const s of symbols ?? []) byId.set(s.symbol_id, s);
  return (symbolid: number) => {
    const s = byId.get(symbolid);
    return { name: s?.symbol ?? `#${symbolid}`, scaler: s?.price_scaler || 1 };
  };
}

// Column builders take the symbol lookup so int64 ticks scale per-symbol.
function fillFeeColumns(sym: SymLookup): ColumnDef<FillFee>[] {
  return [
    { id: "sym", header: "Sym", accessorKey: "symbolid", size: 100, cell: (c) => <span className="sym">{sym(c.getValue<number>()).name}</span> },
    { id: "side", header: "Side", accessorKey: "side", size: 60, cell: (c) => { const v = c.getValue<string>(); return <span style={{ color: v === "buy" ? POS : NEG, textTransform: "uppercase" }}>{v}</span>; } },
    { id: "price", header: "Price", accessorKey: "price", size: 110, cell: (c) => <span className="num">{formatPrice(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "qty", header: "Qty", accessorKey: "qty", size: 100, cell: (c) => <span className="num">{formatQty(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "liquidity", header: "Liq", accessorKey: "liquidity", size: 70, cell: (c) => <span className="dim" style={{ textTransform: "capitalize" }}>{c.getValue<string>()}</span> },
    { id: "fee", header: "Fee", accessorKey: "fee", size: 100, cell: (c) => <span className="num">{formatQty(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "ts", header: "Time", accessorKey: "ts", size: 100, cell: (c) => <span className="num dim">{formatFeedTime(c.getValue<number>())}</span> },
  ];
}

function liquidationColumns(sym: SymLookup): ColumnDef<Liquidation>[] {
  return [
    { id: "sym", header: "Sym", accessorKey: "symbolid", size: 100, cell: (c) => <span className="sym">{sym(c.getValue<number>()).name}</span> },
    { id: "qty", header: "Qty", accessorKey: "qty", size: 100, cell: (c) => <span className="num">{formatQty(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "mark_price", header: "Mark", accessorKey: "mark_price", size: 110, cell: (c) => <span className="num">{formatPrice(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "realized_pnl", header: "Realized PnL", accessorKey: "realized_pnl", size: 130, cell: (c) => { const v = c.getValue<number>(); return <span className="num" style={{ color: signColor(v) }}>{formatPrice(v, sym(c.row.original.symbolid).scaler)}</span>; } },
    { id: "fee", header: "Liq Fee", accessorKey: "fee", size: 100, cell: (c) => <span className="num">{formatQty(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "ts", header: "Time", accessorKey: "ts", size: 100, cell: (c) => <span className="num dim">{formatFeedTime(c.getValue<number>())}</span> },
  ];
}

function fundingColumns(sym: SymLookup): ColumnDef<FundingPayment>[] {
  return [
    { id: "sym", header: "Sym", accessorKey: "symbolid", size: 100, cell: (c) => <span className="sym">{sym(c.getValue<number>()).name}</span> },
    { id: "funding_rate_bps", header: "Rate (bps)", accessorKey: "funding_rate_bps", size: 100, cell: (c) => <span className="num">{c.getValue<number>()}</span> },
    { id: "mark_price", header: "Mark", accessorKey: "mark_price", size: 110, cell: (c) => <span className="num">{formatPrice(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "position_qty", header: "Position", accessorKey: "position_qty", size: 110, cell: (c) => <span className="num">{formatQty(c.getValue<number>(), sym(c.row.original.symbolid).scaler)}</span> },
    { id: "payment", header: "Payment", accessorKey: "payment", size: 120, cell: (c) => { const v = c.getValue<number>(); return <span className="num" style={{ color: signColor(v) }}>{formatPrice(v, sym(c.row.original.symbolid).scaler)}</span>; } },
    { id: "ts", header: "Time", accessorKey: "ts", size: 100, cell: (c) => <span className="num dim">{formatFeedTime(c.getValue<number>())}</span> },
  ];
}

// Compact column sets for narrow (mobile) screens — fewer columns so rows are
// readable without horizontal scrolling.
const mobileFilter = (cols: ColumnDef<any>[], ids: Set<string>) => cols.filter((c) => ids.has((c as any).id));

function useIsMobile(bp = 767): boolean {
  const [m, setM] = useState(() => typeof window !== "undefined" && window.matchMedia(`(max-width: ${bp}px)`).matches);
  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${bp}px)`);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [bp]);
  return m;
}

const LAYOUT_KEY = "testlogon.trading.dock.v3";
interface Ctx {
  orders: Order[]; touched: Set<string>; onCancel: (c: string) => void; isMobile: boolean; sym: SymLookup;
  paper: boolean; paperAcct: PaperAccount; paperMarks: PaperMarks; paperSymName: SymName;
}
const WsCtx = createContext<Ctx | null>(null);
const useWs = (): Ctx => { const c = useContext(WsCtx); if (!c) throw new Error("WsCtx missing"); return c; };

// A small unavailable/empty placeholder for the real-feed panels.
function FeedNote({ children }: { children: React.ReactNode }) {
  return <div style={{ padding: "0.8rem 1rem", fontSize: "0.8rem", opacity: 0.55 }}>{children}</div>;
}

// Orders — the REAL working-orders MANAGEMENT surface (GET /me/orders/live
// with per-row Amend / Cancel + confirmed Cancel-all). Replaces the former
// mock-generator grid; the mock still feeds the Positions panel below.
function OrdersPanel() {
  const c = useWs();
  if (!c.paper) return <WorkingOrdersPanel />;
  const rows = paperOrdersToBlotter(c.paperAcct, c.paperSymName);
  const cols = c.isMobile ? mobileFilter(orderColumns as ColumnDef<any>[], new Set(["sym", "side", "px", "qty", "status"])) : orderColumns;
  return (
    <div className="tl-panel-body">
      <Blotter data={rows} columns={cols} storageKeyPrefix="tl-ws-paper-orders" />
      {rows.length === 0 ? <FeedNote>No working paper orders. Place a limit order in Paper mode.</FeedNote> : null}
    </div>
  );
}

// Trade history — the REAL executed-fills feed (GET /me/fills/fees).
function HistoryPanel() { return <TradeHistoryPanel />; }

// Fills — REAL /me/fills/fees feed: per-fill price/qty + the actual engine fee
// (+ maker/taker). When the route 404s (or errors) the grid shows no rows and a
// note; the former client-side estimate is retired.
function FillsPanel() {
  const c = useWs();
  const q = useFillsFees();
  const paperRows = c.paper ? paperFillsToBlotter(c.paperAcct, c.paperSymName) : null;
  const cols = useMemo(() => {
    const full = fillFeeColumns(c.sym);
    return c.isMobile ? mobileFilter(full as ColumnDef<any>[], new Set(["sym", "side", "price", "qty", "fee"])) : full;
  }, [c.sym, c.isMobile]);
  if (c.paper && paperRows) {
    const pcols = c.isMobile ? mobileFilter(fillsColumns as ColumnDef<any>[], new Set(["sym", "side", "cumQty", "avgPx"])) : fillsColumns;
    return (
      <div className="tl-panel-body">
        <Blotter data={paperRows} columns={pcols} storageKeyPrefix="tl-ws-paper-fills" />
        {paperRows.length === 0 ? <FeedNote>No paper fills yet.</FeedNote> : null}
      </div>
    );
  }
  const rows = q.data?.fills ?? [];
  return (
    <div className="tl-panel-body">
      <Blotter data={rows} columns={cols} storageKeyPrefix="tl-ws-fills" getRowId={(r: any) => `${r.symbolid}:${r.ts}:${r.price}:${r.qty}:${r.side}`} />
      {q.isLoading ? <FeedNote>Loading fills…</FeedNote>
        : q.isError ? <FeedNote>Fills-fee feed not available on this backend yet.</FeedNote>
        : rows.length === 0 ? <FeedNote>No fills yet.</FeedNote> : null}
    </div>
  );
}

function LiquidationsPanel() {
  const c = useWs();
  const q = useLiquidations();
  const cols = useMemo(() => {
    const full = liquidationColumns(c.sym);
    return c.isMobile ? mobileFilter(full as ColumnDef<any>[], new Set(["sym", "qty", "realized_pnl", "ts"])) : full;
  }, [c.sym, c.isMobile]);
  const rows = q.data?.liquidations ?? [];
  return (
    <div className="tl-panel-body">
      <Blotter data={rows} columns={cols} storageKeyPrefix="tl-ws-liqs" getRowId={(r: any) => `${r.symbolid}:${r.ts}:${r.qty}:${r.mark_price}`} />
      {q.isLoading ? <FeedNote>Loading liquidations…</FeedNote>
        : q.isError ? <FeedNote>Liquidations feed not available on this backend yet.</FeedNote>
        : rows.length === 0 ? <FeedNote>No liquidations.</FeedNote> : null}
    </div>
  );
}

function FundingPanel() {
  const c = useWs();
  const q = useFundingPayments();
  const cols = useMemo(() => {
    const full = fundingColumns(c.sym);
    return c.isMobile ? mobileFilter(full as ColumnDef<any>[], new Set(["sym", "funding_rate_bps", "payment", "ts"])) : full;
  }, [c.sym, c.isMobile]);
  const rows = q.data?.funding ?? [];
  return (
    <div className="tl-panel-body">
      <Blotter data={rows} columns={cols} storageKeyPrefix="tl-ws-funding" getRowId={(r: any) => `${r.symbolid}:${r.ts}:${r.payment}:${r.position_qty}`} />
      {q.isLoading ? <FeedNote>Loading funding payments…</FeedNote>
        : q.isError ? <FeedNote>Funding-payments feed not available on this backend yet.</FeedNote>
        : rows.length === 0 ? <FeedNote>No funding payments.</FeedNote> : null}
    </div>
  );
}

function PositionsPanel() {
  const c = useWs();
  const paperPos = c.paper ? paperPositionsToBlotter(c.paperAcct, c.paperMarks, c.paperSymName) : null;
  const pos = useMemo(() => {
    const m = new Map<string, PosRow>();
    for (const o of c.orders) {
      const sgn = o.side === "B" ? 1 : -1;
      const p = m.get(o.sym) || { sym: o.sym, netQty: 0, avgCost: o.avgPx || o.px, markPx: o.px, unrealized: 0 };
      p.netQty += sgn * o.cumQty; p.markPx = o.px; if (o.avgPx) p.avgCost = o.avgPx;
      m.set(o.sym, p);
    }
    const rows = [...m.values()];
    rows.forEach((p) => { p.unrealized = +((p.markPx - p.avgCost) * p.netQty).toFixed(2); });
    return rows;
  }, [c.orders]);
  if (c.paper && paperPos) {
    return (
      <div className="tl-panel-body">
        <Blotter data={paperPos} columns={posColumns} storageKeyPrefix="tl-ws-paper-pos" getRowId={(r: any) => r.sym} />
        {paperPos.length === 0 ? <FeedNote>No open paper positions.</FeedNote> : null}
      </div>
    );
  }
  return <div className="tl-panel-body"><Blotter data={pos} columns={posColumns} storageKeyPrefix="tl-ws-pos" getRowId={(r: any) => r.sym} /></div>;
}

const COMPONENTS = { orders: OrdersPanel, history: HistoryPanel, fills: FillsPanel, positions: PositionsPanel, liquidations: LiquidationsPanel, funding: FundingPanel };
type PanelId = keyof typeof COMPONENTS;
const PANEL_META: { id: PanelId; title: string }[] = [
  { id: "orders", title: "Orders" },
  { id: "history", title: "Trade History" },
  { id: "fills", title: "Fills" },
  { id: "positions", title: "Positions" },
  { id: "liquidations", title: "Liquidations" },
  { id: "funding", title: "Funding" },
];

export default function TradingWorkspacePage() {
  const [orders, setOrders] = useState<Order[]>(() => Array.from({ length: 600 }, makeOrder));
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const clearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancel = (clord: string) => setOrders((prev) => prev.map((o) => (o.clord === clord ? { ...o, status: "cancelled" as OrderStatus, leaves: 0 } : o)));
  const isMobile = useIsMobile();
  const [activeTab, setActiveTab] = useState<PanelId>("orders");
  // Symbol catalog for mapping symbolid -> name + price scaler on the real feeds.
  const symbolsQuery = useSymbols();
  const sym = useMemo(() => makeSymLookup(symbolsQuery.data?.symbols), [symbolsQuery.data]);
  const { enabled: paper } = usePaperMode();
  const paperAcct = usePaperAccount(paper);
  const { marks: paperMarks, symName: paperSymName } = usePaperMarks(paperAcct, paper);

  useEffect(() => {
    const id = setInterval(() => {
      setOrders((prev) => {
        const next = prev.slice(); const t = new Set<string>();
        for (let k = 0; k < 24; k++) {
          const i = Math.floor(Math.random() * next.length);
          const cur = next[i];
          if (!cur) continue;
          const o = { ...cur, lots: cur.lots.slice() };
          o.px = +(o.px * (1 + (Math.random() - 0.5) * 0.0006)).toFixed(2); o.tLastUpd = nowNs();
          if (o.leaves > 0 && o.status !== "cancelled" && Math.random() < 0.3) {
            const f = Math.min(o.leaves, Math.max(1, Math.floor(Math.random() * 120)));
            o.cumQty += f; o.leaves -= f;
            o.lots.push({ ts: o.tLastUpd, qty: f, px: o.px, liq: Math.random() < 0.5 ? "A" : "R" });
            o.avgPx = +(o.lots.reduce((s, l) => s + l.px * l.qty, 0) / o.cumQty).toFixed(2);
            o.status = o.leaves === 0 ? "filled" : "partial";
          }
          next[i] = o; t.add(o.clord);
        }
        setTouched(t);
        if (clearTimer.current) clearTimeout(clearTimer.current);
        clearTimer.current = setTimeout(() => setTouched(new Set()), 500);
        return next;
      });
    }, 1000);
    return () => { clearInterval(id); if (clearTimer.current) clearTimeout(clearTimer.current); };
  }, []);

  const ctxRef = useRef<Ctx>({ orders, touched, onCancel: cancel, isMobile, sym, paper, paperAcct, paperMarks, paperSymName });
  ctxRef.current = { orders, touched, onCancel: cancel, isMobile, sym, paper, paperAcct, paperMarks, paperSymName };
  const stableCtx = useMemo(() => new Proxy({} as Ctx, { get(_, k: string) { return (ctxRef.current as any)[k]; } }), []);

  const [dockApi, setDockApi] = useState<DockviewApi | null>(null);
  const [openIds, setOpenIds] = useState<Set<PanelId>>(new Set(PANEL_META.map((m) => m.id)));
  const [menuOpen, setMenuOpen] = useState(false);

  const addDefaults = (api: DockviewApi) => {
    api.addPanel({ id: "orders", title: "Orders", component: "orders", params: { ctx: stableCtx } });
    api.addPanel({ id: "fills", title: "Fills", component: "fills", params: { ctx: stableCtx }, position: { referencePanel: "orders", direction: "right" } });
    api.addPanel({ id: "history", title: "Trade History", component: "history", params: { ctx: stableCtx }, position: { referencePanel: "fills", direction: "within" } });
    api.addPanel({ id: "positions", title: "Positions", component: "positions", params: { ctx: stableCtx }, position: { referencePanel: "fills", direction: "below" } });
    api.addPanel({ id: "liquidations", title: "Liquidations", component: "liquidations", params: { ctx: stableCtx }, position: { referencePanel: "positions", direction: "within" } });
    api.addPanel({ id: "funding", title: "Funding", component: "funding", params: { ctx: stableCtx }, position: { referencePanel: "liquidations", direction: "within" } });
    api.getPanel("orders")?.api.setActive();
  };
  const onReady = (ev: DockviewReadyEvent) => {
    setDockApi(ev.api);
    const saved = localStorage.getItem(LAYOUT_KEY);
    if (saved) {
      try { ev.api.fromJSON(JSON.parse(saved)); for (const p of ev.api.panels) p.api.updateParameters({ ctx: stableCtx }); if (ev.api.panels.length === 0) addDefaults(ev.api); }
      catch { addDefaults(ev.api); }
    } else addDefaults(ev.api);
    const refresh = () => {
      const ids = new Set<PanelId>(); for (const p of ev.api.panels) ids.add(p.id as PanelId);
      setOpenIds(ids); localStorage.setItem(LAYOUT_KEY, JSON.stringify(ev.api.toJSON()));
    };
    refresh(); ev.api.onDidLayoutChange(refresh);
  };
  const reopen = (id: PanelId) => {
    if (!dockApi) return;
    const ex = dockApi.getPanel(id); if (ex) { ex.api.setActive(); return; }
    const meta = PANEL_META.find((m) => m.id === id)!;
    const anchor = dockApi.panels[0];
    dockApi.addPanel({ id, title: meta.title, component: id, params: { ctx: stableCtx }, position: anchor ? { referencePanel: anchor.id, direction: "within" } : undefined }).api.setActive();
    setMenuOpen(false);
  };
  const reset = () => { if (!dockApi) return; dockApi.clear(); addDefaults(dockApi); setMenuOpen(false); };
  const closed = PANEL_META.filter((m) => !openIds.has(m.id));

  // ── Mobile: dockview splits are unusable on a phone, so show one full-width
  // panel at a time with a segmented tab switcher (grids use compact columns). ──
  if (isMobile) {
    const ActivePanel = COMPONENTS[activeTab];
    return (
      <WsCtx.Provider value={ctxRef.current}>
        <div style={{ height: "calc(100vh - 3.5rem)", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.5rem 0.7rem 0.35rem" }}>
            <h1 style={{ fontSize: "1rem", fontWeight: 600 }}>Trading Workspace</h1>
            {paper && <Badge variant="secondary">PAPER</Badge>}
          </div>
          <div className="tl-mobile-tabs" style={{ overflowX: "auto" }}>
            {PANEL_META.map((m) => (
              <button key={m.id} type="button" className={activeTab === m.id ? "active" : ""} onClick={() => setActiveTab(m.id)}>{m.title}</button>
            ))}
          </div>
          <div style={{ flex: 1, minHeight: 0 }}><ActivePanel /></div>
        </div>
      </WsCtx.Provider>
    );
  }

  return (
    <WsCtx.Provider value={ctxRef.current}>
      <div style={{ height: "calc(100vh - 3.5rem)", display: "flex", flexDirection: "column", padding: "0.6rem 0.75rem", gap: "0.4rem" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "0.75rem" }}>
          <h1 style={{ fontSize: "1.1rem", fontWeight: 600 }}>Trading Workspace</h1>
          {paper && <Badge variant="secondary">PAPER</Badge>}
          <span style={{ fontSize: "0.78rem", opacity: 0.55 }}>drag tabs to split / float · layout persists · right-click a grid header for group / filter / columns</span>
        </div>
        <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
          <div className="tl-dock-host">
            <DockviewReact className="dockview-theme-abyss tl-trading-dock" components={COMPONENTS} onReady={onReady} />
            <div className={`tl-panel-menu ${menuOpen ? "open" : ""}`}>
              <button type="button" className="tl-panel-btn" onClick={() => setMenuOpen((m) => !m)} title="Reopen a closed panel">+ Panel ▾</button>
              {menuOpen && (
                <div className="tl-panel-list" role="menu">
                  {PANEL_META.map((m) => {
                    const isOpen = openIds.has(m.id);
                    return (
                      <button key={m.id} type="button" className="tl-panel-item" disabled={isOpen} onClick={() => reopen(m.id)} title={isOpen ? "Already open" : "Reopen this panel"}>
                        <span className={`dot ${isOpen ? "on" : "off"}`} />{m.title}{isOpen && <span className="chip">open</span>}
                      </button>
                    );
                  })}
                  <hr />
                  <button type="button" className="tl-panel-item danger" onClick={reset}>Reset layout</button>
                  {closed.length > 0 && <button type="button" className="tl-panel-item" onClick={() => closed.forEach((m) => reopen(m.id))}>Reopen all ({closed.length})</button>}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </WsCtx.Provider>
  );
}
