// Trading Workspace — a dockable/splittable/floatable panel layout (dockview)
// hosting the testlogon blotter: Orders, Fills, and Positions panels. Drag tabs
// to split or float; the "+ Panel" menu reopens closed panels; layout persists.
import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getFillsFees, computeFee } from "@/api/endpoints/custody";
import {
  DockviewReact,
  type DockviewReadyEvent,
  type DockviewApi,
} from "dockview-react";
import "dockview-react/dist/styles/dockview.css";
import type { ColumnDef } from "@tanstack/react-table";
import { Blotter } from "@/components/blotter/grid";
import { orderColumns } from "@/components/blotter/grid/columns";
import { fillsColumns } from "@/components/blotter/grid/fillsColumns";
import type { Order, Side, OrderStatus, Venue, Lot } from "@/components/blotter/types";
import "@/components/blotter/dock.css";

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

// Compact column sets for narrow (mobile) screens — fewer columns so rows are
// readable without horizontal scrolling.
const MOBILE_ORDER_IDS = new Set(["sym", "side", "px", "qty", "cumQty", "status"]);
const MOBILE_FILL_IDS = new Set(["sym", "side", "px", "qty", "avgPx", "fee", "status"]);
const mobileOrderColumns = orderColumns.filter((c) => MOBILE_ORDER_IDS.has((c as any).id));
const mobileFillsColumns = fillsColumns.filter((c) => MOBILE_FILL_IDS.has((c as any).id));

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

const LAYOUT_KEY = "testlogon.trading.dock.v1";
interface Ctx { orders: Order[]; touched: Set<string>; onCancel: (c: string) => void; isMobile: boolean; takerFeeBps: number | null; }
const WsCtx = createContext<Ctx | null>(null);
const useWs = (): Ctx => { const c = useContext(WsCtx); if (!c) throw new Error("WsCtx missing"); return c; };

function OrdersPanel() { const c = useWs(); return <div className="tl-panel-body"><Blotter data={c.orders} columns={c.isMobile ? mobileOrderColumns : orderColumns} touched={c.touched} storageKeyPrefix="tl-ws-orders" onCancel={c.onCancel} /></div>; }
function FillsPanel() { const c = useWs(); const fills = useMemo(() => c.orders.filter((o) => o.cumQty > 0).map((o) => (c.takerFeeBps == null ? o : { ...o, fee: computeFee(o.avgPx, o.cumQty, c.takerFeeBps) })), [c.orders, c.takerFeeBps]); return <div className="tl-panel-body"><Blotter data={fills} columns={c.isMobile ? mobileFillsColumns : fillsColumns} touched={c.touched} storageKeyPrefix="tl-ws-fills" /></div>; }
function PositionsPanel() {
  const c = useWs();
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
  return <div className="tl-panel-body"><Blotter data={pos} columns={posColumns} storageKeyPrefix="tl-ws-pos" getRowId={(r: any) => r.sym} /></div>;
}

const COMPONENTS = { orders: OrdersPanel, fills: FillsPanel, positions: PositionsPanel };
type PanelId = keyof typeof COMPONENTS;
const PANEL_META: { id: PanelId; title: string }[] = [
  { id: "orders", title: "Orders" },
  { id: "fills", title: "Fills" },
  { id: "positions", title: "Positions" },
];

export default function TradingWorkspacePage() {
  const [orders, setOrders] = useState<Order[]>(() => Array.from({ length: 600 }, makeOrder));
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const clearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancel = (clord: string) => setOrders((prev) => prev.map((o) => (o.clord === clord ? { ...o, status: "cancelled" as OrderStatus, leaves: 0 } : o)));
  const isMobile = useIsMobile();
  const [activeTab, setActiveTab] = useState<PanelId>("orders");
  // Enriched fills-fee feed. 404s until the edge deploys -> null taker rate,
  // and the Fills grid then hides its Fee column gracefully (no error).
  const feesQuery = useQuery({ queryKey: ["fills", "fees"], queryFn: getFillsFees, retry: false, staleTime: 60_000 });
  const takerFeeBps = feesQuery.data?.taker_fee_bps ?? null;

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

  const ctxRef = useRef<Ctx>({ orders, touched, onCancel: cancel, isMobile, takerFeeBps });
  ctxRef.current = { orders, touched, onCancel: cancel, isMobile, takerFeeBps };
  const stableCtx = useMemo(() => new Proxy({} as Ctx, { get(_, k: string) { return (ctxRef.current as any)[k]; } }), []);

  const [dockApi, setDockApi] = useState<DockviewApi | null>(null);
  const [openIds, setOpenIds] = useState<Set<PanelId>>(new Set(PANEL_META.map((m) => m.id)));
  const [menuOpen, setMenuOpen] = useState(false);

  const addDefaults = (api: DockviewApi) => {
    api.addPanel({ id: "orders", title: "Orders", component: "orders", params: { ctx: stableCtx } });
    api.addPanel({ id: "fills", title: "Fills", component: "fills", params: { ctx: stableCtx }, position: { referencePanel: "orders", direction: "right" } });
    api.addPanel({ id: "positions", title: "Positions", component: "positions", params: { ctx: stableCtx }, position: { referencePanel: "fills", direction: "below" } });
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
          <h1 style={{ fontSize: "1rem", fontWeight: 600, padding: "0.5rem 0.7rem 0.35rem" }}>Trading Workspace</h1>
          <div className="tl-mobile-tabs">
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
