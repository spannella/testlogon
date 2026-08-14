// Trading Blotter — dense, virtualized order blotter with the
// full layout tooling (group-by, per-column filters, column chooser/reorder/
// resize, master-detail fills tooltip, edit-in-place, CSV/TSV export, persisted
// layout). Fed here by a live-ticking order generator over testlogon symbols;
// swap `useOrders` for the exchange /me/orders feed to go live.
import { useEffect, useMemo, useRef, useState } from "react";
import { Blotter } from "@/components/blotter/grid";
import { orderColumns } from "@/components/blotter/grid/columns";
import type { Order, Side, OrderStatus, Venue, Lot } from "@/components/blotter/types";

const SYMS = ["BTC-USD", "ETH-USD", "SOL-USD", "PMKT-2028"];
const REF: Record<string, number> = { "BTC-USD": 64000, "ETH-USD": 3400, "SOL-USD": 145, "PMKT-2028": 0.62 };
const VENUES: Venue[] = ["ARCA", "NYSE", "NASDAQ", "BZX", "IEX", "MEMX", "EDGX"];
const TIFS = ["DAY", "IOC", "GTX", "MOC"] as const;
const SOURCES = ["MANL", "VWAP", "QUOT", ""];
let seq = 0x1000;
const rnd = () => Math.random();
const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)];
const nowNs = () => Date.now() * 1e6;

function makeOrder(): Order {
  const sym = pick(SYMS);
  const ref = REF[sym];
  const side: Side = rnd() < 0.5 ? "B" : "S";
  const dp = sym.startsWith("PMKT") ? 2 : 2;
  const px = +(ref * (1 + (rnd() - 0.5) * 0.004)).toFixed(dp);
  const qty = 100 * (1 + Math.floor(rnd() * 20));
  const cumQty = rnd() < 0.35 ? Math.floor(qty * rnd()) : rnd() < 0.5 ? 0 : qty;
  const leaves = qty - cumQty;
  const status: OrderStatus =
    cumQty === qty ? "filled" : cumQty > 0 ? "partial" : rnd() < 0.9 ? "live" : pick(["pending", "cancelled", "rejected"] as OrderStatus[]);
  const lots: Lot[] = [];
  let done = 0;
  while (done < cumQty) {
    const slice = Math.min(cumQty - done, Math.max(1, Math.floor(rnd() * 200)));
    lots.push({ ts: nowNs(), qty: slice, px: +(px + (rnd() - 0.5) * ref * 0.0004).toFixed(dp), liq: rnd() < 0.5 ? "A" : "R" });
    done += slice;
  }
  const avgPx = cumQty > 0 ? lots.reduce((s, l) => s + l.px * l.qty, 0) / cumQty : 0;
  const t = nowNs();
  return {
    clord: "0x" + (seq++).toString(16).padStart(12, "0"),
    sym, side, venue: pick(VENUES), px, qty, cumQty, leaves,
    avgPx: +avgPx.toFixed(dp), status, tif: pick(TIFS),
    tRcv: t - Math.floor(rnd() * 3e11), tLastUpd: t, subacct: 1 + Math.floor(rnd() * 3),
    lots, source: pick(SOURCES),
  };
}

export default function TradingBlotterPage() {
  const [orders, setOrders] = useState<Order[]>(() => Array.from({ length: 600 }, makeOrder));
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const clearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const id = setInterval(() => {
      setOrders((prev) => {
        const next = prev.slice();
        const t = new Set<string>();
        for (let k = 0; k < 24; k++) {
          const i = Math.floor(Math.random() * next.length);
          const o = { ...next[i], lots: next[i].lots.slice() };
          o.px = +(o.px * (1 + (Math.random() - 0.5) * 0.0006)).toFixed(2);
          o.tLastUpd = nowNs();
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

  const cancel = (clord: string) =>
    setOrders((prev) => prev.map((o) => (o.clord === clord ? { ...o, status: "cancelled", leaves: 0 } : o)));

  const live = useMemo(() => orders.filter((o) => o.status === "live" || o.status === "partial").length, [orders]);

  return (
    <div style={{ height: "calc(100vh - 3.5rem)", display: "flex", flexDirection: "column", padding: "0.75rem", gap: "0.5rem" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: "0.75rem" }}>
        <h1 style={{ fontSize: "1.1rem", fontWeight: 600 }}>Trading Blotter</h1>
        <span style={{ fontSize: "0.8rem", opacity: 0.6 }}>{orders.length} orders · {live} working · live</span>
        <span style={{ fontSize: "0.75rem", opacity: 0.5, marginLeft: "auto" }}>
          right-click a header to group / filter / choose columns · drag to reorder · layout persists
        </span>
      </div>
      <div style={{ flex: 1, minHeight: 0 }}>
        <Blotter data={orders} columns={orderColumns} touched={touched} storageKeyPrefix="tl-blotter" onCancel={cancel} />
      </div>
    </div>
  );
}
