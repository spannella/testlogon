// Working-orders MANAGEMENT surface — the caller's LIVE working orders read
// from the REAL GET /me/orders/live feed with per-row Amend (price/qty →
// PATCH /me/orders/{clordid}) and Cancel (DELETE /me/orders/{clordid}) plus a
// confirmed Cancel-all (POST /me/bulk_cancel). Prices/qty are int64 engine
// ticks scaled per-symbol via the /md/symbols catalog + the markets
// formatters. The /me/orders/live route MAY 404 until the exchange edge
// deploys it — this panel degrades gracefully (loading / unavailable / empty).
import { useMemo, useState } from "react";
import { useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { useOrdersLive, useAmendOrder, useCancelOrder, useBulkCancel } from "@/hooks/useTrading";
import type { LiveOrder } from "@/api/endpoints/trading";
import { ackMessage } from "@/api/endpoints/trading";
import { formatPrice, formatQty } from "@/pages/markets/format";

type SymLookup = (symbolid: number | undefined) => { name: string; scaler: number };
function makeSymLookup(symbols: MarketSymbol[] | undefined): SymLookup {
  const byId = new Map<number, MarketSymbol>();
  for (const s of symbols ?? []) byId.set(s.symbol_id, s);
  return (symbolid) => {
    const s = symbolid == null ? undefined : byId.get(symbolid);
    return { name: s?.symbol ?? (symbolid == null ? "—" : `#${symbolid}`), scaler: s?.price_scaler || 1 };
  };
}

const POS = "var(--pos)";
const NEG = "var(--neg)";
const isBuy = (side: string | undefined) => side === "buy" || side === "B" || side === "b";

/** Remaining (working) qty — prefer leaves, else qty − cum, else qty. */
function leavesOf(o: LiveOrder): number | undefined {
  if (o.leaves_qty != null && Number.isFinite(o.leaves_qty)) return o.leaves_qty;
  if (o.qty != null && o.cum_qty != null) return o.qty - o.cum_qty;
  return o.qty;
}

/** Stable-ish row key even when clordid is absent. */
const rowKey = (o: LiveOrder, i: number) => o.clordid ?? String(o.orderid ?? `row-${i}`);

interface RowProps {
  o: LiveOrder;
  sym: SymLookup;
  busy: boolean;
  onAmend: (clordid: string, symbolId: number, newQty: number, newPrice: number) => void;
  onCancel: (clordid: string, symbolId: number) => void;
}

function OrderRow({ o, sym, busy, onAmend, onCancel }: RowProps) {
  const { name, scaler } = sym(o.symbolid);
  const [editing, setEditing] = useState(false);
  const [px, setPx] = useState("");
  const [qty, setQty] = useState("");
  const canManage = !!o.clordid && o.symbolid != null;
  const leaves = leavesOf(o);

  const startEdit = () => {
    // Seed the edit fields with the current (scaled) values.
    setPx(o.price != null ? String(o.price / (scaler || 1)) : "");
    setQty(leaves != null ? String(leaves / (scaler || 1)) : "");
    setEditing(true);
  };
  const submit = () => {
    if (!o.clordid || o.symbolid == null) return;
    const sc = scaler || 1;
    const newQty = Math.round(Number(qty) * sc);
    const newPrice = Math.round(Number(px) * sc);
    if (!Number.isFinite(newQty) || newQty <= 0) return;
    onAmend(o.clordid, o.symbolid, newQty, Number.isFinite(newPrice) ? newPrice : (o.price ?? 0));
    setEditing(false);
  };

  return (
    <>
      <tr>
        <td className="sym">{name}</td>
        <td style={{ color: isBuy(o.side) ? POS : NEG, textTransform: "uppercase" }}>{String(o.side ?? "—")}</td>
        <td className="num">{formatPrice(o.price, scaler)}</td>
        <td className="num">{formatQty(o.qty, scaler)}</td>
        <td className="num">{leaves != null ? formatQty(leaves, scaler) : "—"}</td>
        <td className="dim">{String(o.tif ?? o.status ?? "")}</td>
        <td className="dim" style={{ fontFamily: "monospace", fontSize: "0.7rem" }}>{o.clordid ?? "—"}</td>
        <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
          <button type="button" className="tl-wo-btn" disabled={!canManage || busy} onClick={startEdit}>Amend</button>
          <button type="button" className="tl-wo-btn danger" disabled={!canManage || busy}
            onClick={() => o.clordid && o.symbolid != null && onCancel(o.clordid, o.symbolid)}>Cancel</button>
        </td>
      </tr>
      {editing && (
        <tr className="tl-wo-edit">
          <td colSpan={8}>
            <div className="tl-wo-editrow">
              <span className="dim">Amend {name}</span>
              <label>Price<input value={px} onChange={(e) => setPx(e.target.value)} inputMode="decimal" /></label>
              <label>Qty<input value={qty} onChange={(e) => setQty(e.target.value)} inputMode="decimal" /></label>
              <button type="button" className="tl-wo-btn accent" disabled={busy} onClick={submit}>Apply</button>
              <button type="button" className="tl-wo-btn" onClick={() => setEditing(false)}>Close</button>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function WorkingOrdersPanel() {
  const symbolsQuery = useSymbols();
  const sym = useMemo(() => makeSymLookup(symbolsQuery.data?.symbols), [symbolsQuery.data]);
  const q = useOrdersLive();
  const amend = useAmendOrder();
  const cancel = useCancelOrder();
  const bulk = useBulkCancel();
  const [confirming, setConfirming] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const orders: LiveOrder[] = Array.isArray(q.data?.orders) ? q.data!.orders! : [];
  const busy = amend.isPending || cancel.isPending || bulk.isPending;

  const onAmend = (clordid: string, symbolId: number, newQty: number, newPrice: number) => {
    setNote(null);
    amend.mutate(
      { clordid, body: { new_qty: newQty, new_price: newPrice, symbolid: symbolId } },
      {
        onSuccess: (ack) => { setNote(ackMessage(ack) ?? `Amended ${clordid}`); void q.refetch(); },
        onError: (e: unknown) => setNote((e as Error)?.message ?? "Amend failed"),
      },
    );
  };
  const onCancel = (clordid: string, symbolId: number) => {
    setNote(null);
    cancel.mutate(
      { clordid, symbolId },
      {
        onSuccess: (ack) => { setNote(ackMessage(ack) ?? `Cancelled ${clordid}`); void q.refetch(); },
        onError: (e: unknown) => setNote((e as Error)?.message ?? "Cancel failed"),
      },
    );
  };
  const doCancelAll = () => {
    setConfirming(false);
    setNote(null);
    bulk.mutate(undefined, {
      onSuccess: (ack) => { setNote(ack?.cancelled_count != null ? `Cancelled ${ack.cancelled_count} order(s)` : "Cancel-all sent"); void q.refetch(); },
      onError: (e: unknown) => setNote((e as Error)?.message ?? "Cancel-all failed"),
    });
  };

  return (
    <div className="tl-panel-body tl-wo">
      <div className="tl-wo-bar">
        <span className="dim">{orders.length} working order{orders.length === 1 ? "" : "s"}</span>
        <span style={{ flex: 1 }} />
        {q.isFetching && <span className="dim" style={{ fontSize: "0.7rem" }}>refreshing…</span>}
        {!confirming ? (
          <button type="button" className="tl-wo-btn danger" disabled={busy || orders.length === 0} onClick={() => setConfirming(true)}>Cancel all</button>
        ) : (
          <span className="tl-wo-confirm">
            Cancel ALL working orders?
            <button type="button" className="tl-wo-btn danger" disabled={busy} onClick={doCancelAll}>Yes, cancel all</button>
            <button type="button" className="tl-wo-btn" onClick={() => setConfirming(false)}>No</button>
          </span>
        )}
      </div>
      {note && <div className="tl-wo-note">{note}</div>}
      <div className="tl-wo-scroll">
        <table className="tl-wo-table">
          <thead>
            <tr>
              <th>Sym</th><th>Side</th><th>Price</th><th>Qty</th><th>Leaves</th>
              <th>TIF</th><th>ClOrdID</th><th style={{ textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {orders.map((o, i) => (
              <OrderRow key={rowKey(o, i)} o={o} sym={sym} busy={busy} onAmend={onAmend} onCancel={onCancel} />
            ))}
          </tbody>
        </table>
        {q.isLoading ? <div className="tl-wo-empty">Loading working orders…</div>
          : q.isError ? <div className="tl-wo-empty">Working-orders feed (/me/orders/live) not available on this backend yet.</div>
          : orders.length === 0 ? <div className="tl-wo-empty">No working orders.</div> : null}
      </div>
    </div>
  );
}
