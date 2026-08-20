// Trade History — a view of the caller's EXECUTED fills read from the REAL
// GET /me/fills/fees feed: symbol / side / price / qty / liquidity (maker
// vs taker) / the engine-charged fee / time. price / qty / fee are int64
// engine ticks scaled per-symbol via the /md/symbols catalog + the markets
// formatters; `ts` is seconds-or-ms (detected). The route MAY 404 until the
// exchange edge deploys it — this panel degrades gracefully.
import { useMemo } from "react";
import { useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { useFillsFees } from "@/hooks/useTrading";
import type { FillFee } from "@/api/endpoints/trading";
import { formatPrice, formatQty } from "@/pages/markets/format";
import { buildTradeHistoryCsv, downloadCsv, type ReportFill } from "@/lib/exportReport";

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

// `ts` may be seconds or ms — below ~year-2001-in-ms treat as seconds.
const MS_THRESHOLD = 1e12;
function formatFeedTime(ts: number | undefined): string {
  if (ts == null || !Number.isFinite(ts)) return "—";
  const ms = ts < MS_THRESHOLD ? ts * 1000 : ts;
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const rowKey = (f: FillFee, i: number) => `${f.symbolid}:${f.ts}:${f.price}:${f.qty}:${f.side}:${i}`;

export default function TradeHistoryPanel() {
  const symbolsQuery = useSymbols();
  const sym = useMemo(() => makeSymLookup(symbolsQuery.data?.symbols), [symbolsQuery.data]);
  const q = useFillsFees();
  const fills: FillFee[] = Array.isArray(q.data?.fills) ? q.data!.fills! : [];

  const exportCsv = () => {
    const rows: ReportFill[] = fills.map((f) => ({
      symbolid: f.symbolid,
      price: f.price,
      qty: f.qty,
      side: String(f.side ?? ""),
      liquidity: f.liquidity,
      fee: f.fee,
      ts: f.ts,
    }));
    downloadCsv(
      "testlogon-trades.csv",
      buildTradeHistoryCsv(rows, (id) => sym(id)),
    );
  };

  return (
    <div className="tl-panel-body tl-wo">
      <div className="tl-wo-bar">
        <span className="dim">{fills.length} executed fill{fills.length === 1 ? "" : "s"}</span>
        <span style={{ flex: 1 }} />
        {q.isFetching && <span className="dim" style={{ fontSize: "0.7rem" }}>refreshing…</span>}
        <button
          type="button"
          className="tl-wo-btn"
          onClick={exportCsv}
          disabled={fills.length === 0}
          title="Export trade history to CSV"
          style={{
            marginLeft: "0.5rem",
            fontSize: "0.7rem",
            cursor: fills.length === 0 ? "default" : "pointer",
            opacity: fills.length === 0 ? 0.5 : 1,
          }}
        >
          Export CSV
        </button>
      </div>
      <div className="tl-wo-scroll">
        <table className="tl-wo-table">
          <thead>
            <tr>
              <th>Sym</th><th>Side</th><th>Price</th><th>Qty</th><th>Liq</th><th>Fee</th><th>Time</th>
            </tr>
          </thead>
          <tbody>
            {fills.map((f, i) => {
              const { name, scaler } = sym(f.symbolid);
              return (
                <tr key={rowKey(f, i)}>
                  <td className="sym">{name}</td>
                  <td style={{ color: isBuy(f.side) ? POS : NEG, textTransform: "uppercase" }}>{String(f.side ?? "—")}</td>
                  <td className="num">{formatPrice(f.price, scaler)}</td>
                  <td className="num">{formatQty(f.qty, scaler)}</td>
                  <td className="dim" style={{ textTransform: "capitalize" }}>{String(f.liquidity ?? "")}</td>
                  <td className="num">{formatQty(f.fee, scaler)}</td>
                  <td className="num dim">{formatFeedTime(f.ts)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {q.isLoading ? <div className="tl-wo-empty">Loading trade history…</div>
          : q.isError ? <div className="tl-wo-empty">Trade-history feed (/me/fills/fees) not available on this backend yet.</div>
          : fills.length === 0 ? <div className="tl-wo-empty">No executed fills yet.</div> : null}
      </div>
    </div>
  );
}
