// Master-detail expansion row.  Shows a full lot-by-lot fills breakdown
// with per-lot P&L and a running cumulative fill line — the kind of
// thing DevExpress GridView does via master-detail templates.

import type { Order } from '../types';

function fmtTs(ns: number) {
  return new Date(ns / 1_000_000).toISOString().slice(11, 23);
}
function fmtNum(n: number) { return n.toLocaleString(); }

export function DetailRow({ order }: { order: Order }) {
  const { lots, px: orderPx, side, sym, qty, cumQty } = order;
  const signedSide = side === 'B' ? +1 : -1;
  let cumFilled = 0;
  const rows = lots.map((l, i) => {
    cumFilled += l.qty;
    const edge = (l.px - orderPx) * signedSide * -1; // + = better than limit
    const notional = l.px * l.qty;
    return { i, ts: l.ts, qty: l.qty, px: l.px, edge, liq: l.liq, notional, cumFilled };
  });
  const totalNotional = rows.reduce((s, r) => s + r.notional, 0);
  const vwap = cumQty > 0 ? totalNotional / cumQty : 0;
  const totalEdge = rows.reduce((s, r) => s + r.edge * r.qty, 0);

  // Fill-quality analytics chip. Only rendered when at least one of the
  // wire-side analytics fields is populated (i.e. this order came from
  // a corso_etf_fill, not a synthesised demo row).
  const hasAnalytics = order.source
      || order.fairAtPlace != null
      || order.fairAtExec != null
      || order.liq != null
      || order.linkExecid != null;
  const fmt = (v: number | undefined, dp = 4) =>
      v != null && Number.isFinite(v) ? v.toFixed(dp) : '–';
  const fmtSigned = (v: number | undefined, dp = 3) =>
      v != null && Number.isFinite(v)
          ? `${v >= 0 ? '+' : ''}${v.toFixed(dp)}`
          : '–';
  const srcLabel = (s?: string) => (s === 'QUOT' ? 'ETF Quote'
                                 : s === 'HDGE' ? 'Hedge'
                                 : s === 'VWAP' ? 'VWAP'
                                 : s === 'MANL' ? 'Manual'
                                 : s || '—');
  const liqLabel = (l?: string) => (l === 'A' ? 'A (Added)'
                                 : l === 'R' ? 'R (Removed)'
                                 : l === 'H' ? 'H (Hidden add)'
                                 : l === 'C' ? 'C (Took hidden)'
                                 : l === 'e' ? 'e (Add @ mid)'
                                 : l === 'f' ? 'f (Take @ mid)'
                                 : l === 'M' ? 'M (Midpoint match)'
                                 : l === 'k' ? 'k (Set BBO)'
                                 : l === 'L' ? 'L (Added @ NBBO)'
                                 : l === 'J' ? 'J (Retail add)'
                                 : l === 'j' ? 'j (Retail remove)'
                                 : l === 'D' ? 'D (Displayed add)'
                                 : l === 'S' ? 'S (Subscribed)'
                                 : l === 'K' ? 'K (Retail add)'
                                 : l === 'U' ? 'U (Unspec)'
                                 : l === 'O' ? 'O (Other)'
                                 : l         ? `${l} (venue-specific)`
                                 : '—');

  return (
    <div className="detail">
      <div className="detail-head">
        <span className="detail-title">{sym} · {side === 'B' ? 'BUY' : 'SELL'} · limit {orderPx.toFixed(2)}</span>
        <span className="detail-stat">lots <b>{lots.length}</b></span>
        <span className="detail-stat">filled <b>{fmtNum(cumQty)}</b> / {fmtNum(qty)}</span>
        <span className="detail-stat">vwap <b>{vwap ? vwap.toFixed(4) : '–'}</b></span>
        <span className="detail-stat">Σ notional <b>{fmtNum(Math.round(totalNotional))}</b></span>
        <span className={`detail-stat ${totalEdge >= 0 ? 'pos' : 'neg'}`}>
          Σ edge <b>{totalEdge >= 0 ? '+' : ''}{totalEdge.toFixed(2)}</b>
        </span>
      </div>
      {hasAnalytics && (
        <div className="detail-analytics">
          <span className="detail-stat">source <b>{srcLabel(order.source)}</b></span>
          <span className="detail-stat">acct <b>{order.subacct ?? '—'}</b></span>
          <span className="detail-stat">liq <b>{liqLabel(order.liq)}</b></span>
          <span className="detail-stat">
            fair@place <b>{fmt(order.fairAtPlace)}</b>
          </span>
          {order.edgeToPlace != null && Number.isFinite(order.edgeToPlace) && (
            <span className={`detail-stat ${order.edgeToPlace >= 0 ? 'pos' : 'neg'}`}>
              Δ vs place <b>{fmtSigned(order.edgeToPlace)}</b>
            </span>
          )}
          <span className="detail-stat">
            fair@exec <b>{fmt(order.fairAtExec)}</b>
          </span>
          {order.edgeToExec != null && Number.isFinite(order.edgeToExec) && (
            <span className={`detail-stat ${order.edgeToExec >= 0 ? 'pos' : 'neg'}`}>
              Δ vs exec <b>{fmtSigned(order.edgeToExec)}</b>
            </span>
          )}
          {order.source === 'HDGE' && (
            <>
              <span className="detail-stat">
                link exec <b className="mono">{order.linkExecid ? order.linkExecid.slice(-10) : '—'}</b>
              </span>
              <span className="detail-stat">
                implied@quoter <b>{fmt(order.impliedPx)}</b>
              </span>
              {order.slipBp != null && Number.isFinite(order.slipBp) && (
                <span className={`detail-stat ${order.slipBp >= 0 ? 'pos' : 'neg'}`}>
                  slip <b>{order.slipBp >= 0 ? '+' : ''}{order.slipBp.toFixed(1)} bp</b>
                </span>
              )}
            </>
          )}
        </div>
      )}
      {lots.length === 0 ? (
        <div className="detail-empty">No fills yet on this order.</div>
      ) : (
        <div className="detail-scroll">
          <table className="detail-tbl">
            <thead>
              <tr>
                <th style={{ width: 32 }}>#</th>
                <th style={{ width: 100 }}>time</th>
                <th style={{ width: 70 }} className="num">qty</th>
                <th style={{ width: 80 }} className="num">px</th>
                <th style={{ width: 80 }} className="num">edge</th>
                <th style={{ width: 100 }} className="num">notional</th>
                <th style={{ width: 100 }} className="num">cum filled</th>
                <th>liq</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.i}>
                  <td className="dim">{r.i + 1}</td>
                  <td className="mono">{fmtTs(r.ts)}</td>
                  <td className="num">{fmtNum(r.qty)}</td>
                  <td className="num">{r.px.toFixed(2)}</td>
                  <td className={`num ${r.edge >= 0 ? 'pos' : 'neg'}`}>
                    {r.edge >= 0 ? '+' : ''}{r.edge.toFixed(3)}
                  </td>
                  <td className="num dim">{fmtNum(Math.round(r.notional))}</td>
                  <td className="num dim">{fmtNum(r.cumFilled)}</td>
                  <td>
                    <span className={`liq-pill liq-${r.liq}`}>
                      {r.liq === 'A' ? 'add' : 'remove'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
