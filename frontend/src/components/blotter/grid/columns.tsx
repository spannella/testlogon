// Column definitions.  Each column advertises its filter kind via
// `meta.filterKind` so the header dropdown can render the right UI
// (text / numeric range / multi-select for enums).

import type { ColumnDef, FilterFn } from '@tanstack/react-table';
import type { Order, Lot } from '../types';
import { TableTooltip } from '../tooltip/TableTooltip';
import { EditableCell, DateEditableCell } from './EditableCell';

// --------- meta typing so TS narrows correctly on filterKind lookups ---------
declare module '@tanstack/react-table' {
  interface ColumnMeta<TData extends unknown, TValue> {
    filterKind?: 'text' | 'num' | 'enum' | 'date';
    enumValues?: string[];
    hint?: string;
    editable?: 'px' | 'qty' | 'date';
    // When grouping a numeric column, values are bucketed by this size so
    // rows near each other collapse into one "68.80 – 68.90" group instead
    // of a separate group per unique price.
    numBucket?: number;
    // For date-typed columns: bucket by 'minute' | 'hour' | 'day' when grouped.
    dateBucket?: 'minute' | 'hour' | 'day';
    // Column is present in the def but hidden on first render — the user
    // can turn it on via the column chooser. Only consulted when the
    // Blotter's persisted visibility state is empty.
    defaultHidden?: boolean;
  }
}

// Bucket a number into "lo – hi" range string.  0.1 bucket, value 68.847
// → lo=68.80, hi=68.90 → "68.80 – 68.90".  Stable string works as a
// grouping key that TanStack can hash.
function numRangeKey(v: number, bucket: number, digits: number): string {
  if (v == null || Number.isNaN(v)) return '(empty)';
  const lo = Math.floor(v / bucket) * bucket;
  const hi = lo + bucket;
  return `${lo.toFixed(digits)} – ${hi.toFixed(digits)}`;
}
// Same idea for timestamps (ns).  Bucket size 'minute' | 'hour' | 'day'.
function dateRangeKey(ns: number, bucket: 'minute' | 'hour' | 'day'): string {
  if (ns == null) return '(empty)';
  const ms = ns / 1_000_000;
  const d = new Date(ms);
  const yr = d.getUTCFullYear();
  const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  if (bucket === 'day') return `${yr}-${mo}-${dd}`;
  const hh = String(d.getUTCHours()).padStart(2, '0');
  if (bucket === 'hour') return `${yr}-${mo}-${dd} ${hh}:00 UTC`;
  const mm = String(Math.floor(d.getUTCMinutes())).padStart(2, '0');
  return `${yr}-${mo}-${dd} ${hh}:${mm} UTC`;
}

// ---------- filter functions ----------

// Text: {op: 'contains'|'equals'|'startsWith'|'endsWith'|'neq', val: string}
export const textFilter: FilterFn<Order> = (row, colId, filterVal) => {
  if (!filterVal) return true;
  const { op, val } = filterVal as { op: string; val: string };
  if (!val) return true;
  const cell = String(row.getValue(colId) ?? '').toLowerCase();
  const q = val.toLowerCase();
  switch (op) {
    case 'equals':     return cell === q;
    case 'startsWith': return cell.startsWith(q);
    case 'endsWith':   return cell.endsWith(q);
    case 'neq':        return !cell.includes(q);
    default:           return cell.includes(q);   // contains
  }
};

// Numeric: {op: 'eq'|'neq'|'gt'|'gte'|'lt'|'lte'|'between', val: number, val2?: number}
export const numFilter: FilterFn<Order> = (row, colId, filterVal) => {
  if (!filterVal) return true;
  const { op, val, val2 } = filterVal as { op: string; val?: number; val2?: number };
  if (val == null || Number.isNaN(val)) return true;
  const n = row.getValue<number>(colId);
  if (n == null || Number.isNaN(n)) return false;
  switch (op) {
    case 'eq':      return n === val;
    case 'neq':     return n !== val;
    case 'gt':      return n > val;
    case 'gte':     return n >= val;
    case 'lt':      return n < val;
    case 'lte':     return n <= val;
    case 'between': return val2 != null && n >= Math.min(val, val2) && n <= Math.max(val, val2);
    default:        return true;
  }
};

// Enum: Set<string> — accept row iff its value is IN the picked set (empty = accept all).
export const enumFilter: FilterFn<Order> = (row, colId, filterVal) => {
  const set = filterVal as Set<string> | null;
  if (!set || set.size === 0) return true;
  const v = String(row.getValue(colId));
  return set.has(v);
};

// ---------- formatting helpers ----------
function fmtPx(n: number) { return n.toFixed(2); }
function fmtQty(n: number) { return n.toLocaleString(); }
function fmtTs(ns: number) { return new Date(ns / 1_000_000).toISOString().slice(11, 23); }
function ageMs(ns: number) { return Math.max(0, Date.now() - ns / 1_000_000); }
function fmtAge(ns: number): string {
  const ms = ageMs(ns);
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

// ---------- tooltip content components ----------

// Fill-quality tooltip content. Same information as the DetailRow
// analytics band but formatted for the compact hover popover so users
// don't have to click ▸ to see per-fill lineage / edge / liquidity.
function FillAnalyticsTip({ order }: { order: Order }) {
  const srcLabel = order.source === 'QUOT' ? 'ETF Quote'
                 : order.source === 'HDGE' ? 'Hedge'
                 : order.source === 'VWAP' ? 'VWAP'
                 : order.source === 'MANL' ? 'Manual'
                 : order.source || '—';
  // Venue-specific liquidity letters. Nasdaq OUCH5's Order Executed
  // message encodes ~40 codes — we surface the common ones. Each
  // label is "<letter> · <what it means>" so a hover on any of them
  // is self-explanatory without needing to know the venue spec.
  const liqLabel = order.liq === 'A' ? 'A · Added (maker)'
                 : order.liq === 'R' ? 'R · Removed (taker)'
                 : order.liq === 'H' ? 'H · Hidden Added'
                 : order.liq === 'C' ? 'C · Removed Hidden'
                 : order.liq === 'e' ? 'e · Added at Midpoint'
                 : order.liq === 'f' ? 'f · Removed at Midpoint'
                 : order.liq === 'M' ? 'M · Midpoint Match'
                 : order.liq === 'k' ? 'k · Set displayed BBO'
                 : order.liq === 'L' ? 'L · Added at NBBO'
                 : order.liq === 'J' ? 'J · Retail Added'
                 : order.liq === 'j' ? 'j · Retail Removed'
                 : order.liq === 'D' ? 'D · Displayed Added'
                 : order.liq === 'S' ? 'S · Subscribed (Pillar)'
                 : order.liq === 'K' ? 'K · Retail Added (Pillar)'
                 : order.liq === 'U' ? 'U · Unspecified'
                 : order.liq === 'O' ? 'O · Other'
                 : order.liq        ? `${order.liq} · (venue-specific)`
                 : '—';
  const fmt = (v: number | undefined, dp = 4) =>
      v != null && Number.isFinite(v) ? v.toFixed(dp) : '–';
  const fmtSigned = (v: number | undefined, dp = 3) =>
      v != null && Number.isFinite(v)
          ? `${v >= 0 ? '+' : ''}${v.toFixed(dp)}`
          : '–';
  const edgeCls = (v: number | undefined) =>
      v == null || !Number.isFinite(v) ? 'dim'
      : v > 0.001 ? 'pos' : v < -0.001 ? 'neg' : 'dim';
  const isHedge = order.source === 'HDGE';
  return (
    <div className="tooltip-analytics">
      <div className="tooltip-hdr">
        {srcLabel} · {order.sym || '—'} · {order.side === 'B' ? 'BUY' : 'SELL'} @ {fmt(order.px, 4)}
      </div>
      <table className="tooltip-tbl tt-kv">
        <tbody>
          <tr><td>acct</td><td className="num">{order.subacct ?? '—'}</td></tr>
          <tr><td>liq</td><td>{liqLabel}</td></tr>
          <tr><td>fair @ place</td><td className="num">{fmt(order.fairAtPlace)}</td></tr>
          <tr>
            <td>Δ vs place</td>
            <td className={`num ${edgeCls(order.edgeToPlace)}`}>{fmtSigned(order.edgeToPlace)}</td>
          </tr>
          <tr><td>fair @ exec</td><td className="num">{fmt(order.fairAtExec)}</td></tr>
          <tr>
            <td>Δ vs exec</td>
            <td className={`num ${edgeCls(order.edgeToExec)}`}>{fmtSigned(order.edgeToExec)}</td>
          </tr>
          {isHedge && (
            <>
              <tr><td>link exec</td>
                  <td className="mono dim">{order.linkExecid ? order.linkExecid.slice(-10) : '—'}</td></tr>
              <tr><td>implied @ quoter</td><td className="num">{fmt(order.impliedPx)}</td></tr>
              <tr>
                <td>slip</td>
                <td className={`num ${order.slipBp == null || !Number.isFinite(order.slipBp) ? 'dim' : order.slipBp > 0.5 ? 'pos' : order.slipBp < -0.5 ? 'neg' : 'dim'}`}>
                  {order.slipBp != null && Number.isFinite(order.slipBp)
                      ? `${order.slipBp >= 0 ? '+' : ''}${order.slipBp.toFixed(1)} bp`
                      : '–'}
                </td>
              </tr>
            </>
          )}
        </tbody>
      </table>
    </div>
  );
}

function LotTable({ lots, orderPx }: { lots: Lot[]; orderPx: number }) {
  if (!lots.length) return <div className="tooltip-empty">No fills yet</div>;
  const total = lots.reduce((s, l) => s + l.qty, 0);
  const vwap = lots.reduce((s, l) => s + l.px * l.qty, 0) / total;
  return (
    <table className="tooltip-tbl">
      <thead><tr><th>time</th><th>qty</th><th>px</th><th>edge</th><th>liq</th></tr></thead>
      <tbody>
        {lots.slice(-10).map((l, i) => {
          const edge = l.px - orderPx;
          return (
            <tr key={i}>
              <td>{fmtTs(l.ts)}</td>
              <td className="num">{fmtQty(l.qty)}</td>
              <td className="num">{fmtPx(l.px)}</td>
              <td className={`num ${edge >= 0 ? 'pos' : 'neg'}`}>{edge >= 0 ? '+' : ''}{edge.toFixed(3)}</td>
              <td>{l.liq}</td>
            </tr>
          );
        })}
      </tbody>
      <tfoot>
        <tr>
          <td>vwap</td>
          <td className="num">{fmtQty(total)}</td>
          <td className="num">{fmtPx(vwap)}</td>
          <td className="num">{lots.length} lots</td>
          <td></td>
        </tr>
      </tfoot>
    </table>
  );
}

function StatusBadge({ status, reason }: { status: string; reason?: string }) {
  const cls = `badge badge-${status}`;
  if (status === 'rejected' && reason) {
    return (
      <TableTooltip
        content={
          <div className="tooltip-reject">
            <div className="tooltip-hdr">Rejected</div>
            <div className="tooltip-body">{reason}</div>
          </div>
        }
      >
        <span className={cls}>{status}</span>
      </TableTooltip>
    );
  }
  return <span className={cls}>{status}</span>;
}

export const orderColumns: ColumnDef<Order>[] = [
  {
    id: 'clord', header: 'ClOrd', accessorKey: 'clord',
    size: 130, enableSorting: false, enableGrouping: false,
    filterFn: textFilter,
    meta: { filterKind: 'text' },
    cell: info => <span className="mono dim">{info.getValue<string>().slice(-8)}</span>,
  },
  {
    id: 'sym', header: 'Sym', accessorKey: 'sym', size: 60,
    filterFn: enumFilter,
    meta: { filterKind: 'enum' },
    cell: info => <span className="sym">{info.getValue<string>()}</span>,
    aggregatedCell: ({ getValue }) => <span className="sym">{String(getValue() ?? '')}</span>,
  },
  {
    id: 'side', header: 'S', accessorKey: 'side', size: 32,
    filterFn: enumFilter,
    meta: { filterKind: 'enum', enumValues: ['B', 'S'] },
    cell: info => {
      const s = info.getValue<string>();
      return <span className={`side side-${s}`}>{s}</span>;
    },
  },
  {
    id: 'venue', header: 'Venue', accessorKey: 'venue', size: 68,
    filterFn: enumFilter,
    meta: { filterKind: 'enum' },
  },
  {
    id: 'px', header: 'Px', accessorKey: 'px', size: 78,
    filterFn: numFilter,
    meta: { filterKind: 'num', editable: 'px', numBucket: 0.10 },
    getGroupingValue: row => numRangeKey(row.px, 0.10, 2),
    cell: info => (
      <EditableCell
        value={info.getValue<number>()}
        rowId={info.row.original.clord}
        colId="px"
        canEdit={info.row.original.status === 'live' || info.row.original.status === 'partial'}
        format={fmtPx}
        parse={(s) => {
          const v = parseFloat(s);
          return isNaN(v) ? null : v;
        }}
      />
    ),
    aggregatedCell: ({ getValue }) => <span className="num dim">{String(getValue() ?? '')}</span>,
  },
  {
    id: 'qty', header: 'Qty', accessorKey: 'qty', size: 68,
    filterFn: numFilter,
    meta: { filterKind: 'num', editable: 'qty', numBucket: 100 },
    getGroupingValue: row => numRangeKey(row.qty, 100, 0),
    cell: info => (
      <EditableCell
        value={info.getValue<number>()}
        rowId={info.row.original.clord}
        colId="qty"
        canEdit={info.row.original.status === 'live' || info.row.original.status === 'partial'}
        format={fmtQty}
        parse={(s) => {
          const v = parseInt(s.replace(/,/g, ''), 10);
          return isNaN(v) || v <= 0 ? null : v;
        }}
      />
    ),
    aggregatedCell: ({ getValue }) => <span className="num dim">{String(getValue() ?? '')}</span>,
  },
  {
    id: 'cumQty', header: 'Cum', accessorKey: 'cumQty', size: 70,
    filterFn: numFilter,
    meta: { filterKind: 'num', numBucket: 100 },
    getGroupingValue: row => numRangeKey(row.cumQty, 100, 0),
    cell: info => {
      const row = info.row.original;
      return (
        <TableTooltip content={<LotTable lots={row.lots} orderPx={row.px} />}>
          <span className={`num ${row.cumQty > 0 ? 'accent' : 'dim'}`}>
            {fmtQty(row.cumQty)}
          </span>
        </TableTooltip>
      );
    },
  },
  {
    id: 'leaves', header: 'Lvs', accessorKey: 'leaves', size: 68,
    filterFn: numFilter,
    meta: { filterKind: 'num', numBucket: 100 },
    getGroupingValue: row => numRangeKey(row.leaves, 100, 0),
    cell: info => <span className="num dim">{fmtQty(info.getValue<number>())}</span>,
    aggregatedCell: ({ getValue }) => <span className="num dim">{String(getValue() ?? '')}</span>,
  },
  {
    id: 'avgPx', header: 'Avg', accessorKey: 'avgPx', size: 78,
    filterFn: numFilter,
    meta: { filterKind: 'num', numBucket: 0.10 },
    getGroupingValue: row => numRangeKey(row.avgPx, 0.10, 2),
    cell: info => {
      const v = info.getValue<number>();
      return <span className="num">{v > 0 ? fmtPx(v) : '–'}</span>;
    },
    aggregatedCell: ({ getValue }) => <span className="num dim">{String(getValue() ?? '')}</span>,
  },
  {
    id: 'status', header: 'Status', accessorKey: 'status', size: 88,
    filterFn: enumFilter,
    meta: {
      filterKind: 'enum',
      enumValues: ['live', 'partial', 'filled', 'cancelled', 'rejected', 'pending'],
    },
    cell: info => (
      <StatusBadge
        status={info.getValue<string>()}
        reason={info.row.original.rejectReason}
      />
    ),
  },
  {
    id: 'tif', header: 'TIF', accessorKey: 'tif', size: 52,
    filterFn: enumFilter,
    meta: { filterKind: 'enum', enumValues: ['DAY', 'IOC', 'GTX', 'MOC'] },
    cell: info => <span className="dim">{info.getValue<string>()}</span>,
  },
  {
    id: 'tRcv', header: 'Received', accessorKey: 'tRcv', size: 130,
    filterFn: (row, colId, filterVal) => {
      if (!filterVal) return true;
      const { op, val, val2 } = filterVal as { op: string; val?: number; val2?: number };
      if (val == null || Number.isNaN(val)) return true;
      // Filter values are expressed as ms-since-epoch (from datetime-local).
      const ns = row.getValue<number>(colId);
      const ms = ns / 1_000_000;
      const v  = val * 1000;                     // sec → ms if val is unix-sec
      // Support both: if val looks like seconds (small), treat as unix-sec.
      // If val looks like ms already (huge), use as-is.
      const cmp = val > 1e11 ? val : v;
      const cmp2 = val2 != null ? (val2 > 1e11 ? val2 : val2 * 1000) : undefined;
      switch (op) {
        case 'eq':      return Math.abs(ms - cmp) < 500;
        case 'neq':     return Math.abs(ms - cmp) >= 500;
        case 'gt':      return ms > cmp;
        case 'gte':     return ms >= cmp;
        case 'lt':      return ms < cmp;
        case 'lte':     return ms <= cmp;
        case 'between': return cmp2 != null && ms >= Math.min(cmp, cmp2) && ms <= Math.max(cmp, cmp2);
        default:        return true;
      }
    },
    meta: { filterKind: 'date', editable: 'date', dateBucket: 'minute' },
    // Group by minute so all orders received in the same wall-clock minute
    // collapse together — cleaner than a group per unique nanosecond.
    getGroupingValue: row => dateRangeKey(row.tRcv, 'minute'),
    cell: info => (
      <DateEditableCell
        ns={info.getValue<number>()}
        rowId={info.row.original.clord}
        colId="tRcv"
        canEdit={info.row.original.status === 'live' || info.row.original.status === 'pending'}
      />
    ),
    aggregatedCell: ({ getValue }) => <span className="mono dim">{String(getValue() ?? '')}</span>,
  },
  {
    id: 'tLastUpd', header: 'Age', accessorKey: 'tLastUpd', size: 68,
    enableGrouping: false,
    // Age filter is numeric — operates in SECONDS of age; the tLastUpd
    // value in the row is nanoseconds since epoch, so we translate to
    // (now - tLastUpd)/1e9 before applying the op.  Comparison direction
    // is intuitive: "> 60" means "older than 60s".
    filterFn: (row, colId, filterVal) => {
      if (!filterVal) return true;
      const { op, val, val2 } = filterVal as { op: string; val?: number; val2?: number };
      if (val == null || Number.isNaN(val)) return true;
      const ns = row.getValue<number>(colId);
      const ageSec = Math.max(0, Date.now() - ns / 1_000_000) / 1000;
      switch (op) {
        case 'eq':      return Math.abs(ageSec - val) < 0.5;
        case 'neq':     return Math.abs(ageSec - val) >= 0.5;
        case 'gt':      return ageSec > val;
        case 'gte':     return ageSec >= val;
        case 'lt':      return ageSec < val;
        case 'lte':     return ageSec <= val;
        case 'between': return val2 != null && ageSec >= Math.min(val, val2) && ageSec <= Math.max(val, val2);
        default:        return true;
      }
    },
    meta: { filterKind: 'num', hint: 'age in seconds' },
    cell: info => {
      const ns = info.getValue<number>();
      return (
        <TableTooltip
          content={
            <div className="tooltip-ts">
              <div className="tooltip-hdr">Timestamps</div>
              <table className="tooltip-tbl">
                <tbody>
                  <tr><td>received</td><td className="mono">{fmtTs(info.row.original.tRcv)}</td></tr>
                  <tr><td>last update</td><td className="mono">{fmtTs(ns)}</td></tr>
                  <tr><td>age</td><td className="mono">{fmtAge(ns)}</td></tr>
                </tbody>
              </table>
            </div>
          }
        >
          <span className="num dim">{fmtAge(ns)}</span>
        </TableTooltip>
      );
    },
  },
  {
    // Fill source — surfaced from corso_etf_fill.feecode; distinguishes
    // ETF quoter/drainer (QUOT), hedger (HDGE), and future VWAP/manual
    // (VWAP/MANL) fill lineage in the Fills blotter.
    //
    // Hovering the pill opens a full fill-quality tooltip (same content
    // as the row-expand DetailRow analytics band). This is the "hover
    // shortcut" — no click required.
    id: 'source', header: 'Source', accessorKey: 'source', size: 74,
    enableGrouping: true,
    filterFn: enumFilter, meta: { filterKind: 'enum' },
    cell: info => {
      const row = info.row.original;
      const v = (row.source ?? '').toUpperCase();
      const label = v === 'QUOT' ? 'ETF Quote'
                  : v === 'HDGE' ? 'Hedge'
                  : v === 'VWAP' ? 'VWAP'
                  : v === 'MANL' ? 'Manual'
                  : v ? v : '—';
      const cls = v === 'QUOT' ? 'src-quot'
                : v === 'HDGE' ? 'src-hdge'
                : v === 'VWAP' ? 'src-vwap'
                : v === 'MANL' ? 'src-manl'
                : 'src-none';
      return (
        <TableTooltip content={<FillAnalyticsTip order={row} />}>
          <span className={`src-pill ${cls}`}>{label}</span>
        </TableTooltip>
      );
    },
  },
  {
    // Boerboel sub-account posting this fill/order.  Wired from
    // corso_etf_fill.subaccount; 0 for legacy/unset rows.
    id: 'subacct', header: 'Acct', accessorKey: 'subacct', size: 52,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => <span className="num dim">{info.getValue<number>() ?? '—'}</span>,
  },
  {
    // Fair-value snapshot at order-send time. 0/undefined for paths
    // that don't call record_fair_at_place (aggress, auction, replace).
    id: 'fairAtPlace', header: 'FairPlace', accessorKey: 'fairAtPlace', size: 78,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => {
      const v = info.getValue<number | undefined>();
      return <span className="num dim">{v && v > 0 ? fmtPx(v) : '—'}</span>;
    },
  },
  {
    // Fair-value at exec time — pb.last_prim_mark for QUOT,
    // pb.last_hedge_mark for HDGE. Compare against fill_price to see
    // how far our fill was from the model's fair.
    id: 'fairAtExec', header: 'FairExec', accessorKey: 'fairAtExec', size: 78,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => {
      const v = info.getValue<number | undefined>();
      return <span className="num dim">{v && v > 0 ? fmtPx(v) : '—'}</span>;
    },
  },
  {
    // Raw liquidity letter from the venue: A/R/H/U/O ('A'=Added,
    // 'R'=Removed, 'H'=HiddenAdded, 'U'=Unspecified, 'O'=Other).
    // Blank for legacy fills where the venue didn't report it.
    id: 'liq', header: 'Liq', accessorKey: 'liq', size: 42,
    filterFn: enumFilter, meta: { filterKind: 'enum' },
    cell: info => {
      const v = info.getValue<string | undefined>();
      if (!v) return <span className="dim">—</span>;
      // Group letters into add / remove / mid for colour but keep the
      // raw char in the pill so users see what the venue emitted.
      const isAdd = v === 'A' || v === 'H' || v === 'k' || v === 'L'
                 || v === 'D' || v === 'J' || v === 'S' || v === 'K';
      const isRem = v === 'R' || v === 'C' || v === 'j';
      const isMid = v === 'e' || v === 'f' || v === 'M';
      const cls = isAdd ? 'liq-add' : isRem ? 'liq-rem'
                : isMid ? 'liq-mid' : 'liq-other';
      return <span className={`liq-pill ${cls}`}>{v}</span>;
    },
  },
  {
    // Hedge lineage — for HDGE rows, the quoter execid that produced
    // the residual we're unwinding.  Blank for QUOT/other.
    id: 'linkExecid', header: 'LinkExec', accessorKey: 'linkExecid', size: 110,
    filterFn: textFilter, meta: { filterKind: 'text' }, enableSorting: false,
    cell: info => {
      const v = info.getValue<string | undefined>();
      return <span className="mono dim">{v ? v.slice(-8) : '—'}</span>;
    },
  },
  {
    // Implied hedge price at the moment the linked quoter fill booked
    // (= pb.last_hedge_mark then). HDGE fills only.
    id: 'impliedPx', header: 'ImpliedPx', accessorKey: 'impliedPx', size: 80,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => {
      const v = info.getValue<number | undefined>();
      return <span className="num dim">{v && v > 0 ? fmtPx(v) : '—'}</span>;
    },
  },
  {
    // Side-aware slippage in bps. + = favourable (better than the
    // implied hedge price at trigger time), − = adverse.
    id: 'slipBp', header: 'Slip bp', accessorKey: 'slipBp', size: 72,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => {
      const v = info.getValue<number | undefined>();
      if (v == null || !Number.isFinite(v)) return <span className="dim">—</span>;
      const cls = v > 0.5 ? 'pos' : v < -0.5 ? 'neg' : 'dim';
      return <span className={`num ${cls}`}>{v >= 0 ? '+' : ''}{v.toFixed(1)}</span>;
    },
  },
  {
    // Side-aware edge vs fair@place. + = favourable capture.
    id: 'edgeToPlace', header: 'Δ Place', accessorKey: 'edgeToPlace', size: 74,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => {
      const v = info.getValue<number | undefined>();
      if (v == null || !Number.isFinite(v)) return <span className="dim">—</span>;
      const cls = v > 0.001 ? 'pos' : v < -0.001 ? 'neg' : 'dim';
      return <span className={`num ${cls}`}>{v >= 0 ? '+' : ''}{v.toFixed(3)}</span>;
    },
  },
  {
    // Side-aware edge vs fair@exec. + = favourable capture. Hover opens
    // the full fill-quality tooltip (same content as the Source column
    // hover / row-expand DetailRow).
    id: 'edgeToExec', header: 'Δ Exec', accessorKey: 'edgeToExec', size: 74,
    filterFn: numFilter, meta: { filterKind: 'num' },
    cell: info => {
      const v = info.getValue<number | undefined>();
      const cls = v == null || !Number.isFinite(v) ? 'dim'
                : v > 0.001 ? 'pos'
                : v < -0.001 ? 'neg' : 'dim';
      const body = v == null || !Number.isFinite(v)
          ? <span className="dim">—</span>
          : <span className={`num ${cls}`}>{v >= 0 ? '+' : ''}{v.toFixed(3)}</span>;
      return (
        <TableTooltip content={<FillAnalyticsTip order={info.row.original} />}>
          {body}
        </TableTooltip>
      );
    },
  },
];
