// Compute the ideal pixel width for a column by measuring header + up
// to N filtered rows' rendered text with an offscreen canvas.  Doesn't
// depend on the DOM being populated — good for autofit-before-render.

import type { Column, Row } from '@tanstack/react-table';
import type { Order } from '../types';

// Reuse one canvas across measurements — cheap.
const _canvas = typeof document !== 'undefined' ? document.createElement('canvas') : null;
const _ctx = _canvas?.getContext('2d') ?? null;

function measure(font: string, s: string): number {
  if (!_ctx) return s.length * 7;   // SSR fallback
  _ctx.font = font;
  return _ctx.measureText(s).width;
}

// Match the rendered cell text.  Duplicates a subset of columns.tsx
// formatting — no way to invoke the column cell renderer without an
// actual React tree — but numeric/date columns are the ones that
// dominate width, and we handle them explicitly.
function textFor(col: Column<Order, unknown>, row: Row<Order>): string {
  const v = row.getValue(col.id);
  if (v == null) return '';
  switch (col.id) {
    case 'clord':    return String(v).slice(-8);
    case 'px':       return (v as number).toFixed(2);
    case 'avgPx':    return (v as number) > 0 ? (v as number).toFixed(2) : '–';
    case 'qty':
    case 'cumQty':
    case 'leaves':   return (v as number).toLocaleString();
    case 'tLastUpd': {
      const ms = Math.max(0, Date.now() - (v as number) / 1_000_000);
      if (ms < 1000) return `${ms.toFixed(0)}ms`;
      if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
      if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)}m`;
      return `${(ms / 3_600_000).toFixed(1)}h`;
    }
    case 'tRcv': {
      const d = new Date((v as number) / 1_000_000);
      const pad = (n: number) => String(n).padStart(2, '0');
      return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }
    default:         return String(v);
  }
}

const CELL_PAD = 18;   // px of chrome (padding + resizer clearance)
const MIN_WIDTH = 40;
const MAX_WIDTH = 320;
const HEAD_FONT = "500 12px ui-sans-serif, -apple-system, 'Segoe UI', 'Inter', sans-serif";
const CELL_FONT = "12px ui-monospace, 'SF Mono', Menlo, 'Roboto Mono', monospace";
const SAMPLE_MAX = 500;

export function autoFitColumn(col: Column<Order, unknown>, rows: Row<Order>[]): number {
  const header = String(col.columnDef.header ?? col.id);
  let w = measure(HEAD_FONT, header) + 20;   // extra room for sort ▲/▼ + funnel

  const n = Math.min(rows.length, SAMPLE_MAX);
  for (let i = 0; i < n; i++) {
    const t = textFor(col, rows[i]);
    if (!t) continue;
    const cw = measure(CELL_FONT, t);
    if (cw > w) w = cw;
  }
  return Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, Math.ceil(w + CELL_PAD)));
}

// Convenience: fit every visible column in one go.  Returns a
// TanStack-shaped { [colId]: pixels } map.
export function autoFitAll(cols: Column<Order, unknown>[], rows: Row<Order>[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const c of cols) out[c.id] = autoFitColumn(c, rows);
  return out;
}
