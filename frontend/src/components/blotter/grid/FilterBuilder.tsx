// DevExpress-style filter editor.  Shows every active column filter as
// a row of [column ▼] [operator ▼] [value].  Add / remove conditions,
// clear all.  v1 combines everything with AND (implicit — TanStack
// columnFilters are AND semantics anyway).  A future v2 can add OR
// groups by wrapping conditions in nested clauses.

import {
  useFloating, useClick, useDismiss, useInteractions, useRole,
  FloatingPortal, offset, flip, shift, autoUpdate,
} from '@floating-ui/react';
import { useState } from 'react';
import type { Table } from '@tanstack/react-table';
import type { Order } from '../types';

interface Props {
  table: Table<Order>;
  data: Order[];
}

const OPS_TEXT = [
  { k: 'contains',   label: 'contains' },
  { k: 'equals',     label: 'equals' },
  { k: 'startsWith', label: 'starts with' },
  { k: 'endsWith',   label: 'ends with' },
  { k: 'neq',        label: 'not contains' },
];
const OPS_NUM = [
  { k: 'eq', label: '=' }, { k: 'neq', label: '≠' },
  { k: 'gt', label: '>' }, { k: 'gte', label: '≥' },
  { k: 'lt', label: '<' }, { k: 'lte', label: '≤' },
  { k: 'between', label: 'between' },
];

export function FilterBuilder({ table, data }: Props) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open, onOpenChange: setOpen,
    placement: 'bottom-end',
    middleware: [offset(4), flip(), shift({ padding: 8 })],
    whileElementsMounted: autoUpdate,
  });
  const click = useClick(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'dialog' });
  const { getReferenceProps, getFloatingProps } = useInteractions([click, dismiss, role]);

  const filters = table.getState().columnFilters;
  const cols = table.getAllLeafColumns().filter(c => c.getCanFilter());

  const addCondition = () => {
    // Pick the first column that isn't already filtered.
    const already = new Set(filters.map(f => f.id));
    const c = cols.find(c => !already.has(c.id)) ?? cols[0];
    if (!c) return;
    const kind = c.columnDef.meta?.filterKind ?? 'text';
    const initial =
      kind === 'text' ? { op: 'contains', val: '' } :
      kind === 'num'  ? { op: 'gte', val: 0 } :
      kind === 'date' ? { op: 'gte', val: Date.now() - 3600_000 } :
      new Set<string>();
    c.setFilterValue(initial);
  };

  return (
    <>
      <button
        ref={refs.setReference}
        className={`hdr-ctrl-btn ${filters.length ? 'active' : ''}`}
        {...getReferenceProps()}
      >
        filter editor{filters.length ? <span className="chip-count">{filters.length}</span> : ''}
      </button>
      {open && (
        <FloatingPortal>
          <div ref={refs.setFloating} className="filter-builder" style={floatingStyles} {...getFloatingProps()}>
            <div className="col-menu-hdr">Filter editor</div>
            {filters.length === 0 && (
              <div className="ctx-item disabled" style={{ padding: '8px 6px' }}>
                No filters. Click <b>+ add condition</b> to start.
              </div>
            )}
            <div className="fb-list">
              {filters.map((f, i) => {
                const col = table.getColumn(f.id);
                if (!col) return null;
                const kind = col.columnDef.meta?.filterKind ?? 'text';
                return (
                  <div key={f.id} className="fb-row">
                    <span className="fb-and">{i === 0 ? 'WHERE' : 'AND'}</span>
                    <select
                      value={f.id}
                      onChange={e => {
                        const newColId = e.target.value;
                        // Move filter from old col to new col — clear old, seed new.
                        col.setFilterValue(undefined);
                        const nc = table.getColumn(newColId);
                        if (!nc) return;
                        const nkind = nc.columnDef.meta?.filterKind ?? 'text';
                        const seed =
                          nkind === 'text' ? { op: 'contains', val: '' } :
                          nkind === 'num'  ? { op: 'gte', val: 0 } :
                          nkind === 'date' ? { op: 'gte', val: Date.now() - 3600_000 } :
                          new Set<string>();
                        nc.setFilterValue(seed);
                      }}
                    >
                      {cols.map(c => (
                        <option key={c.id} value={c.id}>{String(c.columnDef.header)}</option>
                      ))}
                    </select>
                    {kind === 'text' && <TextCondition col={col} v={f.value as any} />}
                    {kind === 'num'  && <NumCondition  col={col} v={f.value as any} />}
                    {kind === 'date' && <NumCondition  col={col} v={f.value as any} dateMode />}
                    {kind === 'enum' && <EnumCondition col={col} v={f.value as any} data={data} />}
                    <button
                      className="fb-x"
                      onClick={() => col.setFilterValue(undefined)}
                    >×</button>
                  </div>
                );
              })}
            </div>
            <div className="col-menu-actions">
              <button className="primary" onClick={addCondition}>+ add condition</button>
              <button onClick={() => table.resetColumnFilters()} disabled={!filters.length}>clear all</button>
            </div>
          </div>
        </FloatingPortal>
      )}
    </>
  );
}

function TextCondition({ col, v }: { col: any; v: any }) {
  const cur = v ?? { op: 'contains', val: '' };
  return (
    <>
      <select value={cur.op} onChange={e => col.setFilterValue({ ...cur, op: e.target.value })}>
        {OPS_TEXT.map(o => <option key={o.k} value={o.k}>{o.label}</option>)}
      </select>
      <input
        type="text"
        value={cur.val ?? ''}
        onChange={e => col.setFilterValue({ ...cur, val: e.target.value })}
      />
    </>
  );
}

function NumCondition({ col, v, dateMode }: { col: any; v: any; dateMode?: boolean }) {
  const cur = v ?? { op: 'gte', val: 0 };
  return (
    <>
      <select value={cur.op} onChange={e => col.setFilterValue({ ...cur, op: e.target.value })}>
        {OPS_NUM.map(o => <option key={o.k} value={o.k}>{o.label}</option>)}
      </select>
      {dateMode ? (
        <input
          type="datetime-local"
          value={msToLocal(cur.val ?? Date.now())}
          onChange={e => col.setFilterValue({ ...cur, val: Date.parse(e.target.value) || 0 })}
        />
      ) : (
        <input
          type="number"
          value={cur.val ?? ''}
          onChange={e => col.setFilterValue({ ...cur, val: parseFloat(e.target.value) })}
        />
      )}
      {cur.op === 'between' && (dateMode ? (
        <input
          type="datetime-local"
          value={msToLocal(cur.val2 ?? Date.now())}
          onChange={e => col.setFilterValue({ ...cur, val2: Date.parse(e.target.value) || 0 })}
        />
      ) : (
        <input
          type="number"
          value={cur.val2 ?? ''}
          onChange={e => col.setFilterValue({ ...cur, val2: parseFloat(e.target.value) })}
        />
      ))}
    </>
  );
}

function EnumCondition({ col, v, data }: { col: any; v: any; data: Order[] }) {
  const declared = col.columnDef.meta?.enumValues as string[] | undefined;
  const values = declared ?? Array.from(new Set(data.map(r => String((r as any)[col.id])))).sort();
  const cur: Set<string> = (v as Set<string>) ?? new Set();
  const label = cur.size === 0 ? '(any)' :
    cur.size === 1 ? Array.from(cur)[0] :
    cur.size <= 3 ? Array.from(cur).join(', ') :
    `${cur.size} selected`;
  const [open, setOpen] = useState(false);
  return (
    <div className="fb-enum">
      <button className="fb-enum-btn" onClick={() => setOpen(o => !o)}>
        {label} <span className="dim">▾</span>
      </button>
      {open && (
        <div className="fb-enum-pop">
          {values.map(v => (
            <label key={v} className="enum-item">
              <input
                type="checkbox"
                checked={cur.has(v)}
                onChange={() => {
                  const next = new Set(cur);
                  next.has(v) ? next.delete(v) : next.add(v);
                  col.setFilterValue(next.size ? next : undefined);
                }}
              />
              <span>{v}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

function msToLocal(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}
