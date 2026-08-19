// Per-column header menu + filter popover.  Anchored on the funnel icon;
// content is type-aware (text/num/enum).  Also holds column-scoped
// actions (sort, group by, hide).

import {
  useFloating,
  useClick,
  useDismiss,
  useInteractions,
  useRole,
  FloatingPortal,
  offset, flip, shift, autoUpdate,
} from '@floating-ui/react';
import { useState, useEffect } from 'react';
import type { Column, Table } from '@tanstack/react-table';
import type { Order } from '../types';

interface Props {
  column: Column<Order, unknown>;
  table: Table<Order>;
  data: Order[];
}

export function ColumnMenu({ column, table, data }: Props) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement: 'bottom-start',
    middleware: [offset(4), flip(), shift({ padding: 8 })],
    whileElementsMounted: autoUpdate,
  });
  const click = useClick(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getReferenceProps, getFloatingProps } = useInteractions([click, dismiss, role]);

  const active = column.getFilterValue() != null;

  return (
    <>
      <button
        ref={refs.setReference}
        className={`col-menu-btn ${active ? 'active' : ''}`}
        aria-label={`filter and options for ${String(column.columnDef.header)}`}
        {...getReferenceProps({ onClick: e => e.stopPropagation() })}
      >
        ⛛
      </button>
      {open && (
        <FloatingPortal>
          <div
            ref={refs.setFloating}
            className="col-menu"
            style={floatingStyles}
            {...getFloatingProps()}
          >
            <ColumnMenuBody column={column} table={table} data={data} onClose={() => setOpen(false)} />
          </div>
        </FloatingPortal>
      )}
    </>
  );
}

function ColumnMenuBody({
  column, table, data, onClose,
}: {
  column: Column<Order, unknown>;
  table: Table<Order>;
  data: Order[];
  onClose: () => void;
}) {
  const kind = column.columnDef.meta?.filterKind;
  const sorted = column.getIsSorted();

  return (
    <div className="col-menu-inner">
      <div className="col-menu-hdr">{String(column.columnDef.header)}</div>
      <div className="col-menu-actions">
        <button
          className={sorted === 'asc' ? 'on' : ''}
          onClick={() => { column.toggleSorting(false); onClose(); }}
          disabled={!column.getCanSort()}
        >Sort ↑</button>
        <button
          className={sorted === 'desc' ? 'on' : ''}
          onClick={() => { column.toggleSorting(true); onClose(); }}
          disabled={!column.getCanSort()}
        >Sort ↓</button>
        <button
          onClick={() => { column.clearSorting(); onClose(); }}
          disabled={!sorted}
        >Clear sort</button>
      </div>
      <div className="col-menu-actions">
        <button
          onClick={() => {
            table.setGrouping(g => g.includes(column.id) ? g : [...g, column.id]);
            onClose();
          }}
          disabled={!column.getCanGroup() || table.getState().grouping.includes(column.id)}
        >Group by this</button>
        <button
          onClick={() => { column.toggleVisibility(false); onClose(); }}
        >Hide column</button>
      </div>
      <div className="col-menu-hdr sub">Filter</div>
      {kind === 'enum' && <EnumFilterUI column={column} data={data} />}
      {kind === 'num'  && <NumFilterUI  column={column} />}
      {kind === 'date' && <NumFilterUI  column={column} dateMode />}
      {kind === 'text' && <TextFilterUI column={column} />}
      {!kind && <div className="col-menu-empty">No filter for this column</div>}
      <div className="col-menu-actions">
        <button
          onClick={() => column.setFilterValue(undefined)}
          disabled={column.getFilterValue() == null}
        >Clear filter</button>
        <button className="primary" onClick={onClose}>Close</button>
      </div>
    </div>
  );
}

// --------- filter UIs per type ---------

function TextFilterUI({ column }: { column: Column<Order, unknown> }) {
  const cur = column.getFilterValue() as { op: string; val: string } | undefined;
  const [op, setOp] = useState(cur?.op ?? 'contains');
  const [val, setVal] = useState(cur?.val ?? '');
  useEffect(() => {
    if (!val) column.setFilterValue(undefined);
    else column.setFilterValue({ op, val });
  }, [op, val]);
  return (
    <div className="filter-body">
      <select value={op} onChange={e => setOp(e.target.value)}>
        <option value="contains">contains</option>
        <option value="equals">equals</option>
        <option value="startsWith">starts with</option>
        <option value="endsWith">ends with</option>
        <option value="neq">does not contain</option>
      </select>
      <input
        type="text"
        placeholder="text…"
        value={val}
        onChange={e => setVal(e.target.value)}
        autoFocus
      />
    </div>
  );
}

function NumFilterUI({ column, dateMode }: { column: Column<Order, unknown>; dateMode?: boolean }) {
  const cur = column.getFilterValue() as { op: string; val?: number; val2?: number } | undefined;
  const [op, setOp] = useState(cur?.op ?? 'gte');
  const [val, setVal] = useState<string>(
    dateMode
      ? (cur?.val != null ? msToLocalDateTime(cur.val as number) : msToLocalDateTime(Date.now() - 3600_000))
      : (cur?.val != null ? String(cur.val) : '')
  );
  const [val2, setVal2] = useState<string>(
    dateMode
      ? (cur?.val2 != null ? msToLocalDateTime(cur.val2 as number) : '')
      : (cur?.val2 != null ? String(cur.val2) : '')
  );
  useEffect(() => {
    const parse = (s: string) => (dateMode ? Date.parse(s) : parseFloat(s));
    const n = parse(val);
    if (isNaN(n)) { column.setFilterValue(undefined); return; }
    if (op === 'between') {
      const n2 = parse(val2);
      if (isNaN(n2)) { column.setFilterValue(undefined); return; }
      column.setFilterValue({ op, val: n, val2: n2 });
    } else {
      column.setFilterValue({ op, val: n });
    }
  }, [op, val, val2, dateMode]);
  const inputType = dateMode ? 'datetime-local' : 'number';
  return (
    <div className="filter-body">
      <select value={op} onChange={e => setOp(e.target.value)}>
        <option value="eq">=</option>
        <option value="neq">≠</option>
        <option value="gt">&gt;</option>
        <option value="gte">≥</option>
        <option value="lt">&lt;</option>
        <option value="lte">≤</option>
        <option value="between">between</option>
      </select>
      <input
        type={inputType}
        placeholder="value"
        value={val}
        onChange={e => setVal(e.target.value)}
        autoFocus
      />
      {op === 'between' && (
        <input
          type={inputType}
          placeholder="and"
          value={val2}
          onChange={e => setVal2(e.target.value)}
        />
      )}
    </div>
  );
}
function msToLocalDateTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function EnumFilterUI({ column, data }: { column: Column<Order, unknown>; data: Order[] }) {
  // Prefer explicit enumValues from meta; else derive from data.
  const declared = column.columnDef.meta?.enumValues;
  const values = declared ?? Array.from(new Set(data.map(r => String((r as any)[column.id])))).sort();
  const cur = (column.getFilterValue() as Set<string> | undefined) ?? new Set<string>();
  const [pick, setPick] = useState<Set<string>>(new Set(cur));

  const toggle = (v: string) => {
    const next = new Set(pick);
    if (next.has(v)) next.delete(v); else next.add(v);
    setPick(next);
    column.setFilterValue(next.size ? next : undefined);
  };

  return (
    <div className="filter-body enum">
      <div className="enum-list">
        {values.map(v => (
          <label key={v} className="enum-item">
            <input
              type="checkbox"
              checked={pick.has(v)}
              onChange={() => toggle(v)}
            />
            <span>{v}</span>
          </label>
        ))}
      </div>
      <div className="enum-btns">
        <button onClick={() => { setPick(new Set(values)); column.setFilterValue(new Set(values)); }}>
          all
        </button>
        <button onClick={() => { setPick(new Set()); column.setFilterValue(undefined); }}>
          none
        </button>
      </div>
    </div>
  );
}
