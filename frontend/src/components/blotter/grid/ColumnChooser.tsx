// "Column list" popover — DevExpress column chooser.  Shows hidden
// columns as chips you can drag back onto the table (or click to
// re-add).  Includes a search box.

import {
  useFloating,
  useClick,
  useDismiss,
  useInteractions,
  useRole,
  FloatingPortal,
  offset, flip, shift, autoUpdate,
} from '@floating-ui/react';
import { useState } from 'react';
import type { Table } from '@tanstack/react-table';
import type { Order } from '../types';

export function ColumnChooser({ table }: { table: Table<Order> }) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement: 'bottom-end',
    middleware: [offset(4), flip(), shift({ padding: 8 })],
    whileElementsMounted: autoUpdate,
  });
  const click = useClick(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getReferenceProps, getFloatingProps } = useInteractions([click, dismiss, role]);

  const allCols = table.getAllLeafColumns();
  const hiddenCount = allCols.filter(c => !c.getIsVisible()).length;
  const [q, setQ] = useState('');
  const shown = allCols.filter(c =>
    !q || String(c.columnDef.header).toLowerCase().includes(q.toLowerCase())
  );

  return (
    <>
      <button
        ref={refs.setReference}
        className="hdr-ctrl-btn"
        aria-label="Column chooser"
        {...getReferenceProps()}
      >
        columns {hiddenCount > 0 ? <span className="chip-count">{hiddenCount} hidden</span> : ''}
      </button>
      {open && (
        <FloatingPortal>
          <div ref={refs.setFloating} className="col-chooser" style={floatingStyles} {...getFloatingProps()}>
            <div className="col-menu-hdr">Column visibility</div>
            <input
              type="text"
              className="chooser-search"
              placeholder="search columns…"
              value={q}
              onChange={e => setQ(e.target.value)}
            />
            <div className="chooser-list">
              {shown.map(c => (
                <label key={c.id} className="chooser-item">
                  <input
                    type="checkbox"
                    checked={c.getIsVisible()}
                    onChange={c.getToggleVisibilityHandler()}
                  />
                  <span>{String(c.columnDef.header)}</span>
                  <span className="chooser-id">{c.id}</span>
                </label>
              ))}
            </div>
            <div className="col-menu-actions">
              <button onClick={() => table.toggleAllColumnsVisible(true)}>show all</button>
              <button onClick={() => table.resetColumnVisibility()}>reset</button>
            </div>
          </div>
        </FloatingPortal>
      )}
    </>
  );
}
