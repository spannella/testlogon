// Right-click context menu for the header row.  Anchored to the cursor
// position where the right-click happened.  Contains column-scoped
// actions (sort, group, hide, filter shortcut) plus table-wide actions
// (expand all / collapse all / column chooser submenu / reset layout).

import {
  useFloating,
  useDismiss,
  useInteractions,
  useRole,
  FloatingPortal,
  offset, flip, shift,
} from '@floating-ui/react';
import { useState } from 'react';
import type { Column, Row, Table } from '@tanstack/react-table';
import type { Order } from '../types';
import { extractCells, exportCSV, exportPDF, exportParquet, toTSV, copyToClipboard } from './export';

interface Props {
  column: Column<Order, unknown>;
  table: Table<Order>;
  x: number;
  y: number;
  onClose: () => void;
  dataRows: Row<Order>[];
  visibleCols: Column<Order, unknown>[];
  selection: Set<string>;
  onAutoFitCol: (colId: string) => void;
  onAutoFitAll: () => void;
  onResetCol: (colId: string) => void;
}

export function HeaderContextMenu({
  column, table, x, y, onClose, dataRows, visibleCols, selection,
  onAutoFitCol, onAutoFitAll, onResetCol,
}: Props) {
  const [showChooser, setShowChooser] = useState(false);

  const { refs, floatingStyles, context } = useFloating({
    open: true,
    onOpenChange: (v) => { if (!v) onClose(); },
    placement: 'right-start',
    middleware: [offset(2), flip(), shift({ padding: 6 })],
    // Anchor to a virtual element at cursor position.
    elements: {
      reference: {
        getBoundingClientRect() {
          return {
            x, y, top: y, left: x, bottom: y, right: x, width: 0, height: 0,
            toJSON() { return this; }
          } as DOMRect;
        },
      } as any,
    },
  });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getFloatingProps } = useInteractions([dismiss, role]);

  const sorted = column.getIsSorted();
  const grouped = column.getIsGrouped();
  const hasFilter = column.getFilterValue() != null;
  const allCols = table.getAllLeafColumns();
  const hiddenCount = allCols.filter(c => !c.getIsVisible()).length;
  const [q, setQ] = useState('');
  const chooserRows = allCols.filter(c =>
    !q || String(c.columnDef.header).toLowerCase().includes(q.toLowerCase())
  );

  const item = (label: string, onClick: () => void, opts: { disabled?: boolean; danger?: boolean; kbd?: string; icon?: string } = {}) => (
    <button
      className={`ctx-item ${opts.disabled ? 'disabled' : ''} ${opts.danger ? 'danger' : ''}`}
      disabled={opts.disabled}
      onClick={() => { onClick(); onClose(); }}
    >
      <span className="ctx-icon">{opts.icon ?? ''}</span>
      <span className="ctx-label">{label}</span>
      {opts.kbd && <span className="ctx-kbd">{opts.kbd}</span>}
    </button>
  );
  const separator = (label?: string) => (
    <div className="ctx-sep">{label && <span>{label}</span>}</div>
  );

  return (
    <FloatingPortal>
      <div
        ref={refs.setFloating}
        className="ctx-menu"
        style={floatingStyles}
        {...getFloatingProps()}
      >
        <div className="ctx-hdr">
          {String(column.columnDef.header)} <span className="dim">— column</span>
        </div>

        {separator('Sort')}
        {item(sorted === 'asc' ? '✓ Sort ascending' : 'Sort ascending',
          () => column.toggleSorting(false),
          { disabled: !column.getCanSort(), icon: '↑' })}
        {item(sorted === 'desc' ? '✓ Sort descending' : 'Sort descending',
          () => column.toggleSorting(true),
          { disabled: !column.getCanSort(), icon: '↓' })}
        {item('Clear sort', () => column.clearSorting(),
          { disabled: !sorted, icon: '×' })}

        {separator('Group')}
        {item(grouped ? '✓ Ungroup this column' : 'Group by this column',
          () => grouped
            ? table.setGrouping(g => g.filter(id => id !== column.id))
            : table.setGrouping(g => g.includes(column.id) ? g : [...g, column.id]),
          { disabled: !column.getCanGroup(), icon: grouped ? '−' : '+' })}
        {item('Expand all groups', () => table.toggleAllRowsExpanded(true),
          { disabled: table.getState().grouping.length === 0, icon: '▾' })}
        {item('Collapse all groups', () => table.toggleAllRowsExpanded(false),
          { disabled: table.getState().grouping.length === 0, icon: '▸' })}

        {separator('Filter')}
        {item('Clear this column\'s filter',
          () => column.setFilterValue(undefined),
          { disabled: !hasFilter, icon: '⛛' })}
        {item('Clear ALL filters',
          () => table.resetColumnFilters(),
          { disabled: table.getState().columnFilters.length === 0, icon: '⛒' })}

        {separator(`Copy · Export ${selection.size ? '(selection)' : '(whole table)'}`)}
        {item('Copy to clipboard (TSV)', async () => {
          const x = extractCells(dataRows, visibleCols, selection.size ? selection : null);
          await copyToClipboard(toTSV(x));
        }, { icon: '⧉', kbd: '⌃C' })}
        {item('Export CSV…', () => {
          const x = extractCells(dataRows, visibleCols, selection.size ? selection : null);
          exportCSV(x, `testlogon-blotter-${Date.now()}.csv`);
        }, { icon: '⇩' })}
        {item('Export PDF…', () => {
          const x = extractCells(dataRows, visibleCols, selection.size ? selection : null);
          exportPDF(x, `testlogon-blotter-${Date.now()}.pdf`,
            selection.size ? 'Testlogon blotter — selection' : 'Testlogon blotter — full');
        }, { icon: '⇩' })}
        {item('Export Parquet…', () => {
          const x = extractCells(dataRows, visibleCols, selection.size ? selection : null);
          exportParquet(x, `testlogon-blotter-${Date.now()}.parquet`);
        }, { icon: '⇩' })}

        {separator('Sizing')}
        {item('Auto-fit this column', () => onAutoFitCol(column.id),
          { icon: '↔' })}
        {item('Auto-fit all columns', () => onAutoFitAll(),
          { icon: '⇔' })}
        {item('Reset this column width', () => onResetCol(column.id),
          { icon: '⤺' })}

        {separator('Columns')}
        {item('Hide this column', () => column.toggleVisibility(false),
          { icon: '⊘' })}
        <button
          className="ctx-item"
          onClick={() => setShowChooser(s => !s)}
          aria-expanded={showChooser}
        >
          <span className="ctx-icon">▤</span>
          <span className="ctx-label">
            Column chooser{hiddenCount ? ` (${hiddenCount} hidden)` : ''}…
          </span>
          <span className="ctx-kbd">{showChooser ? '▾' : '▸'}</span>
        </button>
        {showChooser && (
          <div className="ctx-chooser">
            <input
              type="text"
              className="chooser-search"
              placeholder="search columns…"
              value={q}
              onChange={e => setQ(e.target.value)}
              onKeyDown={e => e.stopPropagation()}
            />
            <div className="chooser-list">
              {chooserRows.map(c => (
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
        )}
      </div>
    </FloatingPortal>
  );
}
