// Right-click a data cell.  Focused on selection actions: copy, export,
// plus a quick "cancel this order" for live/partial rows.  Grid
// consumers can inject their own items via the extraItems prop — those
// items render in an additional section beneath the built-in ones.

import {
  useFloating, useDismiss, useInteractions, useRole,
  FloatingPortal, offset, flip, shift,
} from '@floating-ui/react';
import type { Column, Row } from '@tanstack/react-table';
import type { BlotterRow, CustomMenuItem } from './BlotterApi';
import { extractCells, exportCSV, exportPDF, exportParquet, toTSV, copyToClipboard } from './export';

interface Props {
  x: number;
  y: number;
  row: Row<BlotterRow>;
  colId: string;
  visibleCols: Column<BlotterRow, unknown>[];
  dataRows: Row<BlotterRow>[];
  selection: Set<string>;
  onClose: () => void;
  onCancelOrder?: (clord: string) => void;
  getRowLabel?: (row: BlotterRow) => string;
  extraItems?: CustomMenuItem[];
}

export function CellContextMenu({
  x, y, row, colId, visibleCols, dataRows, selection, onClose,
  onCancelOrder, getRowLabel, extraItems,
}: Props) {
  const { refs, floatingStyles, context } = useFloating({
    open: true,
    onOpenChange: v => { if (!v) onClose(); },
    placement: 'right-start',
    middleware: [offset(2), flip(), shift({ padding: 6 })],
    elements: {
      reference: {
        getBoundingClientRect() {
          return {
            x, y, top: y, left: x, bottom: y, right: x, width: 0, height: 0,
            toJSON() { return this; },
          } as DOMRect;
        },
      } as any,
    },
  });
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'menu' });
  const { getFloatingProps } = useInteractions([dismiss, role]);

  const o = row.original;
  const scope = selection.size ? 'selection' : 'whole table';
  const item = (label: string, onClick: () => void, opts: { icon?: string; kbd?: string; disabled?: boolean; danger?: boolean } = {}) => (
    <button
      key={label}
      className={`ctx-item ${opts.disabled ? 'disabled' : ''} ${opts.danger ? 'danger' : ''}`}
      disabled={opts.disabled}
      onClick={() => { onClick(); onClose(); }}
    >
      <span className="ctx-icon">{opts.icon ?? ''}</span>
      <span className="ctx-label">{label}</span>
      {opts.kbd && <span className="ctx-kbd">{opts.kbd}</span>}
    </button>
  );

  // Row-header label.  Prefer the caller's function; fall back to the
  // Order-shape sym+clord we know the built-in view uses; else the
  // stringified row id.
  let hdr: string;
  if (getRowLabel) hdr = getRowLabel(o);
  else if (o && typeof o === 'object' && 'sym' in o && 'clord' in o) {
    hdr = `${(o as any).sym} · ${((o as any).clord as string).slice(-8)}`;
  } else {
    hdr = String(row.id);
  }

  // Cancel-order only for Order-shape rows (has status field).
  const canCancel =
    onCancelOrder != null
    && o && typeof o === 'object' && 'clord' in o && 'status' in o
    && ((o as any).status === 'live' || (o as any).status === 'partial');

  return (
    <FloatingPortal>
      <div ref={refs.setFloating} className="ctx-menu" style={floatingStyles} {...getFloatingProps()}>
        <div className="ctx-hdr">
          {hdr}
          {colId && <span className="dim"> · {colId}</span>}
        </div>

        <div className="ctx-sep"><span>Copy · Export ({scope})</span></div>
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

        <div className="ctx-sep"><span>Row</span></div>
        {item(row.getIsExpanded() ? 'Collapse detail' : 'Expand detail (fills)',
          () => row.toggleExpanded(),
          { icon: row.getIsExpanded() ? '▾' : '▸' })}
        {canCancel && item('Cancel this order',
          () => onCancelOrder?.((o as any).clord),
          { icon: '×', danger: true })}

        {/* Consumer-supplied custom items — grouped by section header. */}
        {extraItems && extraItems.length > 0 && (
          <>
            {extraItems.map((it, i) => (
              <span key={`extra-${i}`}>
                {(it.separator || it.section) &&
                  <div className="ctx-sep"><span>{it.section ?? '—'}</span></div>}
                {item(it.label, it.onClick, {
                  icon: it.icon, kbd: it.kbd, disabled: it.disabled, danger: it.danger,
                })}
              </span>
            ))}
          </>
        )}
      </div>
    </FloatingPortal>
  );
}
