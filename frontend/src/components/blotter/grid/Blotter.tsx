// Full-featured order blotter:
//   - virtualized rows (react-virtual)
//   - drag column header → group panel to group by
//   - drag column header out of the table → hide it (column chooser to re-add)
//   - per-column filter dropdown (text / num / enum) via ColumnMenu
//   - column visibility chooser
//   - master-detail row expansion
//   - inline edit for px / qty (double-click)

import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getExpandedRowModel,
  getGroupedRowModel,
  flexRender,
  type SortingState,
  type ColumnFiltersState,
  type ExpandedState,
  type GroupingState,
  type VisibilityState,
  type ColumnOrderState,
  type ColumnSizingState,
} from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Fragment, forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react';
import type { BlotterProps, BlotterRef } from './BlotterApi';
import { orderColumns } from './columns';
import { DetailRow } from './DetailRow';
import { GroupPanel, GROUP_PREFIX, HEADER_PREFIX } from './GroupPanel';
import { ColumnMenu } from './ColumnMenu';
import { ColumnChooser } from './ColumnChooser';
import { HeaderContextMenu } from './HeaderContextMenu';
import { CellContextMenu } from './CellContextMenu';
import { extractCells, toTSV, copyToClipboard } from './export';
import { FilterBuilder } from './FilterBuilder';
import { autoFitColumn, autoFitAll } from './autofit';
import { usePersistedState, clearPersistedKeys } from './usePersistedState';

const DEFAULT_LS = 'testlogon.blotter.v1.';

// The full Blotter surface is now defined in BlotterApi.  Keep the internal
// prop alias for readability.
type Props = BlotterProps;

const EXPANDED_ROW_HEIGHT = 220;
const ROW_HEIGHT = 18;
const GROUP_ROW_HEIGHT = 22;

export const Blotter = forwardRef<BlotterRef, Props>(function BlotterImpl({
  data: dataProp,
  touched = new Set<string>(),
  columns: columnsProp,
  storageKeyPrefix,
  getRowId,
  selectionMode = 'cell',
  onCancel,
  extraContextMenuItems,
  getRowLabel,
  cellFormat, rowFormat,
  onCellClick: propOnCellClick,
  onRowClick, onHeaderClick,
  onCellHover, onRowHover,
  onCellCommit, validateCell,
  onSortingChange, onGroupingChange, onFiltersChange,
  onVisibilityChange, onOrderChange, onSelectionChange,
}, apiRef) {
  // Coalesce a missing `data` prop to `[]` so TanStack's accessRows
  // and every downstream `data.length`/`data.filter` call don't throw
  // on a one-render race after a dockview layout restore (where the
  // Proxy-based ctx briefly reads as `{}`).
  const data = dataProp ?? [];
  const activeColumns = columnsProp ?? orderColumns;
  const LS = storageKeyPrefix ?? DEFAULT_LS;
  const rowIdOf = getRowId ?? ((r) => r.clord);
  // Persisted-across-reload state.  Filters aren't persisted because
  // enum filters use Set<string> which doesn't JSON — the underlying
  // filterFn is preserved by column definition, so re-typing a filter
  // after reload is quick.
  const [sorting, setSorting] = usePersistedState<SortingState>(LS + 'sorting', [
    { id: 'tLastUpd', desc: true },
  ]);
  const [grouping, setGrouping] = usePersistedState<GroupingState>(LS + 'grouping', []);
  const [visibility, setVisibility] = usePersistedState<VisibilityState>(LS + 'visibility', () => {
    const v: VisibilityState = {};
    for (const c of activeColumns) {
      if ((c.meta as { defaultHidden?: boolean } | undefined)?.defaultHidden && c.id) v[c.id] = false;
    }
    return v;
  });
  const [columnOrder, setColumnOrder] = usePersistedState<ColumnOrderState>(
    LS + 'columnOrder',
    () => activeColumns.map(c => c.id!),
  );
  const [columnSizing, setColumnSizing] = usePersistedState<ColumnSizingState>(
    LS + 'columnSizing', {},
  );
  const [colFilters, setColFilters] = useState<ColumnFiltersState>([]);
  const [globalFilter, setGlobalFilter] = useState('');
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [dragOutside, setDragOutside] = useState(false);
  const [ctxMenu, setCtxMenu] = useState<{ colId: string; x: number; y: number } | null>(null);
  const [cellCtxMenu, setCellCtxMenu] = useState<{ rowId: string; colId: string; x: number; y: number } | null>(null);
  // Cell selection + active cell.  `selection` is a Set of "rowId:colId"
  // strings; `activeCell` is the "cursor" cell that moves with arrows;
  // `anchor` is the last plain-clicked cell — Shift-select ranges from
  // anchor.  Group rows are skipped for keyboard nav.
  type CellPos = { rowId: string; colId: string };
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [activeCell, setActiveCellState] = useState<CellPos | null>(null);
  // Ref-mirror of activeCell so the arrow-key handler sees the freshest
  // position between rapid keydowns (React state is committed on the
  // next render tick — too late for 60+ presses/sec).
  const activeCellRef = useRef<CellPos | null>(null);
  const setActiveCell = useCallback((v: CellPos | null | ((p: CellPos | null) => CellPos | null)) => {
    const next = typeof v === 'function' ? v(activeCellRef.current) : v;
    activeCellRef.current = next;
    setActiveCellState(next);
  }, []);
  const [anchor, setAnchor] = useState<CellPos | null>(null);
  const cellKey = (r: string, c: string) => `${r}${c}`;
  // Live drop-indicator state while dragging a column over another header.
  // Rendered as a blue line on the left or right edge of the target th.
  const [dropTarget, setDropTarget] = useState<{ colId: string; side: 'left' | 'right' } | null>(null);

  const columns = useMemo(() => activeColumns, [activeColumns]);
  // Filter out sorting entries pointing at columns this table doesn't
  // have.  Persisted state is shared with older schemas (e.g. the
  // default `tLastUpd` sort seeded for order blotters) and getSortedRowModel
  // throws if it references an unknown column id.
  const columnIds = useMemo(() => new Set(activeColumns.map(c => c.id!).filter(Boolean)), [activeColumns]);
  const safeSorting = useMemo(
    () => sorting.filter(s => columnIds.has(s.id)),
    [sorting, columnIds],
  );
  const table = useReactTable({
    data,
    columns,
    state: {
      sorting: safeSorting, columnFilters: colFilters, globalFilter,
      expanded, grouping, columnVisibility: visibility,
      columnOrder, columnSizing,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColFilters,
    onGlobalFilterChange: setGlobalFilter,
    onExpandedChange: setExpanded,
    onGroupingChange: setGrouping,
    onColumnVisibilityChange: setVisibility,
    onColumnOrderChange: setColumnOrder,
    onColumnSizingChange: setColumnSizing,
    globalFilterFn: (row, _colId, val: string) => {
      if (!val) return true;
      const v = String(val).toLowerCase();
      const o = row.original as unknown as Record<string, unknown>;
      // Search every scalar field of the row.  Cheap for our schema (~15
      // fields); TanStack calls this once per row per filter change.
      for (const k of Object.keys(o)) {
        const x = o[k];
        if (x == null) continue;
        if (typeof x === 'object') continue;   // skip lots array
        if (String(x).toLowerCase().includes(v)) return true;
      }
      return false;
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    getGroupedRowModel: getGroupedRowModel(),
    getRowCanExpand: (row) => !row.getIsGrouped(),
    // Auto-expand groups when created — DevExpress feels this way.
    autoResetExpanded: false,
    columnResizeMode: 'onChange',
  });

  const visibleCols = table.getVisibleFlatColumns();
  const rows = table.getRowModel().rows;
  // Freshest rows for deferred callbacks (rAF chains after group expand
  // fire AFTER the row model changes — the closure's `rows` is stale).
  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const rowVirt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (idx) => {
      const row = rows[idx];
      if (!row) return ROW_HEIGHT;
      if (row.getIsGrouped()) return GROUP_ROW_HEIGHT;
      return row.getIsExpanded() ? ROW_HEIGHT + EXPANDED_ROW_HEIGHT : ROW_HEIGHT;
    },
    overscan: 8,
    getItemKey: (idx) => {
      const r = rows[idx];
      if (!r) return idx;
      return r.getIsGrouped() ? `g:${r.id}` : rowIdOf(r.original);
    },
  });
  const virtItems = rowVirt.getVirtualItems();
  const firstItem = virtItems[0];
  const lastItem = virtItems[virtItems.length - 1];
  const padTop = firstItem ? firstItem.start : 0;
  const padBot = rowVirt.getTotalSize() - (lastItem ? lastItem.end : 0);

  // ---- selection + keyboard nav ---------------------------------------
  // Data-only rows (skip group headers for arrow-key nav).
  const dataRows = useMemo(() => rows.filter(r => !r.getIsGrouped()), [rows]);
  const rowIds   = useMemo(() => dataRows.map(r => rowIdOf(r.original)), [dataRows]);
  const colIds   = useMemo(() => visibleCols.map(c => c.id), [visibleCols]);

  // Helper: expand a row-id (or list of them) into keys for every visible column.
  const rowCells = useCallback((rowId: string): string[] => {
    return colIds.map(c => cellKey(rowId, c));
  }, [colIds]);

  const computeRange = useCallback((a: CellPos, b: CellPos): Set<string> => {
    const rA = rowIds.indexOf(a.rowId), rB = rowIds.indexOf(b.rowId);
    const out = new Set<string>();
    if (rA < 0 || rB < 0) return out;
    const [r0, r1] = rA < rB ? [rA, rB] : [rB, rA];
    if (selectionMode === 'row') {
      for (let r = r0; r <= r1; r++)
        for (const c of colIds) out.add(cellKey(rowIds[r], c));
      return out;
    }
    const cA = colIds.indexOf(a.colId), cB = colIds.indexOf(b.colId);
    if (cA < 0 || cB < 0) return out;
    const [c0, c1] = cA < cB ? [cA, cB] : [cB, cA];
    for (let r = r0; r <= r1; r++)
      for (let c = c0; c <= c1; c++)
        out.add(cellKey(rowIds[r]!, colIds[c]!));
    return out;
  }, [rowIds, colIds, selectionMode]);

  const onCellClick = useCallback((e: React.MouseEvent, rowId: string, colId: string) => {
    // Ignore clicks bubbling up from an inline editor.
    if ((e.target as HTMLElement).tagName === 'INPUT') return;
    const pos: CellPos = { rowId, colId };

    // Shift-select can drag selection across text — clear any native
    // text selection so only cell/row highlight is visible.
    if (e.shiftKey) window.getSelection?.()?.removeAllRanges();

    if (e.shiftKey && anchor) {
      setSelection(computeRange(anchor, pos));
      setActiveCell(pos);
    } else if (e.ctrlKey || e.metaKey) {
      setSelection(prev => {
        const next = new Set(prev);
        if (selectionMode === 'row') {
          // Toggle the whole row's cells in unison.
          const cells = rowCells(rowId);
          const already = cells.every(k => next.has(k));
          if (already) cells.forEach(k => next.delete(k));
          else cells.forEach(k => next.add(k));
        } else {
          const k = cellKey(rowId, colId);
          if (next.has(k)) next.delete(k); else next.add(k);
        }
        return next;
      });
      setActiveCell(pos);
      setAnchor(pos);
    } else {
      if (selectionMode === 'row') {
        setSelection(new Set(rowCells(rowId)));
      } else {
        setSelection(new Set([cellKey(rowId, colId)]));
      }
      setActiveCell(pos);
      setAnchor(pos);
    }
  }, [anchor, computeRange, selectionMode, rowCells]);

  // Scroll a row into view when arrow-nav pushes us off-screen.  `dir`
  // biases the alignment: 'down' pins to the bottom edge so ArrowDown at
  // the last visible row scrolls one row into view (not a page jump);
  // 'up' pins to the top for the symmetric ArrowUp case.  Without a
  // direction, TanStack's `align:'auto'` is a no-op when the target row
  // is partially visible — which is exactly when the user hits the
  // viewport edge — so autoscroll never triggers.
  // rAF-batched autoscroll: rapid arrow-nav enqueues many calls in the
  // same task; only the LAST rowId needs to end up in view.  Scheduling
  // one rAF (and coalescing intermediate calls) ensures React has
  // committed the new .active-row class before we scroll, and lets us
  // use the browser's own scrollIntoView on the actual DOM node —
  // which correctly handles sticky headers and sub-pixel rounding
  // without any manual offset math.
  const autoscrollRafRef = useRef<number | null>(null);
  const autoscrollTargetRef = useRef<string | null>(null);
  const scrollActiveIntoView = useCallback(
    (rowId: string, _dir: 'up' | 'down' | 'auto' = 'auto') => {
      autoscrollTargetRef.current = rowId;
      if (autoscrollRafRef.current != null) return;
      autoscrollRafRef.current = requestAnimationFrame(() => {
        autoscrollRafRef.current = null;
        const targetId = autoscrollTargetRef.current;
        autoscrollTargetRef.current = null;
        const sc = scrollRef.current;
        if (!sc || !targetId) return;
        // Look up the row's index in the FRESHEST row model (via ref,
        // not closure — the row model may have changed since dispatch
        // due to group expand/collapse).
        const rr = rowsRef.current;
        let idx = -1;
        for (let i = 0; i < rr.length; i++) {
          const ri = rr[i];
          if (ri && !ri.getIsGrouped() && rowIdOf(ri.original) === targetId) {
            idx = i; break;
          }
        }
        if (idx < 0) return;
        // Force the row into the virtualizer's window so its DOM
        // element exists.  align:'auto' returns immediately when the
        // row is already there — cheap no-op in the common case.
        rowVirt.scrollToIndex(idx, { align: 'auto' });
        // On the frame *after* the virtualizer commits the render, the
        // <tr data-index="idx"> element is queryable.  scrollIntoView
        // handles the sticky <thead> automatically (block:'nearest').
        requestAnimationFrame(() => {
          const row = sc.querySelector<HTMLElement>(`tr[data-index="${idx}"]`);
          if (row) row.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        });
      });
    },
    [rows, rowVirt],
  );

  const onGridKeyDown = useCallback((e: React.KeyboardEvent) => {
    // Never eat keys when focus is inside an inline input.
    const t = e.target as HTMLElement;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.isContentEditable)) return;

    // Ctrl/Cmd+A → select all visible data cells.
    if ((e.ctrlKey || e.metaKey) && (e.key === 'a' || e.key === 'A')) {
      e.preventDefault();
      const s = new Set<string>();
      for (const r of rowIds) for (const c of colIds) s.add(cellKey(r, c));
      setSelection(s);
      return;
    }
    // Ctrl/Cmd+C → copy selection (or whole table if nothing selected) as TSV.
    if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'C')) {
      e.preventDefault();
      const x = extractCells(dataRows, visibleCols, selection.size ? selection : null);
      copyToClipboard(toTSV(x));
      return;
    }
    if (e.key === 'Escape') {
      setSelection(new Set());
      setActiveCell(null);
      return;
    }

    // Read the freshest active cell (ref-mirrored to avoid state lag).
    const current = activeCellRef.current ?? activeCell;

    // Alt+ArrowUp/Down — jump between group headers when in group-by mode.
    // Lands on the FIRST data row of the target group (auto-expanding a
    // collapsed group so an active cell is available).  Works from the
    // "no active cell yet" state too; falls through to plain Arrow when
    // no groups are active.
    if (e.altKey && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      const groupRows = rows.filter(r => r.getIsGrouped());
      if (groupRows.length) {
        e.preventDefault();
        // Find which group the current active row (if any) sits under.
        let curGroupIdx = -1;
        if (current) {
          for (let g = 0; g < groupRows.length; g++) {
            const gr = groupRows[g];
            if (!gr) continue;
            const subIds = gr
              .getLeafRows()
              .map(r => rowIdOf(r.original));
            if (subIds.includes(current.rowId)) { curGroupIdx = g; break; }
          }
        }
        const nextIdx =
          e.key === 'ArrowDown'
            ? Math.min(groupRows.length - 1, curGroupIdx + 1)
            : Math.max(0, (curGroupIdx < 0 ? 0 : curGroupIdx - 1));
        const targetGroup = groupRows[nextIdx];
        if (!targetGroup) return;
        const wasCollapsed = !targetGroup.getIsExpanded();
        if (wasCollapsed) targetGroup.toggleExpanded();
        const leaf = targetGroup.getLeafRows()[0];
        if (!leaf) return;
        const targetRowId = rowIdOf(leaf.original);
        const targetColId = current?.colId ?? colIds[0];
        if (targetColId == null) return;
        const next: CellPos = { rowId: targetRowId, colId: targetColId };
        const shifted = e.shiftKey && !!anchor;
        const applySelection = () => {
          setActiveCell(next);
          if (shifted && anchor) setSelection(computeRange(anchor, next));
          else { setSelection(new Set([cellKey(next.rowId, next.colId)])); setAnchor(next); }
          scrollActiveIntoView(next.rowId, e.key === 'ArrowDown' ? 'down' : 'up');
        };
        if (wasCollapsed) {
          // toggleExpanded triggers TWO renders: the first flushes the
          // new row model; the second lets the virtualizer resize its
          // window.  scrollActiveIntoView needs the second one to have
          // committed so the leaf row is queryable.
          requestAnimationFrame(() => requestAnimationFrame(applySelection));
        } else {
          applySelection();
        }
        return;
      }
      // No groups — fall through to plain Arrow below.
    }

    // Plain arrow-nav needs a seeded active cell in the current data
    // rows.  Seed it if absent, then bail so the seeding is visible
    // before the arrow key acts on it.
    if (!current) {
      const r0 = rowIds[0], c0 = colIds[0];
      if (r0 == null || c0 == null) return;
      const start = { rowId: r0, colId: c0 };
      setActiveCell(start);
      setAnchor(start);
      setSelection(new Set([cellKey(start.rowId, start.colId)]));
      return;
    }
    const rIdx = rowIds.indexOf(current.rowId);
    const cIdx = colIds.indexOf(current.colId);
    if (rIdx < 0 || cIdx < 0) return;
    let nR = rIdx, nC = cIdx, handled = true;
    let dir: 'up' | 'down' | 'auto' = 'auto';

    switch (e.key) {
      case 'ArrowDown':  nR = Math.min(rowIds.length - 1, rIdx + 1); dir = 'down'; break;
      case 'ArrowUp':    nR = Math.max(0, rIdx - 1);                dir = 'up';   break;
      case 'ArrowRight': nC = Math.min(colIds.length - 1, cIdx + 1); break;
      case 'ArrowLeft':  nC = Math.max(0, cIdx - 1); break;
      case 'Home':       nC = 0; if (e.ctrlKey) { nR = 0; dir = 'up'; } break;
      case 'End':        nC = colIds.length - 1; if (e.ctrlKey) { nR = rowIds.length - 1; dir = 'down'; } break;
      case 'PageDown':   nR = Math.min(rowIds.length - 1, rIdx + 15); dir = 'down'; break;
      case 'PageUp':     nR = Math.max(0, rIdx - 15);                dir = 'up';   break;
      default: handled = false;
    }
    if (!handled) return;
    e.preventDefault();
    const nextRowId = rowIds[nR], nextColId = colIds[nC];
    if (nextRowId == null || nextColId == null) return;
    const next: CellPos = { rowId: nextRowId, colId: nextColId };
    setActiveCell(next);
    if (e.shiftKey && anchor) {
      setSelection(computeRange(anchor, next));
    } else {
      setSelection(new Set([cellKey(next.rowId, next.colId)]));
      setAnchor(next);
    }
    scrollActiveIntoView(next.rowId, dir);
  }, [activeCell, anchor, rowIds, colIds, dataRows, visibleCols, selection, computeRange, scrollActiveIntoView, rows, setActiveCell]);

  // Auto-fit callbacks — invoked from the header context menu.
  // Measure widths off the current filtered/sorted rows so the fit
  // matches what the user actually sees.
  const fitOneCol = useCallback((colId: string) => {
    const c = table.getColumn(colId);
    if (!c) return;
    const w = autoFitColumn(c, dataRows);
    setColumnSizing(prev => ({ ...prev, [colId]: w }));
  }, [table, dataRows]);
  const fitAllCols = useCallback(() => {
    const w = autoFitAll(visibleCols, dataRows);
    setColumnSizing(prev => ({ ...prev, ...w }));
  }, [visibleCols, dataRows]);

  // ---- cell-commit bridge ---------------------------------------------
  // EditableCell dispatches a `cell-commit` custom event.  We intercept
  // here so consumers get a proper prop-based validate + commit API
  // instead of having to add their own window listener.
  useEffect(() => {
    const h = (e: Event) => {
      const detail = (e as CustomEvent<{ rowId: string; colId: string; value: unknown }>).detail;
      const rowObj = data.find(r => r.clord === detail.rowId);
      if (!rowObj) return;
      const oldValue = (rowObj as unknown as Record<string, unknown>)[detail.colId];
      if (validateCell) {
        const err = validateCell({
          row: rowObj, rowId: detail.rowId, colId: detail.colId,
          value: oldValue, newValue: detail.value,
        });
        if (err) {
          console.warn(`[blotter] commit rejected: ${err}`);
          window.dispatchEvent(new CustomEvent('cell-commit-reject',
            { detail: { ...detail, reason: err } }));
          return;
        }
      }
      onCellCommit?.({
        row: rowObj, rowId: detail.rowId, colId: detail.colId,
        value: oldValue, oldValue, newValue: detail.value,
      });
    };
    window.addEventListener('cell-commit', h, { capture: true });
    return () => window.removeEventListener('cell-commit', h, { capture: true } as any);
  }, [data, onCellCommit, validateCell]);

  // ---- state-observation callbacks (fire on change) --------------------
  const emitStateRef = useRef({
    onSortingChange, onGroupingChange, onFiltersChange,
    onVisibilityChange, onOrderChange, onSelectionChange,
  });
  emitStateRef.current = {
    onSortingChange, onGroupingChange, onFiltersChange,
    onVisibilityChange, onOrderChange, onSelectionChange,
  };
  const lastEmitted = useRef({
    sorting, grouping, colFilters, visibility, columnOrder, selection,
  });
  if (lastEmitted.current.sorting     !== sorting)      { emitStateRef.current.onSortingChange?.(sorting);   lastEmitted.current.sorting = sorting; }
  if (lastEmitted.current.grouping    !== grouping)     { emitStateRef.current.onGroupingChange?.(grouping); lastEmitted.current.grouping = grouping; }
  if (lastEmitted.current.colFilters  !== colFilters)   { emitStateRef.current.onFiltersChange?.(colFilters); lastEmitted.current.colFilters = colFilters; }
  if (lastEmitted.current.visibility  !== visibility)   { emitStateRef.current.onVisibilityChange?.(visibility); lastEmitted.current.visibility = visibility; }
  if (lastEmitted.current.columnOrder !== columnOrder)  { emitStateRef.current.onOrderChange?.(columnOrder); lastEmitted.current.columnOrder = columnOrder; }
  if (lastEmitted.current.selection   !== selection)    { emitStateRef.current.onSelectionChange?.(selection); lastEmitted.current.selection = selection; }

  // ---- imperative API --------------------------------------------------
  useImperativeHandle(apiRef, () => ({
    setGrouping: (colIds) => setGrouping(colIds),
    setSorting:  (state)  => setSorting(state),
    setColumnFilter: (colId, value) => table.getColumn(colId)?.setFilterValue(value),
    clearColumnFilter: (colId) => table.getColumn(colId)?.setFilterValue(undefined),
    clearAllFilters: () => table.resetColumnFilters(),
    setGlobalFilter: (text) => setGlobalFilter(text),

    hideColumn: (colId) => table.getColumn(colId)?.toggleVisibility(false),
    showColumn: (colId) => table.getColumn(colId)?.toggleVisibility(true),
    setColumnVisibility: (v) => setVisibility(v),
    setColumnOrder: (colIds) => setColumnOrder(colIds),
    autoFitColumn: (colId) => fitOneCol(colId),
    autoFitAllColumns: () => fitAllCols(),
    resetColumnWidth: (colId) => setColumnSizing(prev => {
      const n = { ...prev }; delete n[colId]; return n;
    }),
    setColumnWidth: (colId, px) => setColumnSizing(prev => ({ ...prev, [colId]: px })),

    scrollToRow: (rowId) => scrollActiveIntoView(rowId),
    expandRow: (rowId, on) => {
      const r = dataRows.find(x => rowIdOf(x.original) === rowId);
      if (r) r.toggleExpanded(on);
    },
    expandAllGroups: () => table.toggleAllRowsExpanded(true),
    collapseAllGroups: () => table.toggleAllRowsExpanded(false),

    setActiveCell: (rowId, colId) => {
      setActiveCell({ rowId, colId });
      setAnchor({ rowId, colId });
      setSelection(new Set([cellKey(rowId, colId)]));
      scrollActiveIntoView(rowId);
    },
    clearSelection: () => { setSelection(new Set()); setActiveCell(null); },
    selectCells: (cells) => setSelection(new Set(cells.map(c => cellKey(c.rowId, c.colId)))),
    selectRange: (a, b) => setSelection(computeRange(a, b)),
    getSelection: () => new Set(selection),

    resetLayout: () => {
      setSorting([{ id: 'tLastUpd', desc: true }]);
      setGrouping([]);
      setVisibility({});
      setColumnOrder(activeColumns.map(c => c.id!));
      setColumnSizing({});
    },

    getVisibleRowIds: () => rowIds.slice(),
  }), [table, dataRows, rowIds, selection, fitOneCol, fitAllCols, computeRange, scrollActiveIntoView,
       setGrouping, setSorting, setGlobalFilter, setVisibility, setColumnOrder, setColumnSizing]);


  return (
    <div className={`blotter ${dragOutside ? 'drag-target' : ''}`}
      onDragOver={e => {
        // Accept plain-text drags anywhere over the blotter so the outer
        // drop overlay + hide-on-drop path works consistently.
        if (e.dataTransfer.types.includes('text/plain')) {
          e.preventDefault();
        }
      }}
      onDragEnter={e => {
        if (e.dataTransfer.types.includes('text/plain')) setDragOutside(true);
      }}
      onDragLeave={e => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragOutside(false);
      }}
    >
      <div className="blotter-toolbar">
        <input
          type="text"
          className="filter"
          placeholder="global search (sym / venue / status / clord…)"
          value={globalFilter}
          onChange={e => setGlobalFilter(e.target.value)}
        />
        <span className="stat">rows: <b>{rows.length}</b> / {data.length}</span>
        <span className="stat">live: <b>{data.filter(o => o.status === 'live' || o.status === 'partial').length}</b></span>
        <span className="stat">filled: <b>{data.filter(o => o.status === 'filled').length}</b></span>
        <FilterBuilder table={table} data={data} />
        <span className="stat spacer" />
        <button
          className="hdr-ctrl-btn"
          onClick={() => {
            if (!confirm('Reset saved column order, grouping, sorting, and visibility?')) return;
            clearPersistedKeys(LS);
            setSorting([{ id: 'tLastUpd', desc: true }]);
            setGrouping([]);
            setVisibility({});
            setColumnOrder(activeColumns.map(c => c.id!));
            setColumnSizing({});
          }}
          title="Clear saved layout in localStorage"
        >reset layout</button>
        <ColumnChooser table={table} />
      </div>
      <GroupPanel
        table={table}
        onDropColumn={(colId) => {
          setGrouping(g => g.includes(colId) ? g : [...g, colId]);
        }}
        onClearDragState={() => {
          setDragOutside(false);
          setDropTarget(null);
        }}
      />
      <div
        className={`blotter-scroll ${dragOutside ? 'drop-hide' : ''}`}
        ref={scrollRef}
        tabIndex={0}
        onKeyDown={onGridKeyDown}
        onDragOver={e => {
          if (e.dataTransfer.types.includes('text/plain')) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
          }
        }}
        onDrop={e => {
          e.preventDefault();
          const payload = e.dataTransfer.getData('text/plain');
          setDragOutside(false);
          if (payload.startsWith(GROUP_PREFIX)) {
            // dragged an existing group chip out of the panel → un-group
            const colId = payload.slice(GROUP_PREFIX.length);
            setGrouping(g => g.filter(id => id !== colId));
          } else if (payload.startsWith(HEADER_PREFIX)) {
            // dragged a column header out of the header row → hide it
            const colId = payload.slice(HEADER_PREFIX.length);
            const col = table.getColumn(colId);
            col?.toggleVisibility(false);
          }
        }}
      >
        <table className="blotter-tbl" style={{ width: table.getTotalSize() + 22 }}>
          <colgroup>
            <col style={{ width: 22 }} />
            {visibleCols.map(c => (
              <col key={c.id} style={{ width: c.getSize() }} />
            ))}
          </colgroup>
          <thead>
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id}>
                <th className="expand-cell" aria-label="expand" />
                {hg.headers.map((h) => {
                  const col = h.column;
                  const dropCls = dropTarget?.colId === col.id
                    ? (dropTarget.side === 'left' ? 'drop-left' : 'drop-right')
                    : '';
                  return (
                    <th
                      key={h.id}
                      style={{ width: h.getSize() }}
                      className={`${col.getIsSorted() ? 'is-sorted' : ''} ${dropCls}`}
                      onDragOver={e => {
                        // Accept HEADER_-prefixed drags for reorder.  Compute
                        // insert side (left vs right) from cursor X inside th.
                        if (!e.dataTransfer.types.includes('text/plain')) return;
                        e.preventDefault();
                        e.dataTransfer.dropEffect = 'move';
                        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                        const side: 'left' | 'right' =
                          (e.clientX - rect.left) < rect.width / 2 ? 'left' : 'right';
                        setDropTarget(prev =>
                          prev?.colId === col.id && prev.side === side
                            ? prev
                            : { colId: col.id, side }
                        );
                      }}
                      onDragLeave={e => {
                        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
                          setDropTarget(cur => cur?.colId === col.id ? null : cur);
                        }
                      }}
                      onDrop={e => {
                        const payload = e.dataTransfer.getData('text/plain');
                        if (!payload.startsWith(HEADER_PREFIX)) return;
                        const srcId = payload.slice(HEADER_PREFIX.length);
                        // Stop the scroll-area's hide-on-drop from also firing.
                        e.stopPropagation();
                        e.preventDefault();
                        setDropTarget(null);
                        setDragOutside(false);
                        if (srcId === col.id) return;
                        // Compute new order: remove src, insert relative to this col.
                        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                        const insertBefore = (e.clientX - rect.left) < rect.width / 2;
                        setColumnOrder(prev => {
                          const cur = prev.length ? prev : activeColumns.map(c => c.id!);
                          const without = cur.filter(id => id !== srcId);
                          let idx = without.indexOf(col.id);
                          if (idx === -1) idx = without.length;
                          if (!insertBefore) idx += 1;
                          without.splice(idx, 0, srcId);
                          return without;
                        });
                      }}
                      onContextMenu={e => {
                        // Right-click → open the full header context menu
                        // (sort, group, filter, hide, expand-all, collapse-all,
                        // column chooser).  Shift+Right-Click legacy quick-hide.
                        e.preventDefault();
                        if (e.shiftKey) {
                          col.toggleVisibility(false);
                          return;
                        }
                        setCtxMenu({ colId: col.id, x: e.clientX, y: e.clientY });
                      }}
                    >
                      <span
                        className="col-drag"
                        draggable
                        onDragStart={e => {
                          e.dataTransfer.setData('text/plain', HEADER_PREFIX + col.id);
                          e.dataTransfer.effectAllowed = 'copyMove';
                        }}
                        onDragEnd={() => {
                          setDropTarget(null);
                          setDragOutside(false);
                        }}
                      >
                        <span
                          className="col-title"
                          onClick={(e) => {
                            onHeaderClick?.({ colId: col.id, event: e });
                            col.getToggleSortingHandler()?.(e);
                          }}
                        >
                          {flexRender(col.columnDef.header, h.getContext())}
                          {{ asc: ' ▲', desc: ' ▼' }[col.getIsSorted() as string] ?? ''}
                        </span>
                      </span>
                      {col.getCanFilter() && (
                        <ColumnMenu column={col} table={table} data={data} />
                      )}
                      <span
                        onMouseDown={e => {
                          // Prevent the parent <th draggable> from starting a
                          // drag when the user grabs the resizer.  Without
                          // this the browser can interpret the same gesture
                          // as a column-drag → hide.
                          e.stopPropagation();
                          const handler = h.getResizeHandler();
                          handler?.(e);
                        }}
                        onTouchStart={e => {
                          e.stopPropagation();
                          const handler = h.getResizeHandler();
                          handler?.(e);
                        }}
                        onClick={e => e.stopPropagation()}
                        className={`resizer ${col.getIsResizing() ? 'active' : ''}`}
                      />
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {padTop > 0 && <tr style={{ height: padTop }}><td colSpan={visibleCols.length + 1}/></tr>}
            {virtItems.map(v => {
              const row = rows[v.index];
              if (!row) return null;
              if (row.getIsGrouped()) {
                const col = table.getColumn(row.groupingColumnId!);
                const groupVal = String(row.getGroupingValue(row.groupingColumnId!) ?? '');
                const count = row.subRows.length;
                const depth = row.depth;
                return (
                  <tr key={`g-${row.id}`} className={`group-row depth-${depth}`}
                    onClick={() => row.toggleExpanded()}>
                    <td colSpan={visibleCols.length + 1}>
                      <span className="tree-guides">
                        {Array.from({ length: depth }).map((_, k) => (
                          <span key={k} className="tree-guide" />
                        ))}
                      </span>
                      <span className="group-caret">
                        {row.getIsExpanded() ? '▾' : '▸'}
                      </span>
                      <span className="group-key-name">
                        {String(col?.columnDef.header ?? row.groupingColumnId)}
                      </span>
                      <span className="group-key-val">{groupVal || '(empty)'}</span>
                      <span className="group-count">
                        {count} {count === 1 ? 'order' : 'orders'}
                      </span>
                    </td>
                  </tr>
                );
              }
              const o = row.original;
              const rowId = rowIdOf(o);
              const isFlash = touched.has(rowId);
              const isExpanded = row.getIsExpanded();
              const isActiveRow = activeCell != null && activeCell.rowId === rowId;
              const isSelectedRow = rowCells(rowId).every(k => selection.has(k));
              const sideCls = (o as any)?.side ? `row-${(o as any).side}` : '';
              const rowClass = `${sideCls} ${isFlash ? 'flash' : ''} ${isExpanded ? 'expanded' : ''} ${isActiveRow ? 'active-row' : ''} ${isSelectedRow ? 'selected-row' : ''}`;
              return (
                <Fragment key={rowId}>
                  <tr
                    data-index={v.index}
                    className={`${rowClass} ${rowFormat?.({ row: o, rowId })?.className ?? ''}`}
                    style={rowFormat?.({ row: o, rowId })?.style}
                    onClick={(e) => onRowClick?.({ row: o, rowId, event: e })}
                    onMouseEnter={() => onRowHover?.({ row: o, rowId })}
                    onMouseLeave={() => onRowHover?.(null)}
                    onDoubleClick={(e) => {
                      const tag = (e.target as HTMLElement).tagName;
                      if (tag === 'INPUT') return;
                      const status = (o as any)?.status;
                      if (onCancel && (status === 'live' || status === 'partial')) onCancel((o as any).clord);
                    }}
                  >
                    <td className="expand-cell">
                      {row.depth > 0 && (
                        <span className="tree-guides leaf">
                          {Array.from({ length: row.depth }).map((_, k) => (
                            <span key={k} className="tree-guide" />
                          ))}
                        </span>
                      )}
                      <button
                        className="expander"
                        onClick={(e) => { e.stopPropagation(); row.toggleExpanded(); }}
                        aria-label={isExpanded ? 'collapse' : 'expand'}
                      >
                        {isExpanded ? '▾' : '▸'}
                      </button>
                    </td>
                    {row.getVisibleCells().map((cell) => {
                      const k = cellKey(rowId, cell.column.id);
                      const isSel = selection.has(k);
                      const isActive = activeCell != null && activeCell.rowId === rowId && activeCell.colId === cell.column.id;
                      const cellVal = row.getValue(cell.column.id);
                      const fmt = cellFormat?.({ row: o, rowId, colId: cell.column.id, value: cellVal });
                      return (
                        <td
                          key={cell.id}
                          className={`${cell.getIsPlaceholder() ? 'placeholder' : ''} ${isSel ? 'selected' : ''} ${isActive ? 'active' : ''} ${fmt?.className ?? ''}`}
                          style={{ width: cell.column.getSize(), ...(fmt?.style ?? {}) }}
                          onMouseEnter={() => onCellHover?.({ row: o, rowId, colId: cell.column.id, value: cellVal })}
                          onMouseLeave={() => onCellHover?.(null)}
                          onClick={(e) => {
                            onCellClick(e, rowId, cell.column.id);
                            propOnCellClick?.({ row: o, rowId, colId: cell.column.id, value: cellVal, event: e });
                          }}
                          onContextMenu={(e) => {
                            e.preventDefault();
                            const kk = cellKey(rowId, cell.column.id);
                            if (!selection.has(kk)) {
                              setSelection(new Set([kk]));
                              setActiveCell({ rowId, colId: cell.column.id });
                              setAnchor({ rowId, colId: cell.column.id });
                            }
                            setCellCtxMenu({ rowId, colId: cell.column.id, x: e.clientX, y: e.clientY });
                          }}
                        >
                          {cell.getIsPlaceholder() ? null : flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      );
                    })}
                  </tr>
                  {isExpanded && (o as any)?.lots && (
                    <tr className={`detail-row ${sideCls}`}>
                      <td colSpan={visibleCols.length + 1} className="detail-cell">
                        <DetailRow order={o} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {padBot > 0 && <tr style={{ height: padBot }}><td colSpan={visibleCols.length + 1}/></tr>}
          </tbody>
        </table>
      </div>
      {dragOutside && <div className="drop-overlay-hide">Release to hide column</div>}
      {ctxMenu && (() => {
        const col = table.getColumn(ctxMenu.colId);
        return col ? (
          <HeaderContextMenu
            column={col}
            table={table}
            x={ctxMenu.x}
            y={ctxMenu.y}
            onClose={() => setCtxMenu(null)}
            dataRows={dataRows}
            visibleCols={visibleCols}
            selection={selection}
            onAutoFitCol={fitOneCol}
            onAutoFitAll={fitAllCols}
            onResetCol={(colId) => setColumnSizing(prev => {
              const n = { ...prev }; delete n[colId]; return n;
            })}
          />
        ) : null;
      })()}
      {cellCtxMenu && (() => {
        const row = dataRows.find(r => rowIdOf(r.original) === cellCtxMenu.rowId);
        return row ? (
          <CellContextMenu
            x={cellCtxMenu.x}
            y={cellCtxMenu.y}
            row={row}
            colId={cellCtxMenu.colId}
            visibleCols={visibleCols}
            dataRows={dataRows}
            selection={selection}
            onCancelOrder={onCancel}
            getRowLabel={getRowLabel}
            extraItems={extraContextMenuItems ? extraContextMenuItems({
              row: row.original,
              rowId: rowIdOf(row.original),
              colId: cellCtxMenu.colId,
              value: row.getValue(cellCtxMenu.colId),
            }) : undefined}
            onClose={() => setCellCtxMenu(null)}
          />
        ) : null;
      })()}
    </div>
  );
});

