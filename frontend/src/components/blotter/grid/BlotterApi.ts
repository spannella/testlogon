// Public API surface for the Blotter — one file for consumers to import.
// The Blotter itself is stable data-shape (Order-specific for now); this
// module defines what a consumer can pass in and control from outside.
//
//   import type { BlotterProps, BlotterRef } from './grid/BlotterApi';
//   const ref = useRef<BlotterRef>(null);
//   <Blotter ref={ref} data={orders} onCellCommit={...} ... />
//   ref.current?.setGrouping(['status','venue']);

import type { CSSProperties, MouseEvent } from 'react';
import type { ColumnDef } from '@tanstack/react-table';

// The Blotter is row-shape-agnostic at the API layer: callers pass in
// whatever row type they want along with columns that know how to
// render it.  The built-in Order columns still type-check against the
// Order shape via ColumnDef<Order>[], but new views (Strategy, Params,
// Symbology) can pass their own row types.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type BlotterRow = any;

// ---------------------------------------------------------------- callbacks

export interface CellCtx {
  row: BlotterRow;
  rowId: string;
  colId: string;
  value: unknown;
}
export interface RowCtx {
  row: BlotterRow;
  rowId: string;
}
export interface ColCtx {
  colId: string;
}

// Called with `null` when the pointer leaves the cell / row.
export type CellHoverHandler = (ctx: CellCtx | null) => void;
export type RowHoverHandler  = (ctx: RowCtx  | null) => void;

export type CellClickHandler = (ctx: CellCtx & { event: MouseEvent }) => void;
export type RowClickHandler  = (ctx: RowCtx  & { event: MouseEvent }) => void;
export type HeaderClickHandler = (ctx: ColCtx & { event: MouseEvent }) => void;

// Formatting hooks — return a className, a style, both, or nothing.
export interface Formatting {
  className?: string;
  style?: CSSProperties;
}
export type CellFormatter = (ctx: CellCtx) => Formatting | undefined;
export type RowFormatter  = (ctx: RowCtx)  => Formatting | undefined;

// Change / edit / validation
export type CellCommitHandler = (ctx: CellCtx & { oldValue: unknown; newValue: unknown }) => void;
// Return an error message to block the commit, or null/undefined to accept.
export type CellValidator = (ctx: CellCtx & { newValue: unknown }) => string | null | undefined;

// Custom right-click menu items — grid consumers can inject their own
// actions per cell.  Return `[]` when the context has no custom items;
// return an item with `separator: true` to insert a divider above it.
export interface CustomMenuItem {
  label: string;
  onClick: () => void;
  icon?: string;
  kbd?: string;
  disabled?: boolean;
  danger?: boolean;
  separator?: boolean;   // when true, render a section header above this item
  section?: string;      // optional label for the separator
}
export type CustomMenuBuilder = (ctx: CellCtx) => CustomMenuItem[];

// State observation callbacks
export type SortingChange    = (sorting: { id: string; desc: boolean }[]) => void;
export type GroupingChange   = (grouping: string[]) => void;
export type FiltersChange    = (filters: { id: string; value: unknown }[]) => void;
export type VisibilityChange = (visibility: Record<string, boolean>) => void;
export type OrderChange      = (columnOrder: string[]) => void;
export type SelectionChange  = (selection: Set<string>) => void;

// ---------------------------------------------------------------- props

export interface BlotterProps {
  data: BlotterRow[];
  touched?: Set<string>;
  // Column set to render.  Defaults to the built-in `orderColumns`.
  // Pass a different column def array for a fills / positions / strategy view.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns?: ColumnDef<any>[];
  // Prefix used for all persisted layout state keys.  Different tabs
  // should use different prefixes so their layouts don't collide.
  storageKeyPrefix?: string;
  // Map a row to its stable ID.  Defaults to `row.clord`.
  getRowId?: (row: BlotterRow) => string;

  // Formatting
  cellFormat?: CellFormatter;
  rowFormat?:  RowFormatter;

  // Interaction
  onCellClick?: CellClickHandler;
  onRowClick?:  RowClickHandler;
  onHeaderClick?: HeaderClickHandler;
  onCellHover?: CellHoverHandler;
  onRowHover?:  RowHoverHandler;

  // Edit / validation
  onCellCommit?: CellCommitHandler;
  validateCell?: CellValidator;

  // State observation
  onSortingChange?:   SortingChange;
  onGroupingChange?:  GroupingChange;
  onFiltersChange?:   FiltersChange;
  onVisibilityChange?: VisibilityChange;
  onOrderChange?:     OrderChange;
  onSelectionChange?: SelectionChange;

  // Legacy quick action retained for the demo.
  onCancel?: (clord: string) => void;

  // Right-click menu extension.  Called each time the cell context menu
  // opens.  Extra items appear beneath the built-in Copy / Export /
  // Row section.  Return [] to add nothing.
  extraContextMenuItems?: CustomMenuBuilder;

  // Selection granularity.  `cell` (default) selects individual cells;
  // `row` treats every click as a full-row selection so shift-drag
  // highlights whole rows and copy-to-TSV emits row-major output.
  selectionMode?: 'cell' | 'row';

  // Header string shown at the top of the cell context menu.  Defaults
  // to a truncated rowId — pass a custom label for domain-specific text
  // (e.g. "KBE · KRE" for strategy rows).
  getRowLabel?: (row: BlotterRow) => string;
}

// ---------------------------------------------------------------- imperative

export interface BlotterRef {
  // Filtering / sorting / grouping
  setGrouping(colIds: string[]): void;
  setSorting(state: { id: string; desc: boolean }[]): void;
  setColumnFilter(colId: string, value: unknown): void;
  clearColumnFilter(colId: string): void;
  clearAllFilters(): void;
  setGlobalFilter(text: string): void;

  // Columns
  hideColumn(colId: string): void;
  showColumn(colId: string): void;
  setColumnVisibility(v: Record<string, boolean>): void;
  setColumnOrder(colIds: string[]): void;
  autoFitColumn(colId: string): void;
  autoFitAllColumns(): void;
  resetColumnWidth(colId: string): void;
  setColumnWidth(colId: string, px: number): void;

  // Rows (traversal / view only — data mutation lives with the consumer)
  scrollToRow(rowId: string): void;
  expandRow(rowId: string, on?: boolean): void;
  expandAllGroups(): void;
  collapseAllGroups(): void;

  // Selection / active cell
  setActiveCell(rowId: string, colId: string): void;
  clearSelection(): void;
  selectCells(cells: { rowId: string; colId: string }[]): void;
  selectRange(a: { rowId: string; colId: string }, b: { rowId: string; colId: string }): void;
  getSelection(): Set<string>;

  // Layout persistence
  resetLayout(): void;

  // Snapshot the visible view (respects filter/sort/group).
  getVisibleRowIds(): string[];
}
