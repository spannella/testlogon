// Public entry point for the Blotter library.  Consumers import
// everything they need from here.

// Ship the blotter stylesheet alongside the component.
import './blotter.css';

export { Blotter } from './Blotter';
export type {
  BlotterProps, BlotterRef,
  CellCtx, RowCtx, ColCtx,
  Formatting,
  CellFormatter, RowFormatter,
  CellClickHandler, RowClickHandler, HeaderClickHandler,
  CellHoverHandler, RowHoverHandler,
  CellCommitHandler, CellValidator,
  SortingChange, GroupingChange, FiltersChange,
  VisibilityChange, OrderChange, SelectionChange,
} from './BlotterApi';

// Advanced consumers may want the export helpers or the pieces used
// internally (filter builders, tooltips) — re-exported here.
export { TableTooltip } from '../tooltip/TableTooltip';
export {
  extractCells, toCSV, toTSV, copyToClipboard,
  exportCSV, exportPDF, exportParquet,
} from './export';
export { autoFitColumn, autoFitAll } from './autofit';
export { usePersistedState, clearPersistedKeys } from './usePersistedState';

// Data types are Order-specific for now.  A generic Blotter<T> is
// tracked separately — the surface here is stable Order-only.
export type { Order, Lot, Side, OrderStatus, Venue, PositionRow } from '../types';
