// Fills view — reuses the Order type but presents fields ordered around
// the fill event (execution time, fill px, fill qty, order px).  Mirrors
// the C# OrderManagement fills grid columns: ExecutionTime, Symbol,
// Venue, FillPrice, OrderPrice, FillQuantity, RemainingQuantity, Side,
// ClOrdId.  Only shows rows that have had at least one fill.

import type { ColumnDef } from '@tanstack/react-table';
import type { Order } from '../types';
import { orderColumns, enumFilter, numFilter, textFilter } from './columns';

// Pull a few known column defs from the shared orderColumns list and
// re-order them.  Adds a "cumQty" alias 'FillQty' and 'leaves' aliased
// as 'RemainingQty' for label parity with the C# grid.
const pick = (id: string) => orderColumns.find(c => c.id === id)!;

// Compact Fills view — one row = one fill.  Analytics that only make
// sense per-fill (FairPlace/FairExec, edge, liq, hedge linkage, slippage)
// live in the DetailRow expand panel to keep this table scannable.
// Row-expand chevron is on every row; click to reveal the detail.
export const fillsColumns: ColumnDef<Order>[] = [
  { ...pick('tLastUpd'), header: 'ExecTime' },
  { ...pick('sym') },
  { ...pick('venue') },
  { ...pick('source') },
  { ...pick('subacct') },
  { ...pick('side') },
  { ...pick('cumQty'),   header: 'FillQty'  },
  { ...pick('avgPx'),    header: 'FillPx'   },
  { ...pick('edgeToExec') },       // small: one signed number, quick scan
  { ...pick('px'),       header: 'OrderPx'  },
  { ...pick('leaves'),   header: 'Remaining' },
  { ...pick('status') },
  { ...pick('clord'),    header: 'ClOrd', enableSorting: false,
    filterFn: textFilter, meta: { filterKind: 'text' } },
  { ...pick('tRcv'),     header: 'Received' },
];
// Referenced for TypeScript so unused imports don't warn — the
// filter functions come from the shared columns module and are used
// implicitly when a filterFn is inherited via `pick()`.
void enumFilter; void numFilter;
