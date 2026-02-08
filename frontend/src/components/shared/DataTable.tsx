import * as React from "react";
import { ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

// ─── Types ───────────────────────────────────────────────────────

export type SortDirection = "asc" | "desc";

export interface SortState {
  column: string;
  direction: SortDirection;
}

export interface ColumnDef<T> {
  /** Unique column key */
  id: string;
  /** Header label */
  header: string;
  /** Render the cell value. Receives the row data. */
  cell: (row: T) => React.ReactNode;
  /** Enable sorting on this column */
  sortable?: boolean;
  /** Custom class for header and cells */
  className?: string;
}

export interface DataTableProps<T> {
  columns: ColumnDef<T>[];
  data: T[];
  /** Unique key extractor for each row */
  rowKey: (row: T) => string;
  /** Current sort state (controlled) */
  sort?: SortState;
  /** Called when a sortable column header is clicked */
  onSort?: (sort: SortState) => void;
  /** Called when a row is clicked */
  onRowClick?: (row: T) => void;
  /** Enable checkbox selection */
  selectable?: boolean;
  /** Currently selected row keys (controlled) */
  selectedKeys?: Set<string>;
  /** Called when selection changes */
  onSelectionChange?: (keys: Set<string>) => void;
  /** Show a "Load more" button at the bottom */
  hasMore?: boolean;
  /** Called when "Load more" is clicked */
  onLoadMore?: () => void;
  /** Whether "Load more" is loading */
  loadingMore?: boolean;
  /** Optional empty state when data is empty */
  emptyState?: React.ReactNode;
  /** Additional className for the wrapper */
  className?: string;
}

// ─── DataTable Component ────────────────────────────────────────

export function DataTable<T>({
  columns,
  data,
  rowKey,
  sort,
  onSort,
  onRowClick,
  selectable,
  selectedKeys,
  onSelectionChange,
  hasMore,
  onLoadMore,
  loadingMore,
  emptyState,
  className,
}: DataTableProps<T>) {
  const allKeys = React.useMemo(() => data.map(rowKey), [data, rowKey]);
  const allSelected = selectedKeys != null && allKeys.length > 0 && allKeys.every((k) => selectedKeys.has(k));
  const someSelected = selectedKeys != null && allKeys.some((k) => selectedKeys.has(k)) && !allSelected;

  const toggleAll = () => {
    if (!onSelectionChange) return;
    if (allSelected) {
      onSelectionChange(new Set());
    } else {
      onSelectionChange(new Set(allKeys));
    }
  };

  const toggleRow = (key: string) => {
    if (!onSelectionChange || !selectedKeys) return;
    const next = new Set(selectedKeys);
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    onSelectionChange(next);
  };

  const handleSort = (columnId: string) => {
    if (!onSort) return;
    if (sort?.column === columnId) {
      onSort({ column: columnId, direction: sort.direction === "asc" ? "desc" : "asc" });
    } else {
      onSort({ column: columnId, direction: "asc" });
    }
  };

  const getSortIcon = (columnId: string) => {
    if (sort?.column !== columnId) return <ArrowUpDown className="h-3.5 w-3.5" />;
    return sort.direction === "asc"
      ? <ArrowUp className="h-3.5 w-3.5" />
      : <ArrowDown className="h-3.5 w-3.5" />;
  };

  return (
    <div className={cn("space-y-2", className)}>
      <div className="overflow-x-auto rounded-lg">
      <Table>
        <TableHeader>
          <TableRow>
            {selectable && (
              <TableHead className="w-10">
                <Checkbox
                  checked={allSelected ? true : someSelected ? "indeterminate" : false}
                  onCheckedChange={toggleAll}
                  aria-label="Select all rows"
                />
              </TableHead>
            )}
            {columns.map((col) => (
              <TableHead key={col.id} className={col.className}>
                {col.sortable && onSort ? (
                  <button
                    className="inline-flex items-center gap-1 hover:text-foreground transition-colors"
                    onClick={() => handleSort(col.id)}
                  >
                    {col.header}
                    {getSortIcon(col.id)}
                  </button>
                ) : (
                  col.header
                )}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={columns.length + (selectable ? 1 : 0)}
                className="h-32 text-center"
              >
                {emptyState ?? <span className="text-muted-foreground">No data</span>}
              </TableCell>
            </TableRow>
          ) : (
            data.map((row) => {
              const key = rowKey(row);
              const selected = selectedKeys?.has(key) ?? false;
              return (
                <TableRow
                  key={key}
                  data-state={selected ? "selected" : undefined}
                  className={cn(onRowClick && "cursor-pointer")}
                  onClick={() => onRowClick?.(row)}
                >
                  {selectable && (
                    <TableCell>
                      <Checkbox
                        checked={selected}
                        onCheckedChange={() => toggleRow(key)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={`Select row ${key}`}
                      />
                    </TableCell>
                  )}
                  {columns.map((col) => (
                    <TableCell key={col.id} className={col.className}>
                      {col.cell(row)}
                    </TableCell>
                  ))}
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>
      </div>

      {hasMore && (
        <div className="flex justify-center pt-2">
          <Button variant="outline" size="sm" onClick={onLoadMore} disabled={loadingMore}>
            {loadingMore ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
