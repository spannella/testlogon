import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, Receipt } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable, type ColumnDef, type SortState } from "@/components/shared/DataTable";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { getLedger } from "@/api/endpoints/billing";
import type { LedgerEntry } from "@/api/types";

function formatCents(cents: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(cents / 100);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function stateVariant(state: string) {
  switch (state) {
    case "settled":
    case "completed":
      return "success" as const;
    case "pending":
      return "warning" as const;
    case "failed":
    case "reversed":
      return "danger" as const;
    default:
      return "neutral" as const;
  }
}

const columns: ColumnDef<LedgerEntry>[] = [
  {
    id: "date",
    header: "Date",
    sortable: true,
    cell: (row) => (
      <span className="text-sm whitespace-nowrap">{formatDate(row.ts)}</span>
    ),
    className: "w-32",
  },
  {
    id: "type",
    header: "Description",
    cell: (row) => (
      <div>
        <span className="text-sm font-medium capitalize">
          {row.type.replace(/_/g, " ")}
        </span>
        {row.reason && (
          <p className="text-xs text-muted-foreground">{row.reason}</p>
        )}
      </div>
    ),
  },
  {
    id: "amount",
    header: "Amount",
    sortable: true,
    cell: (row) => (
      <span
        className={cn(
          "text-sm font-medium",
          row.amount_cents >= 0
            ? "text-green-600 dark:text-green-400"
            : "text-destructive",
        )}
      >
        {row.amount_cents >= 0 ? "+" : ""}
        {formatCents(row.amount_cents)}
      </span>
    ),
    className: "text-right w-28",
  },
  {
    id: "state",
    header: "Status",
    cell: (row) => (
      <StatusBadge variant={stateVariant(row.state)} className="capitalize">
        {row.state}
      </StatusBadge>
    ),
    className: "w-24",
  },
];

export function Ledger() {
  const [sort, setSort] = useState<SortState>({ column: "date", direction: "desc" });
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  const ledgerQuery = useQuery({
    queryKey: ["billing", "ledger"],
    queryFn: () => getLedger(200),
  });

  const entries = ledgerQuery.data?.items ?? [];

  // Filter by date range
  const filtered = useMemo(() => {
    let result = entries;
    if (startDate) {
      const startTs = new Date(startDate).getTime() / 1000;
      result = result.filter((e) => e.ts >= startTs);
    }
    if (endDate) {
      const endTs = new Date(endDate).getTime() / 1000 + 86400; // end of day
      result = result.filter((e) => e.ts <= endTs);
    }
    return result;
  }, [entries, startDate, endDate]);

  // Sort
  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sort.column === "date") cmp = a.ts - b.ts;
      else if (sort.column === "amount") cmp = a.amount_cents - b.amount_cents;
      return sort.direction === "desc" ? -cmp : cmp;
    });
    return arr;
  }, [filtered, sort]);

  const exportCsv = () => {
    const header = "Date,Type,Amount,Status,Reason";
    const rows = sorted.map(
      (e) =>
        `${formatDate(e.ts)},${e.type},${(e.amount_cents / 100).toFixed(2)},${e.state},${e.reason ?? ""}`,
    );
    const csv = [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ledger.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (ledgerQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="space-y-1.5">
          <Label htmlFor="start-date">From</Label>
          <Input
            id="start-date"
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="w-40"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="end-date">To</Label>
          <Input
            id="end-date"
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="w-40"
          />
        </div>
        <div className="ml-auto">
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={sorted.length === 0}>
            <Download className="mr-1 h-3.5 w-3.5" />
            Export CSV
          </Button>
        </div>
      </div>

      {/* Table */}
      <DataTable
        columns={columns}
        data={sorted}
        rowKey={(row) => row.sk}
        sort={sort}
        onSort={setSort}
        emptyState={
          <EmptyState
            icon={<Receipt className="h-6 w-6" />}
            title="No transactions"
            description={startDate || endDate ? "Try adjusting your date range" : "No billing activity yet"}
          />
        }
      />

      <p className="text-xs text-muted-foreground text-right">
        Showing {sorted.length} of {entries.length} entries
      </p>
    </div>
  );
}
