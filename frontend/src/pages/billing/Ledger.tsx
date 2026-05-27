import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, Receipt, RotateCcw } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable, type ColumnDef, type SortState } from "@/components/shared/DataTable";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { getLedger } from "@/api/endpoints/billing";
import { RefundRequestDialog } from "./RefundRequestDialog";
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

function isEligibleForRefund(entry: LedgerEntry): boolean {
  // Eligible if: settled, positive amount, within 30 days, and is a debit type
  if (entry.state !== "settled") return false;
  if (entry.amount_cents <= 0) return false;
  const thirtyDaysAgo = Date.now() / 1000 - 30 * 86400;
  if (entry.ts < thirtyDaysAgo) return false;
  // Exclude refund_credit entries
  if (entry.type === "refund_credit") return false;
  // Needs an entry_id
  if (!(entry as Record<string, unknown>).entry_id) return false;
  return true;
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
  const [refundTransaction, setRefundTransaction] = useState<LedgerEntry | null>(null);

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
        <div className="ml-auto flex gap-2">
          <Link to="/billing/refunds">
            <Button variant="outline" size="sm">
              <RotateCcw className="mr-1 h-3.5 w-3.5" />
              My Refund Requests
            </Button>
          </Link>
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

      {/* Per-row refund button */}
      {sorted.some(isEligibleForRefund) && (
        <div className="space-y-1">
          {sorted.filter(isEligibleForRefund).map((entry) => (
            <div key={entry.sk} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
              <span>
                <span className="capitalize">{entry.type?.replace(/_/g, " ")}</span>
                {" — "}{formatCents(entry.amount_cents)} — {formatDate(entry.ts)}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRefundTransaction(entry)}
              >
                <RotateCcw className="mr-1 h-3 w-3" />
                Request Refund
              </Button>
            </div>
          ))}
        </div>
      )}

      <p className="text-xs text-muted-foreground text-right">
        Showing {sorted.length} of {entries.length} entries
      </p>

      <RefundRequestDialog
        transaction={refundTransaction}
        onClose={() => setRefundTransaction(null)}
      />
    </div>
  );
}
