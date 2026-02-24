import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Package, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { listTransactions, searchTransactions } from "@/api/endpoints/purchases";
import type { PurchaseTransactionSummary } from "@/api/types";

const STATUS_FILTERS = ["all", "pending", "completed", "cancelled", "reverted"] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

function statusVariant(status: string) {
  switch (status) {
    case "completed":
      return "success" as const;
    case "pending":
      return "warning" as const;
    case "cancelled":
      return "neutral" as const;
    case "reverted":
      return "danger" as const;
    default:
      return "info" as const;
  }
}

function formatCurrency(amount: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(amount);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function PurchaseHistory() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  // Debounced search
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const debounceTimer = useMemo(() => {
    return (value: string) => {
      const id = setTimeout(() => setDebouncedQuery(value), 300);
      return () => clearTimeout(id);
    };
  }, []);

  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    debounceTimer(value);
  };

  const isSearchMode = debouncedQuery.trim().length > 0;

  // Fetch transactions — either search or list
  const listQuery = useQuery({
    queryKey: ["purchases", "list", statusFilter],
    queryFn: () =>
      listTransactions({
        limit: 50,
        status: statusFilter !== "all" ? statusFilter.toUpperCase() : undefined,
      }),
    enabled: !isSearchMode,
  });

  const searchQueryResult = useQuery({
    queryKey: ["purchases", "search", debouncedQuery],
    queryFn: () => searchTransactions(debouncedQuery, 50),
    enabled: isSearchMode,
  });

  const activeQuery = isSearchMode ? searchQueryResult : listQuery;
  const transactions: PurchaseTransactionSummary[] = activeQuery.data ?? [];

  // Apply client-side status filter to search results
  const filtered = isSearchMode && statusFilter !== "all"
    ? transactions.filter((t) => t.status === statusFilter)
    : transactions;

  const isLoading = activeQuery.isLoading;

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search orders..."
          value={searchQuery}
          onChange={(e) => handleSearchChange(e.target.value)}
          className="pl-9"
        />
      </div>

      {/* Status filter chips */}
      <div className="flex flex-wrap gap-2">
        {STATUS_FILTERS.map((status) => (
          <Button
            key={status}
            size="sm"
            variant={statusFilter === status ? "default" : "outline"}
            onClick={() => setStatusFilter(status)}
            className="capitalize"
          >
            {status}
          </Button>
        ))}
      </div>

      {/* Transaction list */}
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20 w-full rounded-xl" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Package className="h-8 w-8" />}
          title={isSearchMode ? "No matching orders" : "No orders yet"}
          description={
            isSearchMode
              ? "Try a different search term or filter."
              : "Your purchase history will appear here after your first order."
          }
          action={
            !isSearchMode
              ? { label: "Browse Shop", onClick: () => navigate("/shop") }
              : undefined
          }
        />
      ) : (
        <div className="space-y-2">
          {filtered.map((txn) => (
            <Card
              key={txn.txn_id}
              className="cursor-pointer transition-colors hover:bg-accent/50"
              onClick={() => navigate(`/purchases/${txn.txn_id}`)}
            >
              <CardContent className="flex items-center gap-4 p-4">
                {/* Icon */}
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted">
                  <Package className="h-5 w-5 text-muted-foreground" />
                </div>

                {/* Details */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium">
                      {txn.description ?? `Order ${txn.txn_id.slice(0, 8)}...`}
                    </p>
                    <StatusBadge variant={statusVariant(txn.status)} className="shrink-0">
                      {txn.status}
                    </StatusBadge>
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                    <span>{formatDate(txn.created_at)}</span>
                    {txn.merchant_id && <span>Merchant: {txn.merchant_id}</span>}
                    {txn.external_ref && <span>Ref: {txn.external_ref}</span>}
                  </div>
                </div>

                {/* Amount */}
                <p className="shrink-0 text-sm font-semibold">
                  {formatCurrency(txn.amount, txn.currency)}
                </p>
              </CardContent>
            </Card>
          ))}

          {activeQuery.isFetching && !isLoading && (
            <div className="flex justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
