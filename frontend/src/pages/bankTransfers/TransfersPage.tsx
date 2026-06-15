/**
 * TransfersPage — TXR-002
 *
 * Lists all transaction requests for the current user with filtering by status.
 * Handles feature flag off (404) gracefully.
 *
 * Route: /bank/transfers
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeftRight,
  Plus,
  AlertCircle,
  Loader2,
  RefreshCw,
  ChevronRight,
  InboxIcon,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  listTxnRequests,
  type TxnRequestOut,
  type TxnRequestStatus,
} from "@/api/endpoints/txnRequests";
import { ApiError } from "@/api/client";

import {
  formatCurrency,
  fmtTs,
  STATUS_BADGE,
  STATUS_LABEL,
  TYPE_LABEL,
} from "./txrUtils";

// ─── Status filter options ────────────────────────────────────────────────────

// Radix <SelectItem> forbids an empty-string value, so "all" is used as the
// sentinel for the no-filter option and mapped back to "" in state.
const ALL_STATUSES = "all";
const STATUS_OPTIONS: { label: string; value: TxnRequestStatus | typeof ALL_STATUSES }[] = [
  { label: "All statuses", value: ALL_STATUSES },
  { label: "Initiated", value: "INITIATED" },
  { label: "Pending SCA", value: "PENDING" },
  { label: "Processing", value: "IN_FLIGHT" },
  { label: "Completed", value: "COMPLETED" },
  { label: "Failed", value: "FAILED" },
];

// ─── Row component ────────────────────────────────────────────────────────────

function TxnRow({ txn }: { txn: TxnRequestOut }) {
  return (
    <Link
      to={`/bank/transfers/${txn.request_id}`}
      className="flex items-center gap-3 p-3 rounded-lg hover:bg-muted/50 transition-colors group"
    >
      <div className="rounded-full bg-muted p-2">
        <ArrowLeftRight className="h-4 w-4 text-muted-foreground" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-sm">
            {formatCurrency(txn.amount_cents, txn.currency)}
          </span>
          <Badge
            className={`text-xs ${STATUS_BADGE[txn.status as keyof typeof STATUS_BADGE] ?? ""}`}
            variant="outline"
          >
            {STATUS_LABEL[txn.status as keyof typeof STATUS_LABEL] ?? txn.status}
          </Badge>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5 flex-wrap">
          <span>{TYPE_LABEL[txn.type as keyof typeof TYPE_LABEL] ?? txn.type}</span>
          <span>·</span>
          <span>{fmtTs(txn.created_at)}</span>
          {txn.failure_reason && (
            <>
              <span>·</span>
              <span className="text-red-500">{txn.failure_reason}</span>
            </>
          )}
        </div>
        <p className="text-xs font-mono text-muted-foreground truncate mt-0.5">
          {txn.request_id}
        </p>
      </div>

      <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
    </Link>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function TransfersPage() {
  const [statusFilter, setStatusFilter] = useState<TxnRequestStatus | "">("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [allItems, setAllItems] = useState<TxnRequestOut[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const { isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ["txnRequests", "list", statusFilter, cursor],
    queryFn: async () => {
      const result = await listTxnRequests({
        status: statusFilter || undefined,
        cursor,
        limit: 20,
      });
      if (cursor) {
        // Append new page
        setAllItems((prev) => [...prev, ...result.items]);
      } else {
        setAllItems(result.items);
      }
      setNextCursor(result.next_cursor);
      return result;
    },
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  function handleStatusChange(val: string) {
    setStatusFilter(val === ALL_STATUSES ? "" : (val as TxnRequestStatus));
    setCursor(undefined);
    setAllItems([]);
    setNextCursor(null);
  }

  function handleLoadMore() {
    if (nextCursor) {
      setCursor(nextCursor);
    }
  }

  // ── Feature disabled ───────────────────────────────────────────────────────

  if (isError) {
    const apiErr = error instanceof ApiError ? error : null;
    const disabled = apiErr && (apiErr.status === 404 || apiErr.status === 503);

    return (
      <div className="space-y-6 p-4 sm:p-6 max-w-2xl">
        <PageHeader
          title="Transfers"
          description="Transaction requests and money movement"
        />
        <Card className="border-amber-200 bg-amber-50 dark:bg-amber-950 dark:border-amber-800">
          <CardContent className="pt-6 flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-amber-600 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-medium text-amber-800 dark:text-amber-200">
                {disabled
                  ? "Transaction requests are not currently enabled."
                  : "Could not load transfers"}
              </p>
              {!disabled && apiErr && (
                <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                  {apiErr.detail}
                </p>
              )}
              {disabled && (
                <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                  Contact your administrator to enable the Transaction Requests feature.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── Main view ──────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6 p-4 sm:p-6 max-w-3xl">
      <PageHeader
        title="Transfers"
        description="Transaction requests and money movement"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => {
                setCursor(undefined);
                setAllItems([]);
                setNextCursor(null);
                refetch();
              }}
              disabled={isFetching}
              title="Refresh"
            >
              <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
            </Button>
            <Button asChild size="sm">
              <Link to="/bank/transfers/new">
                <Plus className="mr-2 h-4 w-4" />
                New Transfer
              </Link>
            </Button>
          </div>
        }
      />

      {/* Status filter */}
      <div className="flex items-center gap-3">
        <Select value={statusFilter || ALL_STATUSES} onValueChange={handleStatusChange}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {statusFilter && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleStatusChange("")}
          >
            Clear filter
          </Button>
        )}
      </div>

      {/* Loading skeleton */}
      {isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground py-4">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading transfers…
        </div>
      )}

      {/* List */}
      {!isLoading && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {allItems.length > 0
                ? `${allItems.length} transfer${allItems.length !== 1 ? "s" : ""}${nextCursor ? "+" : ""}`
                : "Transfers"}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {allItems.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-10 text-muted-foreground">
                <InboxIcon className="h-8 w-8" />
                <p className="text-sm">No transfers yet</p>
                <Button asChild size="sm" variant="outline" className="mt-1">
                  <Link to="/bank/transfers/new">
                    <Plus className="mr-2 h-4 w-4" />
                    Create your first transfer
                  </Link>
                </Button>
              </div>
            ) : (
              <div className="divide-y">
                {allItems.map((txn) => (
                  <TxnRow key={txn.request_id} txn={txn} />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Load more */}
      {nextCursor && !isLoading && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            size="sm"
            onClick={handleLoadMore}
            disabled={isFetching}
          >
            {isFetching && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}
