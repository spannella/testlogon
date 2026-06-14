import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Package, Search, ArrowRight } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  getOrderLifecycle,
  ORDER_LIFECYCLE_STATUSES,
  formatCents,
  prettyStatus,
  type OrderLifecycle,
  type OrderLifecycleStatus,
} from "@/api/endpoints/orderLifecycle";
import { OrderStatusBadge } from "./OrderStatusBadge";

const RECENT_KEY = "ord_recent_lookups";

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter((x) => typeof x === "string").slice(0, 20) : [];
  } catch {
    return [];
  }
}

function saveRecent(ids: string[]): void {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(ids.slice(0, 20)));
  } catch {
    /* ignore quota */
  }
}

export default function OrdersPage() {
  const navigate = useNavigate();
  const [lookupId, setLookupId] = useState("");
  const [queryId, setQueryId] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | OrderLifecycleStatus>("all");
  const [recent, setRecent] = useState<string[]>(() => loadRecent());

  const lookupQuery = useQuery<OrderLifecycle, ApiError>({
    queryKey: ["order-lifecycle", "lookup", queryId],
    queryFn: () => getOrderLifecycle(queryId),
    enabled: !!queryId,
    retry: false,
  });

  // Resolve cached lifecycle entries for the recent ids so the table can render
  // a multi-row list (the backend has no list endpoint — each row is a read).
  const recentQueries = useQuery<OrderLifecycle[]>({
    queryKey: ["order-lifecycle", "recent", recent],
    enabled: recent.length > 0,
    retry: false,
    queryFn: async () => {
      const results = await Promise.allSettled(recent.map((id) => getOrderLifecycle(id)));
      return results
        .filter((r): r is PromiseFulfilledResult<OrderLifecycle> => r.status === "fulfilled")
        .map((r) => r.value);
    },
  });

  const rows = useMemo(() => {
    const data = recentQueries.data ?? [];
    // De-dupe + apply status filter.
    const byId = new Map<string, OrderLifecycle>();
    for (const o of data) byId.set(o.order_id, o);
    if (lookupQuery.data) byId.set(lookupQuery.data.order_id, lookupQuery.data);
    let list = Array.from(byId.values());
    if (statusFilter !== "all") {
      list = list.filter(
        (o) => (o.lifecycle_status ?? o.status) === statusFilter,
      );
    }
    return list.sort((a, b) => (b.updated_ts ?? 0) - (a.updated_ts ?? 0));
  }, [recentQueries.data, lookupQuery.data, statusFilter]);

  function runLookup() {
    const id = lookupId.trim();
    if (!id) return;
    setQueryId(id);
    const next = [id, ...recent.filter((r) => r !== id)].slice(0, 20);
    setRecent(next);
    saveRecent(next);
  }

  const featureDisabled =
    lookupQuery.error?.status === 503 ||
    (recentQueries.error instanceof ApiError && recentQueries.error.status === 503);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Orders"
        description="Look up an order by ID, inspect its lifecycle status, and manage transitions."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Find an order</CardTitle>
          <CardDescription>
            Enter an order ID to load its lifecycle. Recent lookups are kept below.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              runLookup();
            }}
          >
            <div className="flex-1 space-y-1">
              <Label htmlFor="ord-lookup">Order ID</Label>
              <Input
                id="ord-lookup"
                placeholder="e.g. ord_abc123"
                value={lookupId}
                onChange={(e) => setLookupId(e.target.value)}
              />
            </div>
            <div className="w-full sm:w-56 space-y-1">
              <Label htmlFor="ord-status-filter">Status</Label>
              <Select
                value={statusFilter}
                onValueChange={(v) => setStatusFilter(v as "all" | OrderLifecycleStatus)}
              >
                <SelectTrigger id="ord-status-filter">
                  <SelectValue placeholder="All statuses" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All statuses</SelectItem>
                  {ORDER_LIFECYCLE_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {prettyStatus(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button type="submit" disabled={!lookupId.trim()}>
              <Search className="mr-2 h-4 w-4" />
              Look up
            </Button>
          </form>

          {queryId && lookupQuery.isError && !featureDisabled && (
            <p className="mt-3 text-sm text-destructive">
              {lookupQuery.error?.status === 404
                ? `No order found with ID "${queryId}" (or you don't have access to it).`
                : lookupQuery.error?.message || "Unable to load that order."}
            </p>
          )}
        </CardContent>
      </Card>

      {featureDisabled && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            <Package className="mx-auto mb-3 h-8 w-8 opacity-40" />
            Order lifecycle is not enabled on this environment.
          </CardContent>
        </Card>
      )}

      {!featureDisabled && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Orders</CardTitle>
            <CardDescription>
              {statusFilter === "all"
                ? "Looked-up orders"
                : `Looked-up orders · ${prettyStatus(statusFilter)}`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {(lookupQuery.isFetching || recentQueries.isLoading) && rows.length === 0 ? (
              <div className="space-y-2">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : rows.length === 0 ? (
              <div className="py-10 text-center text-sm text-muted-foreground">
                <Package className="mx-auto mb-3 h-8 w-8 opacity-40" />
                {recent.length === 0
                  ? "No orders yet. Look up an order by ID to get started."
                  : "No orders match the current filter."}
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Order ID</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Items</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((o) => (
                    <TableRow
                      key={o.order_id}
                      className="cursor-pointer"
                      onClick={() => navigate(`/orders/${encodeURIComponent(o.order_id)}`)}
                    >
                      <TableCell className="font-mono text-xs">{o.order_id}</TableCell>
                      <TableCell>
                        <OrderStatusBadge status={o.lifecycle_status ?? o.status} />
                      </TableCell>
                      <TableCell className="text-right">{o.line_item_count}</TableCell>
                      <TableCell className="text-right">
                        {formatCents(o.amount_cents, o.currency)}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {o.updated_at
                          ? new Date(o.updated_at).toLocaleString()
                          : "—"}
                      </TableCell>
                      <TableCell>
                        <Link
                          to={`/orders/${encodeURIComponent(o.order_id)}`}
                          onClick={(e) => e.stopPropagation()}
                          aria-label={`Open order ${o.order_id}`}
                        >
                          <ArrowRight className="h-4 w-4 text-muted-foreground" />
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {recent.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Recent:</span>
          {recent.slice(0, 8).map((id) => (
            <Badge
              key={id}
              variant="outline"
              className="cursor-pointer font-mono"
              onClick={() => {
                setLookupId(id);
                setQueryId(id);
              }}
            >
              {id}
            </Badge>
          ))}
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs"
            onClick={() => {
              setRecent([]);
              saveRecent([]);
            }}
          >
            Clear
          </Button>
        </div>
      )}
    </div>
  );
}
