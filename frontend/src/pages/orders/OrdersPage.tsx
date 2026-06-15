import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Package, Search, ArrowRight } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
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
  listOrders,
  ORDER_LIFECYCLE_STATUSES,
  formatCents,
  prettyStatus,
  type OrderListOut,
  type OrderLifecycleStatus,
} from "@/api/endpoints/orderLifecycle";
import { OrderStatusBadge } from "./OrderStatusBadge";

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function OrdersPage() {
  const navigate = useNavigate();
  const [lookupId, setLookupId] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | OrderLifecycleStatus>("all");
  // Cursor stack so "Previous" works without re-querying from scratch.
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursorStack[cursorStack.length - 1];

  const ordersQuery = useQuery<OrderListOut, ApiError>({
    queryKey: ["orders", "list", statusFilter, cursor ?? null],
    queryFn: () =>
      listOrders({
        status: statusFilter === "all" ? undefined : statusFilter,
        cursor,
        limit: 50,
      }),
    retry: false,
  });

  const featureDisabled = ordersQuery.error?.status === 503;
  const orders = ordersQuery.data?.orders ?? [];
  const nextCursor = ordersQuery.data?.next_cursor ?? null;

  function resetPaging(next: "all" | OrderLifecycleStatus) {
    setStatusFilter(next);
    setCursorStack([undefined]);
  }

  function goNext() {
    if (nextCursor) setCursorStack((s) => [...s, nextCursor]);
  }

  function goPrev() {
    setCursorStack((s) => (s.length > 1 ? s.slice(0, -1) : s));
  }

  function openLookup() {
    const id = lookupId.trim();
    if (!id) return;
    navigate(`/orders/${encodeURIComponent(id)}`);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Orders"
        description="Browse your orders, inspect lifecycle status, and manage transitions."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Jump to an order</CardTitle>
          <CardDescription>
            Know the ID? Enter it to open the order directly.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              openLookup();
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
            <Button type="submit" disabled={!lookupId.trim()}>
              <Search className="mr-2 h-4 w-4" />
              Open
            </Button>
          </form>
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
          <CardHeader className="flex flex-row flex-wrap items-end justify-between gap-3 space-y-0">
            <div>
              <CardTitle className="text-base">Orders</CardTitle>
              <CardDescription>
                {statusFilter === "all"
                  ? "Your most recent orders"
                  : `Filtered by ${prettyStatus(statusFilter)}`}
              </CardDescription>
            </div>
            <div className="w-full sm:w-56 space-y-1">
              <Label htmlFor="ord-status-filter" className="text-xs">
                Status
              </Label>
              <Select
                value={statusFilter}
                onValueChange={(v) => resetPaging(v as "all" | OrderLifecycleStatus)}
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
          </CardHeader>
          <CardContent className="space-y-3">
            {ordersQuery.isError && !featureDisabled && (
              <p className="text-sm text-destructive">
                {ordersQuery.error?.message || "Unable to load orders."}
              </p>
            )}

            {ordersQuery.isLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : orders.length === 0 ? (
              <div className="py-10 text-center text-sm text-muted-foreground">
                <Package className="mx-auto mb-3 h-8 w-8 opacity-40" />
                {statusFilter === "all"
                  ? "No orders yet."
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
                  {orders.map((o) => (
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
                        {fmtTs(o.updated_at)}
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

            {(cursorStack.length > 1 || nextCursor) && (
              <div className="flex justify-end gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={cursorStack.length <= 1 || ordersQuery.isFetching}
                  onClick={goPrev}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!nextCursor || ordersQuery.isFetching}
                  onClick={goNext}
                >
                  Next
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
