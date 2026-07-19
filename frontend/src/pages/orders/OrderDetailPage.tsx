import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Ban, History, Package, Truck, Tag } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import { ApiError } from "@/api/client";
import {
  cancelOrder,
  getOrderLifecycle,
  transitionOrder,
  formatCents,
  prettyStatus,
  type OrderLifecycle,
  type OrderLifecycleStatus,
} from "@/api/endpoints/orderLifecycle";
import { OrderShipmentTracking } from "@/components/shared/ShipmentTracking";
import { OrderStatusBadge } from "./OrderStatusBadge";

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const OWNER_CANCELLABLE = new Set(["created", "approved"]);

export default function OrderDetailPage() {
  const { orderId = "" } = useParams<{ orderId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [transitionReason, setTransitionReason] = useState("");
  const [pendingTransition, setPendingTransition] = useState<OrderLifecycleStatus | null>(null);
  const [cancelOpen, setCancelOpen] = useState(false);
  const [cancelReason, setCancelReason] = useState("");
  const [cancelRefund, setCancelRefund] = useState(false);

  const detailQuery = useQuery<OrderLifecycle, ApiError>({
    queryKey: ["order-lifecycle", "detail", orderId],
    queryFn: () => getOrderLifecycle(orderId, ["history", "adjustments", "ship_groups"]),
    enabled: !!orderId,
    retry: false,
  });

  const order = detailQuery.data;

  const refresh = () => {
    void detailQuery.refetch();
    void qc.invalidateQueries({ queryKey: ["order-lifecycle"] });
  };

  const transitionMut = useMutation({
    mutationFn: (target: OrderLifecycleStatus) =>
      transitionOrder(orderId, {
        target_status: target,
        reason: transitionReason.trim() || undefined,
      }),
    onSuccess: (res) => {
      toast.success(`Order moved to ${prettyStatus(res.to_status)}`);
      setTransitionReason("");
      setPendingTransition(null);
      refresh();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to transition order"),
  });

  const cancelMut = useMutation({
    mutationFn: () =>
      cancelOrder(orderId, {
        reason: cancelReason.trim() || undefined,
        refund: cancelRefund,
      }),
    onSuccess: () => {
      toast.success("Order cancelled");
      setCancelOpen(false);
      setCancelReason("");
      setCancelRefund(false);
      refresh();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to cancel order"),
  });

  const allowedTransitions = useMemo<OrderLifecycleStatus[]>(
    () => (order?.allowed_transitions ?? []) as OrderLifecycleStatus[],
    [order?.allowed_transitions],
  );

  const currentStatus = order?.lifecycle_status ?? null;
  const canOwnerCancel =
    !!currentStatus && OWNER_CANCELLABLE.has(currentStatus);
  const showCancel =
    !!order &&
    currentStatus !== "cancelled" &&
    currentStatus !== "returned" &&
    (isAdmin || canOwnerCancel);

  // ── Loading / error states ────────────────────────────────────────────────
  if (detailQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (detailQuery.isError) {
    const status = detailQuery.error?.status;
    const disabled = status === 503;
    const notFound = status === 404;
    return (
      <div className="space-y-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/orders")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to orders
        </Button>
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            <Package className="mx-auto mb-3 h-8 w-8 opacity-40" />
            {disabled
              ? "Order lifecycle is not enabled on this environment."
              : notFound
                ? `No order found with ID "${orderId}" (or you don't have access to it).`
                : detailQuery.error?.message || "Unable to load this order."}
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!order) return null;

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => navigate("/orders")}>
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to orders
      </Button>

      <PageHeader
        title={`Order ${order.order_id}`}
        description={`${order.source_system || "order"} · ${order.line_item_count} line item${order.line_item_count === 1 ? "" : "s"}`}
        actions={<OrderStatusBadge status={currentStatus ?? order.status} />}
      />

      {/* Summary */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total</CardDescription>
            <CardTitle className="text-xl">
              {formatCents(order.amount_cents, order.currency)}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Status</CardDescription>
            <CardTitle className="text-xl">
              {prettyStatus(currentStatus ?? order.status)}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Created</CardDescription>
            <CardTitle className="text-sm font-medium">
              {order.created_at ? new Date(order.created_at).toLocaleString() : "—"}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Updated</CardDescription>
            <CardTitle className="text-sm font-medium">
              {order.updated_at ? new Date(order.updated_at).toLocaleString() : "—"}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Actions */}
      {(allowedTransitions.length > 0 || showCancel) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Actions</CardTitle>
            <CardDescription>
              {isAdmin
                ? "Move the order through its lifecycle or cancel it."
                : "Cancel this order if it has not yet been processed."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {isAdmin && allowedTransitions.length > 0 && (
              <>
                <div className="space-y-1">
                  <Label htmlFor="transition-reason">Reason (optional)</Label>
                  <Input
                    id="transition-reason"
                    placeholder="Reason for this transition"
                    value={transitionReason}
                    onChange={(e) => setTransitionReason(e.target.value)}
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  {allowedTransitions.map((t) => (
                    <Button
                      key={t}
                      variant={t === "cancelled" ? "destructive" : "default"}
                      size="sm"
                      disabled={transitionMut.isPending}
                      onClick={() => {
                        setPendingTransition(t);
                        transitionMut.mutate(t);
                      }}
                    >
                      {transitionMut.isPending && pendingTransition === t
                        ? "Working…"
                        : `Move to ${prettyStatus(t)}`}
                    </Button>
                  ))}
                </div>
              </>
            )}
            {!isAdmin && allowedTransitions.length === 0 && showCancel && (
              <p className="text-sm text-muted-foreground">
                You can cancel this order while it is still in an early stage.
              </p>
            )}
            {showCancel && (
              <>
                <Separator />
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => setCancelOpen(true)}
                >
                  <Ban className="mr-2 h-4 w-4" />
                  Cancel order
                </Button>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* Line items */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Package className="h-4 w-4" />
            Line items
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!order.line_items || order.line_items.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No line items on this order.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Item</TableHead>
                  <TableHead>SKU</TableHead>
                  <TableHead className="text-right">Qty</TableHead>
                  <TableHead className="text-right">Unit price</TableHead>
                  <TableHead className="text-right">Line total</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {order.line_items.map((li) => (
                  <TableRow key={li.item_id}>
                    <TableCell className="font-medium">{li.name || li.item_id}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {li.sku || "—"}
                    </TableCell>
                    <TableCell className="text-right">{li.quantity}</TableCell>
                    <TableCell className="text-right">
                      {formatCents(li.unit_price_cents, li.currency)}
                    </TableCell>
                    <TableCell className="text-right">
                      {formatCents(li.unit_price_cents * li.quantity, li.currency)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Adjustments */}
      {order.adjustments && order.adjustments.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Tag className="h-4 w-4" />
              Adjustments
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead className="text-right">Amount</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {order.adjustments.map((adj) => (
                  <TableRow key={adj.adjustment_id}>
                    <TableCell>{prettyStatus(adj.adj_type)}</TableCell>
                    <TableCell>{adj.label || "—"}</TableCell>
                    <TableCell className="text-right">
                      {formatCents(adj.amount_cents, adj.currency)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* ECOMX-E1/E2: buyer-visible shipment tracking (carrier/number/status) */}
      {order.shipments && order.shipments.some((s) => s.carrier || s.tracking_number || s.status) && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Truck className="h-4 w-4" />
              Tracking
            </CardTitle>
            <CardDescription>Where your order is right now.</CardDescription>
          </CardHeader>
          <CardContent>
            <OrderShipmentTracking
              shipments={order.shipments}
              fulfillmentStatus={order.fulfillment_status}
            />
          </CardContent>
        </Card>
      )}

      {/* Ship groups */}
      {order.ship_groups && order.ship_groups.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Truck className="h-4 w-4" />
              Ship groups
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {order.ship_groups.map((sg) => (
              <div
                key={sg.ship_group_id}
                className="flex items-center justify-between rounded-md border p-3 text-sm"
              >
                <div>
                  <div className="font-medium">{sg.ship_method || "Ship group"}</div>
                  <div className="text-xs text-muted-foreground">
                    {sg.item_ids.length} item{sg.item_ids.length === 1 ? "" : "s"}
                    {sg.tracking_number ? ` · ${sg.tracking_number}` : ""}
                  </div>
                </div>
                <OrderStatusBadge status={sg.ship_status} />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Status timeline */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <History className="h-4 w-4" />
            Status timeline
          </CardTitle>
          <CardDescription>Most recent first.</CardDescription>
        </CardHeader>
        <CardContent>
          {!order.status_history || order.status_history.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No status history recorded.
            </p>
          ) : (
            <ol className="relative space-y-4 border-l pl-6">
              {order.status_history.map((h) => (
                <li key={h.event_id} className="relative">
                  <span className="absolute -left-[27px] top-1 h-3 w-3 rounded-full border-2 border-background bg-primary" />
                  <div className="flex flex-wrap items-center gap-2">
                    {h.from_status && (
                      <>
                        <Badge variant="outline">{prettyStatus(h.from_status)}</Badge>
                        <span className="text-muted-foreground">→</span>
                      </>
                    )}
                    <OrderStatusBadge status={h.to_status} />
                    <span className="text-xs text-muted-foreground">{fmtTs(h.ts)}</span>
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    by {h.actor}
                    {h.reason ? ` · ${h.reason}` : ""}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>

      <div>
        <Link to="/orders" className="text-sm text-muted-foreground hover:underline">
          ← Back to orders
        </Link>
      </div>

      {/* Cancel dialog */}
      <Dialog open={cancelOpen} onOpenChange={setCancelOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel order</DialogTitle>
            <DialogDescription>
              This will move the order to the cancelled state. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="cancel-reason">Reason (optional)</Label>
              <Input
                id="cancel-reason"
                placeholder="Why is this order being cancelled?"
                value={cancelReason}
                onChange={(e) => setCancelReason(e.target.value)}
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={cancelRefund}
                onCheckedChange={(v) => setCancelRefund(v === true)}
              />
              Issue a refund for this order
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCancelOpen(false)}>
              Keep order
            </Button>
            <Button
              variant="destructive"
              disabled={cancelMut.isPending}
              onClick={() => cancelMut.mutate()}
            >
              {cancelMut.isPending ? "Cancelling…" : "Cancel order"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
