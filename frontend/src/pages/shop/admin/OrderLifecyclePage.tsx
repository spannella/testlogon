/**
 * OrderLifecyclePage (ORD-014)
 *
 * Admin page for managing the full lifecycle of a single order.
 * Route: /shop/admin/orders/:orderId/lifecycle
 *
 * Gated by VITE_ORDER_LIFECYCLE_ENABLED="true". When the flag is off a
 * placeholder is shown so the route doesn't 404.
 *
 * Tabs:
 *   Overview    — current status, allowed transitions, cancel
 *   Adjustments — add / remove price adjustments
 *   Ship Groups — add ship groups, update tracking numbers
 *   History     — status-transition timeline
 */

import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Loader2,
  PackageCheck,
  AlertTriangle,
  RefreshCw,
  Truck,
  CircleDollarSign,
  History,
  XCircle,
  Plus,
  Trash2,
  CheckCircle2,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

import {
  getOrderLifecycle,
  getOrderHistory,
  transitionOrder,
  cancelOrder,
  listOrderAdjustments,
  addOrderAdjustment,
  removeOrderAdjustment,
  listShipGroups,
  createShipGroup,
  updateShipGroup,
  deleteShipGroup,
  formatCents,
  prettyStatus,
  type OrderLifecycle,
  type OrderLifecycleStatus,
  type OrderAdjustmentType,
} from "@/api/endpoints/orderLifecycle";

// ─── Feature gate ─────────────────────────────────────────────────────────────

const LIFECYCLE_ENABLED =
  (import.meta as any).env?.VITE_ORDER_LIFECYCLE_ENABLED === "true";

// ─── Status colour mapping ────────────────────────────────────────────────────

function statusVariant(
  status: string | null | undefined,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "completed":
      return "default";
    case "cancelled":
    case "returned":
      return "destructive";
    case "held":
    case "backorder":
      return "secondary";
    default:
      return "outline";
  }
}

// ─── Overview tab ─────────────────────────────────────────────────────────────

function OverviewTab({ order }: { order: OrderLifecycle }) {
  const qc = useQueryClient();
  const orderId = order.order_id;

  const transitionMut = useMutation({
    mutationFn: (targetStatus: OrderLifecycleStatus) =>
      transitionOrder(orderId, { target_status: targetStatus }),
    onSuccess: (res) => {
      toast.success(`Order moved to "${prettyStatus(res.to_status)}"`);
      qc.invalidateQueries({ queryKey: ["orderLifecycle", orderId] });
      qc.invalidateQueries({ queryKey: ["orderHistory", orderId] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const cancelMut = useMutation({
    mutationFn: (reason: string) =>
      cancelOrder(orderId, { reason: reason || undefined }),
    onSuccess: () => {
      toast.success("Order cancelled");
      qc.invalidateQueries({ queryKey: ["orderLifecycle", orderId] });
      qc.invalidateQueries({ queryKey: ["orderHistory", orderId] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const [cancelReason, setCancelReason] = useState("");

  const allowed = order.allowed_transitions ?? [];
  const isCancelled =
    order.lifecycle_status === "cancelled" ||
    order.lifecycle_status === "returned" ||
    order.lifecycle_status === "completed";

  return (
    <div className="space-y-6">
      {/* Status card */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Current Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-4">
            <Badge
              variant={statusVariant(order.lifecycle_status)}
              className="text-base px-3 py-1"
            >
              {prettyStatus(order.lifecycle_status)}
            </Badge>
            <span className="text-sm text-muted-foreground">
              Order{" "}
              <span className="font-mono text-foreground">{order.order_id}</span>
            </span>
            <span className="text-sm text-muted-foreground">
              {formatCents(order.amount_cents, order.currency)}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Transition buttons */}
      {allowed.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">
              Allowed Transitions
            </CardTitle>
            <CardDescription>
              Move this order to one of the next valid states.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {allowed.map((target) => (
                <Button
                  key={target}
                  variant="outline"
                  size="sm"
                  disabled={transitionMut.isPending}
                  onClick={() =>
                    transitionMut.mutate(target as OrderLifecycleStatus)
                  }
                >
                  {transitionMut.isPending &&
                  transitionMut.variables === target ? (
                    <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                  ) : (
                    <RefreshCw className="mr-1 h-3 w-3" />
                  )}
                  {prettyStatus(target)}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cancel */}
      {!isCancelled && (
        <Card className="border-destructive/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-destructive">
              Cancel Order
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-3">
              <div className="flex-1 space-y-1">
                <Label htmlFor="cancel-reason">Reason (optional)</Label>
                <Input
                  id="cancel-reason"
                  placeholder="e.g. Customer request"
                  value={cancelReason}
                  onChange={(e) => setCancelReason(e.target.value)}
                />
              </div>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button variant="destructive" size="sm">
                    <XCircle className="mr-1 h-4 w-4" /> Cancel Order
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Cancel this order?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This will move the order to "Cancelled" status. This
                      action may be irreversible.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Keep Order</AlertDialogCancel>
                    <AlertDialogAction
                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      onClick={() => cancelMut.mutate(cancelReason)}
                    >
                      {cancelMut.isPending ? (
                        <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                      ) : null}
                      Cancel Order
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Metadata */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Order Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">Order ID</dt>
              <dd className="font-mono break-all">{order.order_id}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Amount</dt>
              <dd>{formatCents(order.amount_cents, order.currency)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Currency</dt>
              <dd>{order.currency}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Source System</dt>
              <dd>{String(order.source_system ?? "—")}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{order.created_at}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Line Items</dt>
              <dd>{order.line_item_count ?? 0}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Adjustments tab ──────────────────────────────────────────────────────────

function AdjustmentsTab({ orderId }: { orderId: string }) {
  const qc = useQueryClient();

  const adjQuery = useQuery({
    queryKey: ["orderAdjustments", orderId],
    queryFn: () => listOrderAdjustments(orderId),
  });

  const addMut = useMutation({
    mutationFn: (body: {
      adj_type: OrderAdjustmentType;
      amount_cents: number;
      label: string;
    }) => addOrderAdjustment(orderId, { ...body, taxable: false }),
    onSuccess: () => {
      toast.success("Adjustment added");
      qc.invalidateQueries({ queryKey: ["orderAdjustments", orderId] });
      setForm({ adj_type: "discount", amount: "", label: "" });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const removeMut = useMutation({
    mutationFn: (adjId: string) => removeOrderAdjustment(orderId, adjId),
    onSuccess: () => {
      toast.success("Adjustment removed");
      qc.invalidateQueries({ queryKey: ["orderAdjustments", orderId] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const [form, setForm] = useState<{
    adj_type: string;
    amount: string;
    label: string;
  }>({ adj_type: "discount", amount: "", label: "" });

  const adjustments = adjQuery.data?.adjustments ?? [];
  const total = adjQuery.data?.total_adjustments_cents ?? 0;

  return (
    <div className="space-y-6">
      {/* Add adjustment form */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Add Adjustment</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-4">
            <div className="space-y-1">
              <Label>Type</Label>
              <Select
                value={form.adj_type}
                onValueChange={(v) => setForm((f) => ({ ...f, adj_type: v }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(
                    [
                      "discount",
                      "surcharge",
                      "tax",
                      "shipping",
                      "promotion",
                    ] as OrderAdjustmentType[]
                  ).map((t) => (
                    <SelectItem key={t} value={t}>
                      {prettyStatus(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1 sm:col-span-2">
              <Label>Label</Label>
              <Input
                placeholder="e.g. 10% loyalty discount"
                value={form.label}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
              />
            </div>
            <div className="space-y-1">
              <Label>Amount (cents)</Label>
              <Input
                type="number"
                placeholder="e.g. 500"
                value={form.amount}
                onChange={(e) =>
                  setForm((f) => ({ ...f, amount: e.target.value }))
                }
              />
            </div>
          </div>
          <div className="mt-3 flex justify-end">
            <Button
              size="sm"
              disabled={
                addMut.isPending ||
                !form.label.trim() ||
                !form.amount ||
                Number.isNaN(Number(form.amount))
              }
              onClick={() =>
                addMut.mutate({
                  adj_type: form.adj_type as OrderAdjustmentType,
                  amount_cents: Number(form.amount),
                  label: form.label.trim(),
                })
              }
            >
              {addMut.isPending ? (
                <Loader2 className="mr-1 h-4 w-4 animate-spin" />
              ) : (
                <Plus className="mr-1 h-4 w-4" />
              )}
              Add
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Adjustments table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            Adjustments
            {total !== 0 && (
              <span className="ml-2 text-muted-foreground font-normal">
                Total: {formatCents(total)}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {adjQuery.isLoading ? (
            <div className="p-4 space-y-2">
              {[1, 2].map((i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : adjustments.length === 0 ? (
            <p className="p-6 text-center text-sm text-muted-foreground">
              No adjustments yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead className="text-right">Amount</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {adjustments.map((adj) => (
                  <TableRow key={adj.adjustment_id}>
                    <TableCell>
                      <Badge variant="outline">{prettyStatus(adj.adj_type)}</Badge>
                    </TableCell>
                    <TableCell>{adj.label}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(adj.amount_cents, adj.currency)}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-destructive"
                        disabled={removeMut.isPending}
                        onClick={() => removeMut.mutate(adj.adjustment_id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Ship groups tab ──────────────────────────────────────────────────────────

function ShipGroupsTab({ orderId }: { orderId: string }) {
  const qc = useQueryClient();

  const sgQuery = useQuery({
    queryKey: ["orderShipGroups", orderId],
    queryFn: () => listShipGroups(orderId),
  });

  const createMut = useMutation({
    mutationFn: (body: { ship_method: string; address_id: string }) =>
      createShipGroup(orderId, { ...body }),
    onSuccess: () => {
      toast.success("Ship group created");
      qc.invalidateQueries({ queryKey: ["orderShipGroups", orderId] });
      setSgForm({ ship_method: "standard", address_id: "" });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const updateMut = useMutation({
    mutationFn: ({
      sgId,
      tracking,
    }: {
      sgId: string;
      tracking: string;
    }) => updateShipGroup(orderId, sgId, { tracking_number: tracking || null }),
    onSuccess: () => {
      toast.success("Tracking updated");
      qc.invalidateQueries({ queryKey: ["orderShipGroups", orderId] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteMut = useMutation({
    mutationFn: (sgId: string) => deleteShipGroup(orderId, sgId),
    onSuccess: () => {
      toast.success("Ship group removed");
      qc.invalidateQueries({ queryKey: ["orderShipGroups", orderId] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const [sgForm, setSgForm] = useState({ ship_method: "standard", address_id: "" });
  const [trackingEdits, setTrackingEdits] = useState<Record<string, string>>({});

  const groups = sgQuery.data?.ship_groups ?? [];

  return (
    <div className="space-y-6">
      {/* Create ship group */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Add Ship Group</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1">
              <Label>Ship Method</Label>
              <Select
                value={sgForm.ship_method}
                onValueChange={(v) =>
                  setSgForm((f) => ({ ...f, ship_method: v }))
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {["standard", "express", "overnight", "freight"].map((m) => (
                    <SelectItem key={m} value={m}>
                      {prettyStatus(m)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1 sm:col-span-2">
              <Label>Address ID (optional)</Label>
              <Input
                placeholder="e.g. addr_abc123"
                value={sgForm.address_id}
                onChange={(e) =>
                  setSgForm((f) => ({ ...f, address_id: e.target.value }))
                }
              />
            </div>
          </div>
          <div className="mt-3 flex justify-end">
            <Button
              size="sm"
              disabled={createMut.isPending}
              onClick={() => createMut.mutate(sgForm)}
            >
              {createMut.isPending ? (
                <Loader2 className="mr-1 h-4 w-4 animate-spin" />
              ) : (
                <Plus className="mr-1 h-4 w-4" />
              )}
              Create
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Ship groups list */}
      {sgQuery.isLoading ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <Skeleton key={i} className="h-24 w-full rounded-lg" />
          ))}
        </div>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            No ship groups yet.
          </CardContent>
        </Card>
      ) : (
        groups.map((sg) => {
          const editVal = trackingEdits[sg.ship_group_id] ?? sg.tracking_number ?? "";
          return (
            <Card key={sg.ship_group_id}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Truck className="h-4 w-4 text-muted-foreground" />
                    <span className="font-mono text-xs">
                      {sg.ship_group_id}
                    </span>
                    <Badge variant="outline">{prettyStatus(sg.ship_method)}</Badge>
                    <Badge variant={statusVariant(sg.ship_status)}>
                      {prettyStatus(sg.ship_status)}
                    </Badge>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-destructive"
                    disabled={deleteMut.isPending}
                    onClick={() => deleteMut.mutate(sg.ship_group_id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-end gap-2">
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs">Tracking Number</Label>
                    <Input
                      className="h-8 text-sm"
                      placeholder="Enter tracking number"
                      value={editVal}
                      onChange={(e) =>
                        setTrackingEdits((prev) => ({
                          ...prev,
                          [sg.ship_group_id]: e.target.value,
                        }))
                      }
                    />
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={updateMut.isPending || editVal === (sg.tracking_number ?? "")}
                    onClick={() =>
                      updateMut.mutate({
                        sgId: sg.ship_group_id,
                        tracking: editVal,
                      })
                    }
                  >
                    {updateMut.isPending &&
                    (updateMut.variables as any)?.sgId === sg.ship_group_id ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    )}
                  </Button>
                </div>
                {sg.item_ids?.length > 0 && (
                  <p className="mt-2 text-xs text-muted-foreground">
                    Items: {sg.item_ids.join(", ")}
                  </p>
                )}
              </CardContent>
            </Card>
          );
        })
      )}
    </div>
  );
}

// ─── History tab ──────────────────────────────────────────────────────────────

function HistoryTab({ orderId }: { orderId: string }) {
  const historyQuery = useQuery({
    queryKey: ["orderHistory", orderId],
    queryFn: () => getOrderHistory(orderId),
  });

  const entries = historyQuery.data ?? [];

  if (historyQuery.isLoading) {
    return (
      <div className="space-y-3">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-16 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-center text-sm text-muted-foreground">
          No history yet.
        </CardContent>
      </Card>
    );
  }

  return (
    <ol className="relative ml-3 border-l border-border">
      {entries.map((entry, idx) => (
        <li key={entry.event_id} className="mb-6 ml-6">
          <span
            className={`absolute -left-3 flex h-6 w-6 items-center justify-center rounded-full ring-4 ring-background ${
              idx === 0
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground"
            }`}
          >
            <History className="h-3 w-3" />
          </span>
          <div className="rounded-lg border bg-card p-3 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {entry.from_status && (
                  <>
                    <Badge variant="outline" className="text-xs">
                      {prettyStatus(entry.from_status)}
                    </Badge>
                    <span className="text-muted-foreground">→</span>
                  </>
                )}
                <Badge
                  variant={statusVariant(entry.to_status)}
                  className="text-xs"
                >
                  {prettyStatus(entry.to_status)}
                </Badge>
              </div>
              <span className="text-xs text-muted-foreground font-mono">
                {typeof entry.ts === "number"
                  ? new Date(entry.ts * 1000).toLocaleString()
                  : entry.ts}
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Actor:{" "}
              <span className="font-mono text-foreground">{entry.actor}</span>
              {entry.reason && (
                <>
                  {" "}
                  — {entry.reason}
                </>
              )}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

// ─── Page skeleton ────────────────────────────────────────────────────────────

function PageSkeleton() {
  return (
    <div className="mx-auto max-w-4xl space-y-4 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-40 w-full rounded-xl" />
      <Skeleton className="h-60 w-full rounded-xl" />
    </div>
  );
}

// ─── Main page component ──────────────────────────────────────────────────────

export default function OrderLifecyclePage() {
  const { orderId = "" } = useParams<{ orderId: string }>();
  const navigate = useNavigate();

  const orderQuery = useQuery({
    queryKey: ["orderLifecycle", orderId],
    queryFn: () =>
      getOrderLifecycle(orderId, ["history", "adjustments", "ship_groups"]),
    enabled: LIFECYCLE_ENABLED && !!orderId,
    retry: false,
  });

  // ─── Feature disabled placeholder ──────────────────────────────────────────
  if (!LIFECYCLE_ENABLED) {
    return (
      <div className="mx-auto max-w-3xl p-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PackageCheck className="h-5 w-5" /> Order Lifecycle (disabled)
            </CardTitle>
            <CardDescription>
              Set{" "}
              <code className="font-mono text-xs">
                VITE_ORDER_LIFECYCLE_ENABLED=true
              </code>{" "}
              in <code className="font-mono text-xs">frontend/.env.local</code>{" "}
              and restart Vite to enable this feature.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  // ─── Loading ────────────────────────────────────────────────────────────────
  if (orderQuery.isLoading) {
    return <PageSkeleton />;
  }

  // ─── Error / not found ──────────────────────────────────────────────────────
  if (orderQuery.isError) {
    return (
      <div className="mx-auto max-w-3xl p-6">
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" /> Order not found
            </CardTitle>
            <CardDescription>
              {(orderQuery.error as Error)?.message ?? "Failed to load order."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" size="sm" onClick={() => navigate(-1)}>
              <ArrowLeft className="mr-1 h-4 w-4" /> Go back
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const order = orderQuery.data!;

  return (
    <div className="mx-auto max-w-4xl space-y-4 p-4 sm:p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate(-1)}
          className="-ml-2"
        >
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back
        </Button>
        <Separator orientation="vertical" className="h-5" />
        <h1 className="text-lg font-semibold">Order Lifecycle</h1>
        <Badge variant={statusVariant(order.lifecycle_status)} className="ml-1">
          {prettyStatus(order.lifecycle_status)}
        </Badge>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview">
        <TabsList className="w-full sm:w-auto">
          <TabsTrigger value="overview" className="flex items-center gap-1">
            <PackageCheck className="h-3.5 w-3.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="adjustments" className="flex items-center gap-1">
            <CircleDollarSign className="h-3.5 w-3.5" /> Adjustments
          </TabsTrigger>
          <TabsTrigger value="shipgroups" className="flex items-center gap-1">
            <Truck className="h-3.5 w-3.5" /> Ship Groups
          </TabsTrigger>
          <TabsTrigger value="history" className="flex items-center gap-1">
            <History className="h-3.5 w-3.5" /> History
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab order={order} />
        </TabsContent>

        <TabsContent value="adjustments" className="mt-4">
          <AdjustmentsTab orderId={orderId} />
        </TabsContent>

        <TabsContent value="shipgroups" className="mt-4">
          <ShipGroupsTab orderId={orderId} />
        </TabsContent>

        <TabsContent value="history" className="mt-4">
          <HistoryTab orderId={orderId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
