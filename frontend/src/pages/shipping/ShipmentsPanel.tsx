import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { PackageSearch, Truck } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  advanceShipment,
  cancelShipment,
  getShipment,
  listOrderShipments,
  updateTracking,
  type ShipmentOut,
  type ShipmentStatus,
} from "@/api/endpoints/shipping";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { ShippingNotEnabled } from "./ShippingNotEnabled";
import {
  STATUS_LABELS,
  STATUS_TRANSITIONS,
  fmtCents,
  fmtTs,
  formatAddress,
  isAddressObj,
  statusVariant,
} from "./shippingHelpers";

function StatusBadge({ status }: { status: ShipmentStatus }) {
  return <Badge variant={statusVariant(status)}>{STATUS_LABELS[status] ?? status}</Badge>;
}

function ShipmentDetail({
  shipmentId,
  onChanged,
}: {
  shipmentId: string;
  onChanged?: () => void;
}) {
  const [trackingNumber, setTrackingNumber] = useState("");
  const [advanceOpen, setAdvanceOpen] = useState(false);
  const [advanceTarget, setAdvanceTarget] = useState<ShipmentStatus | "">("");
  const [advanceReason, setAdvanceReason] = useState("");
  const [cancelOpen, setCancelOpen] = useState(false);
  const [cancelReason, setCancelReason] = useState("");
  const [refundShipping, setRefundShipping] = useState(false);

  const detailQuery = useQuery({
    queryKey: ["shipping", "shipment", shipmentId],
    queryFn: () => getShipment(shipmentId),
    retry: false,
  });

  const refresh = () => {
    void detailQuery.refetch();
    onChanged?.();
  };

  const trackingMut = useMutation({
    mutationFn: () =>
      updateTracking(shipmentId, { tracking_number: trackingNumber.trim() }),
    onSuccess: () => {
      toast.success("Tracking updated");
      setTrackingNumber("");
      refresh();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to update tracking"),
  });

  const advanceMut = useMutation({
    mutationFn: () =>
      advanceShipment(shipmentId, {
        target_status: advanceTarget as ShipmentStatus,
        reason: advanceReason.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Status advanced");
      setAdvanceOpen(false);
      setAdvanceTarget("");
      setAdvanceReason("");
      refresh();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to advance status"),
  });

  const cancelMut = useMutation({
    mutationFn: () =>
      cancelShipment(shipmentId, {
        reason: cancelReason.trim() || "cancelled",
        refund_shipping: refundShipping,
      }),
    onSuccess: () => {
      toast.success("Shipment cancelled");
      setCancelOpen(false);
      setCancelReason("");
      refresh();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to cancel shipment"),
  });

  if (detailQuery.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading shipment…</p>;
  }
  if (detailQuery.isError) {
    const status = (detailQuery.error as ApiError)?.status;
    if (status === 503) return <ShippingNotEnabled />;
    return (
      <p className="text-sm text-muted-foreground">
        {status === 404 ? "Shipment not found." : "Unable to load shipment."}
      </p>
    );
  }

  const s = detailQuery.data as ShipmentOut;
  const transitions = STATUS_TRANSITIONS[s.status] ?? [];
  const terminal = transitions.length === 0;
  const address = isAddressObj(s.ship_to_address) ? s.ship_to_address : undefined;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold">Shipment {s.shipment_id.slice(0, 12)}…</h3>
            <StatusBadge status={s.status} />
          </div>
          <p className="text-sm text-muted-foreground">
            Order {s.order_id} · ship group {s.ship_group_seq} · v{s.version}
          </p>
        </div>
        <div className="flex gap-2">
          {!terminal && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setAdvanceTarget(transitions[0] ?? "");
                setAdvanceOpen(true);
              }}
            >
              Advance status
            </Button>
          )}
          {s.status !== "cancelled" && (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setCancelOpen(true)}
            >
              Cancel
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1 rounded-lg border p-4">
          <p className="text-xs font-medium uppercase text-muted-foreground">
            Carrier &amp; method
          </p>
          <p className="text-sm uppercase">{s.carrier_code}</p>
          <p className="text-sm">{s.method_code}</p>
        </div>
        <div className="space-y-1 rounded-lg border p-4">
          <p className="text-xs font-medium uppercase text-muted-foreground">
            Tracking
          </p>
          {s.tracking_number ? (
            <p className="text-sm">
              {s.tracking_url ? (
                <a
                  className="text-primary underline"
                  href={s.tracking_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  {s.tracking_number}
                </a>
              ) : (
                s.tracking_number
              )}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">No tracking number</p>
          )}
          {s.estimated_delivery && (
            <p className="text-xs text-muted-foreground">
              Est. delivery {s.estimated_delivery}
            </p>
          )}
        </div>
        <div className="space-y-1 rounded-lg border p-4">
          <p className="text-xs font-medium uppercase text-muted-foreground">
            Ship to
          </p>
          <p className="whitespace-pre-line text-sm">{formatAddress(address)}</p>
        </div>
        <div className="space-y-1 rounded-lg border p-4">
          <p className="text-xs font-medium uppercase text-muted-foreground">
            Timeline
          </p>
          <p className="text-sm">Created {fmtTs(s.created_at)}</p>
          <p className="text-sm">Updated {fmtTs(s.updated_at)}</p>
          {s.shipped_at && <p className="text-sm">Shipped {fmtTs(s.shipped_at)}</p>}
          {s.delivered_at && (
            <p className="text-sm">Delivered {fmtTs(s.delivered_at)}</p>
          )}
        </div>
      </div>

      {s.items.length > 0 && (
        <div>
          <p className="mb-2 text-sm font-medium">Items</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Item</TableHead>
                <TableHead>SKU</TableHead>
                <TableHead className="text-right">Qty</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {s.items.map((it, i) => (
                <TableRow key={`${it.item_id}-${i}`}>
                  <TableCell>{it.item_id}</TableCell>
                  <TableCell>{it.sku ?? "—"}</TableCell>
                  <TableCell className="text-right">{it.quantity}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {s.packages.length > 0 && (
        <div>
          <p className="mb-2 text-sm font-medium">Packages</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Weight (oz)</TableHead>
                <TableHead>Billed (oz)</TableHead>
                <TableHead>Dimensions (in)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {s.packages.map((p) => (
                <TableRow key={p.package_seq}>
                  <TableCell>{p.package_seq}</TableCell>
                  <TableCell>{p.weight_oz}</TableCell>
                  <TableCell>{p.billed_weight_oz ?? "—"}</TableCell>
                  <TableCell>
                    {p.length_in != null && p.width_in != null && p.height_in != null
                      ? `${p.length_in} × ${p.width_in} × ${p.height_in}`
                      : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {s.status !== "cancelled" && s.status !== "delivered" && (
        <div className="rounded-lg border p-4">
          <Label className="text-sm">Set / update tracking number</Label>
          <div className="mt-2 flex gap-2">
            <Input
              value={trackingNumber}
              placeholder="1Z999AA10123456784"
              onChange={(e) => setTrackingNumber(e.target.value)}
            />
            <Button
              disabled={!trackingNumber.trim() || trackingMut.isPending}
              onClick={() => trackingMut.mutate()}
            >
              {trackingMut.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      )}

      <Dialog open={advanceOpen} onOpenChange={setAdvanceOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Advance shipment status</DialogTitle>
            <DialogDescription>
              Move the shipment forward to the next allowed status.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div className="grid gap-1.5">
              <Label>Target status</Label>
              <Select
                value={advanceTarget}
                onValueChange={(v) => setAdvanceTarget(v as ShipmentStatus)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select status" />
                </SelectTrigger>
                <SelectContent>
                  {transitions.map((t) => (
                    <SelectItem key={t} value={t}>
                      {STATUS_LABELS[t]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>Reason (optional)</Label>
              <Input
                value={advanceReason}
                onChange={(e) => setAdvanceReason(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAdvanceOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!advanceTarget || advanceMut.isPending}
              onClick={() => advanceMut.mutate()}
            >
              {advanceMut.isPending ? "Advancing…" : "Advance"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={cancelOpen} onOpenChange={setCancelOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel shipment</DialogTitle>
            <DialogDescription>
              This will cancel the shipment and optionally refund shipping.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div className="grid gap-1.5">
              <Label>Reason</Label>
              <Input
                value={cancelReason}
                placeholder="cancelled"
                onChange={(e) => setCancelReason(e.target.value)}
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={refundShipping}
                onChange={(e) => setRefundShipping(e.target.checked)}
              />
              Refund shipping charge
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCancelOpen(false)}>
              Back
            </Button>
            <Button
              variant="destructive"
              disabled={cancelMut.isPending}
              onClick={() => cancelMut.mutate()}
            >
              {cancelMut.isPending ? "Cancelling…" : "Cancel shipment"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function ShipmentsPanel() {
  const [orderId, setOrderId] = useState("");
  const [shipmentId, setShipmentId] = useState("");
  const [activeOrderId, setActiveOrderId] = useState<string | null>(null);
  const [selectedShipmentId, setSelectedShipmentId] = useState<string | null>(null);

  const orderQuery = useQuery({
    queryKey: ["shipping", "order-shipments", activeOrderId],
    queryFn: () => listOrderShipments(activeOrderId!),
    enabled: !!activeOrderId,
    retry: false,
  });

  const notEnabled =
    orderQuery.isError && (orderQuery.error as ApiError)?.status === 503;
  if (notEnabled) return <ShippingNotEnabled />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Find shipments</CardTitle>
          <CardDescription>
            Look up shipments by order ID, or open a specific shipment by ID.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Order ID</Label>
              <div className="flex gap-2">
                <Input
                  value={orderId}
                  placeholder="order_…"
                  onChange={(e) => setOrderId(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && orderId.trim()) {
                      setSelectedShipmentId(null);
                      setActiveOrderId(orderId.trim());
                    }
                  }}
                />
                <Button
                  disabled={!orderId.trim()}
                  onClick={() => {
                    setSelectedShipmentId(null);
                    setActiveOrderId(orderId.trim());
                  }}
                >
                  <PackageSearch className="mr-1 h-4 w-4" /> List
                </Button>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Shipment ID</Label>
              <div className="flex gap-2">
                <Input
                  value={shipmentId}
                  placeholder="shipment hash"
                  onChange={(e) => setShipmentId(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && shipmentId.trim()) {
                      setSelectedShipmentId(shipmentId.trim());
                    }
                  }}
                />
                <Button
                  variant="outline"
                  disabled={!shipmentId.trim()}
                  onClick={() => setSelectedShipmentId(shipmentId.trim())}
                >
                  <Truck className="mr-1 h-4 w-4" /> Open
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {activeOrderId && (
        <Card>
          <CardHeader>
            <CardTitle>Shipments for {activeOrderId}</CardTitle>
          </CardHeader>
          <CardContent>
            {orderQuery.isLoading ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : orderQuery.isError ? (
              <p className="text-sm text-muted-foreground">
                Unable to load shipments for this order.
              </p>
            ) : (orderQuery.data?.shipments.length ?? 0) === 0 ? (
              <p className="text-sm text-muted-foreground">
                No shipments found for this order.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Shipment</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Carrier</TableHead>
                    <TableHead>Tracking</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {orderQuery.data!.shipments.map((s) => {
                    const status = (s.status ?? "pending_fulfillment") as ShipmentStatus;
                    return (
                      <TableRow key={s.shipment_id}>
                        <TableCell className="font-mono text-xs">
                          {s.shipment_id.slice(0, 12)}…
                        </TableCell>
                        <TableCell>
                          <StatusBadge status={status} />
                        </TableCell>
                        <TableCell className="uppercase">{s.carrier_code}</TableCell>
                        <TableCell>{s.tracking_number ?? "—"}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedShipmentId(s.shipment_id)}
                          >
                            View
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {selectedShipmentId && (
        <Card>
          <CardContent className="pt-6">
            <ShipmentDetail
              shipmentId={selectedShipmentId}
              onChanged={() => {
                if (activeOrderId) void orderQuery.refetch();
              }}
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// Re-export for currency formatting usages in tests / siblings.
export { fmtCents };
