import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, MapPin, Package, Truck, User } from "lucide-react";

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
import { ApiError } from "@/api/client";
import {
  getSellerSale,
  transitionSellerSale,
  formatShipTo,
  isOpenFulfilment,
  prettySellerStatus,
  SELLER_FULFILMENT_STAGES,
  type SellerSale,
} from "@/api/endpoints/sellerSales";
import { formatCents } from "@/api/endpoints/orderLifecycle";

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  const s = status.toLowerCase();
  if (s === "shipped" || s === "completed") return "default";
  if (s === "cancelled" || s === "returned") return "destructive";
  if (isOpenFulfilment(status)) return "secondary";
  return "outline";
}

export default function SellerSaleDetailPage() {
  const { shipGroupId = "" } = useParams<{ shipGroupId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [shipOpen, setShipOpen] = useState(false);
  const [carrier, setCarrier] = useState("");
  const [trackingNumber, setTrackingNumber] = useState("");

  const detailQuery = useQuery<SellerSale, ApiError>({
    queryKey: ["seller-sales", "detail", shipGroupId],
    queryFn: () => getSellerSale(shipGroupId),
    enabled: !!shipGroupId,
    retry: false,
  });
  const sale = detailQuery.data;

  useEffect(() => {
    if (sale) {
      setCarrier((c) => c || sale.carrier || "");
      setTrackingNumber((t) => t || sale.tracking_number || "");
    }
  }, [sale]);

  const refresh = () => {
    void detailQuery.refetch();
    void qc.invalidateQueries({ queryKey: ["seller-sales"] });
  };

  const transitionMut = useMutation({
    mutationFn: (vars: { target: string; carrier?: string; tracking_number?: string }) =>
      transitionSellerSale(shipGroupId, {
        target_status: vars.target,
        carrier: vars.carrier,
        tracking_number: vars.tracking_number,
      }),
    onSuccess: (res) => {
      toast.success(`Moved to ${prettySellerStatus(res.status)}`);
      setShipOpen(false);
      refresh();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to update the shipment"),
  });

  const allowed = useMemo(() => sale?.allowed_transitions ?? [], [sale?.allowed_transitions]);
  const canShip = allowed.includes("shipped");
  const nonShipTargets = allowed.filter((t) => t !== "shipped");

  const currentStageIdx = useMemo(() => {
    if (!sale) return -1;
    const i = SELLER_FULFILMENT_STAGES.indexOf(sale.status as (typeof SELLER_FULFILMENT_STAGES)[number]);
    return i;
  }, [sale]);

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
        <Button variant="ghost" size="sm" onClick={() => navigate("/seller/sales")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to sales
        </Button>
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            <Package className="mx-auto mb-3 h-8 w-8 opacity-40" />
            {disabled
              ? "Seller fulfilment is not enabled on this environment."
              : notFound
                ? "This sale was not found, or it isn't one of yours."
                : detailQuery.error?.message || "Unable to load this sale."}
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!sale) return null;

  const shipTo = formatShipTo(sale.ship_to);

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => navigate("/seller/sales")}>
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to sales
      </Button>

      <PageHeader
        title={`Sale · ${sale.buyer_name || sale.buyer_email || "Buyer"}`}
        description={`Order ${sale.order_id} · ${sale.item_count} line item${sale.item_count === 1 ? "" : "s"}`}
        actions={<Badge variant={statusVariant(sale.status)}>{prettySellerStatus(sale.status)}</Badge>}
      />

      {/* Fulfilment progress */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Fulfilment progress</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="flex items-center">
            {SELLER_FULFILMENT_STAGES.map((stage, i) => {
              const reached = currentStageIdx >= 0 && i <= currentStageIdx;
              const isLast = i === SELLER_FULFILMENT_STAGES.length - 1;
              return (
                <li key={stage} className="flex flex-1 items-center last:flex-none">
                  <div className="flex flex-col items-center gap-1">
                    <span
                      className={
                        "flex h-6 w-6 items-center justify-center rounded-full text-xs " +
                        (reached
                          ? "bg-primary text-primary-foreground"
                          : "border bg-background text-muted-foreground")
                      }
                    >
                      {i + 1}
                    </span>
                    <span className={"text-[11px] " + (reached ? "text-foreground" : "text-muted-foreground")}>
                      {prettySellerStatus(stage)}
                    </span>
                  </div>
                  {!isLast && (
                    <div className={"mx-1 h-0.5 flex-1 " + (i < currentStageIdx ? "bg-primary" : "bg-muted")} />
                  )}
                </li>
              );
            })}
          </ol>
        </CardContent>
      </Card>

      {/* Actions */}
      {allowed.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Fulfil this order</CardTitle>
            <CardDescription>Advance the shipment and enter tracking when you ship.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {nonShipTargets.map((t) => (
              <Button
                key={t}
                size="sm"
                variant={t === "cancelled" ? "destructive" : "secondary"}
                disabled={transitionMut.isPending}
                onClick={() => transitionMut.mutate({ target: t })}
              >
                Move to {prettySellerStatus(t)}
              </Button>
            ))}
            {canShip && (
              <Button
                size="sm"
                data-testid="mark-shipped-open"
                disabled={transitionMut.isPending}
                onClick={() => setShipOpen(true)}
              >
                <Truck className="mr-1.5 h-4 w-4" />
                Mark shipped…
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Existing tracking (once shipped) */}
      {(sale.tracking_number || sale.carrier) && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Truck className="h-4 w-4" />
              Tracking
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            <span className="uppercase font-medium">{sale.carrier || "Carrier"}</span>
            {sale.tracking_number ? (
              <span className="ml-2 font-mono text-muted-foreground" data-testid="seller-tracking-number">
                {sale.tracking_number}
              </span>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* Ship-to */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <MapPin className="h-4 w-4" />
            Ship to
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <div className="flex items-center gap-2">
            <User className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-medium">{sale.buyer_name || sale.buyer_email || "Buyer"}</span>
          </div>
          <p className="text-muted-foreground">
            {shipTo || "No shipping address on file for this buyer."}
          </p>
        </CardContent>
      </Card>

      {/* Line items */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Package className="h-4 w-4" />
            Items to ship
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Item</TableHead>
                <TableHead>SKU</TableHead>
                <TableHead className="text-right">Qty</TableHead>
                <TableHead className="text-right">Unit</TableHead>
                <TableHead className="text-right">Line total</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sale.line_items.map((li) => (
                <TableRow key={li.item_id}>
                  <TableCell className="font-medium">{li.name || li.item_id}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{li.sku || "—"}</TableCell>
                  <TableCell className="text-right">{li.quantity}</TableCell>
                  <TableCell className="text-right">
                    {formatCents(li.unit_price_cents, sale.currency)}
                  </TableCell>
                  <TableCell className="text-right">
                    {formatCents(li.line_total_cents, sale.currency)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="mt-3 flex justify-end text-sm font-medium">
            Subtotal: {formatCents(sale.subtotal_cents, sale.currency)}
          </div>
        </CardContent>
      </Card>

      <div>
        <Link to="/seller/sales" className="text-sm text-muted-foreground hover:underline">
          ← Back to sales
        </Link>
      </div>

      {/* Mark-shipped dialog */}
      <Dialog open={shipOpen} onOpenChange={setShipOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark shipped</DialogTitle>
            <DialogDescription>
              Enter the carrier and tracking number so the buyer can follow their order.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="ship-carrier">Carrier</Label>
              <Input
                id="ship-carrier"
                placeholder="e.g. ups, usps, fedex"
                value={carrier}
                onChange={(e) => setCarrier(e.target.value)}
                data-testid="ship-carrier"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ship-tracking">Tracking number</Label>
              <Input
                id="ship-tracking"
                placeholder="e.g. 1Z999AA10123456784"
                value={trackingNumber}
                onChange={(e) => setTrackingNumber(e.target.value)}
                data-testid="ship-tracking"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShipOpen(false)}>
              Cancel
            </Button>
            <Button
              data-testid="ship-confirm"
              disabled={transitionMut.isPending || !trackingNumber.trim() || !carrier.trim()}
              onClick={() =>
                transitionMut.mutate({
                  target: "shipped",
                  carrier: carrier.trim(),
                  tracking_number: trackingNumber.trim(),
                })
              }
            >
              {transitionMut.isPending ? "Shipping…" : "Confirm shipped"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
