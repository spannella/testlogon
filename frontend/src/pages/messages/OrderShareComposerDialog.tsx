import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { listOrders, getOrderLifecycle, prettyStatus } from "@/api/endpoints/orderLifecycle";
import { OrderShareCard } from "./OrderShareCard";
import {
  buildOrderCardPayload,
  formatPriceCents,
  type OrderCardPayload,
  type OrderShareMode,
} from "@/lib/ecomCards";

interface OrderShareComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: OrderCardPayload) => void;
}

const MODE_LABEL: Record<OrderShareMode, string> = {
  receipt: "Receipt (no personal info)",
  gift: "Gift",
  recommendation: "Recommendation",
};

/**
 * FE-151: "Share purchase" composer. Lists the caller's own orders (listOrders
 * -> GET /ui/orders, owner-scoped) + a mode selector (receipt / gift /
 * recommendation). The line-item summary is fetched via getOrderLifecycle
 * (include=line_items). buildOrderCardPayload is the PII choke point -- receipt
 * mode carries neither buyer name/address nor the amount paid.
 */
export function OrderShareComposerDialog({
  open,
  onClose,
  onSubmit,
}: OrderShareComposerDialogProps) {
  const [orderId, setOrderId] = useState<string>("");
  const [mode, setMode] = useState<OrderShareMode>("receipt");

  const ordersQ = useQuery({
    queryKey: ["orders", "orderShareComposer"],
    queryFn: () => listOrders({ limit: 50 }),
    enabled: open,
    retry: false,
  });

  const orders = useMemo(() => ordersQ.data?.orders ?? [], [ordersQ.data]);
  const selectedRow = orders.find((o) => o.order_id === orderId);

  // Fetch line items for the selected order to build the item summary.
  const detailQ = useQuery({
    queryKey: ["orders", "lifecycle", orderId],
    // The lifecycle read joins line_items by default (no include needed).
    queryFn: () => getOrderLifecycle(orderId),
    enabled: open && !!orderId,
    retry: false,
  });

  const preview: OrderCardPayload | null = useMemo(() => {
    if (!selectedRow) return null;
    return buildOrderCardPayload(
      {
        order_id: selectedRow.order_id,
        status: selectedRow.status,
        lifecycle_status: selectedRow.lifecycle_status,
        currency: selectedRow.currency,
        amount_cents: selectedRow.amount_cents,
        line_item_count: selectedRow.line_item_count,
        line_items: detailQ.data?.line_items ?? undefined,
      },
      mode,
    );
  }, [selectedRow, detailQ.data, mode]);

  function reset() {
    setOrderId("");
    setMode("receipt");
  }
  function handleClose() {
    reset();
    onClose();
  }
  function handleSubmit() {
    if (!preview) return;
    onSubmit(preview);
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Share purchase</DialogTitle>
          <DialogDescription>
            Share one of your orders. Receipt mode never includes your name or address.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="order-share-select">Order</Label>
            <Select value={orderId} onValueChange={(v) => setOrderId(v)}>
              <SelectTrigger id="order-share-select" data-testid="order-composer-order">
                <SelectValue placeholder="Select an order" />
              </SelectTrigger>
              <SelectContent>
                {ordersQ.isLoading ? (
                  <div className="px-2 py-1.5 text-sm text-muted-foreground">Loading…</div>
                ) : orders.length === 0 ? (
                  <div className="px-2 py-1.5 text-sm text-muted-foreground">No orders yet</div>
                ) : (
                  orders.map((o) => (
                    <SelectItem key={o.order_id} value={o.order_id}>
                      {prettyStatus(o.lifecycle_status ?? o.status)} —{" "}
                      {formatPriceCents(o.amount_cents, o.currency)} ({o.line_item_count} item
                      {o.line_item_count === 1 ? "" : "s"})
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="order-share-mode-select">Share as</Label>
            <Select value={mode} onValueChange={(v) => setMode(v as OrderShareMode)}>
              <SelectTrigger id="order-share-mode-select" data-testid="order-composer-mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(MODE_LABEL) as OrderShareMode[]).map((m) => (
                  <SelectItem key={m} value={m}>
                    {MODE_LABEL[m]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {preview && (
            <div className="flex justify-center pt-1">
              <OrderShareCard payload={preview} />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!preview} data-testid="order-composer-send">
            Share
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default OrderShareComposerDialog;
