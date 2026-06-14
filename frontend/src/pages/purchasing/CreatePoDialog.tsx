import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
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
  createPurchaseOrder,
  listSuppliers,
  formatCents,
  type PurchaseOrder,
  type PurchaseOrderLinePayload,
} from "@/api/endpoints/purchasing";

interface LineDraft {
  sku: string;
  quantity_ordered: string;
  unit_cost_cents: string; // dollars typed by user
}

const emptyLine = (): LineDraft => ({ sku: "", quantity_ordered: "1", unit_cost_cents: "" });

export function CreatePoDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: (po: PurchaseOrder) => void;
}) {
  const qc = useQueryClient();
  const [supplierId, setSupplierId] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [expected, setExpected] = useState("");
  const [lines, setLines] = useState<LineDraft[]>([emptyLine()]);

  const suppliersQuery = useQuery({
    queryKey: ["purchasing", "suppliers", "active"],
    queryFn: () => listSuppliers({ status: "active", limit: 200 }),
    enabled: open,
  });

  const subtotal = useMemo(
    () =>
      lines.reduce((sum, l) => {
        const qty = Number(l.quantity_ordered) || 0;
        const cost = Math.round((Number(l.unit_cost_cents) || 0) * 100);
        return sum + qty * cost;
      }, 0),
    [lines],
  );

  const reset = () => {
    setSupplierId("");
    setCurrency("USD");
    setExpected("");
    setLines([emptyLine()]);
  };

  const createMut = useMutation({
    mutationFn: () => {
      const payloadLines: PurchaseOrderLinePayload[] = lines
        .filter((l) => l.sku.trim())
        .map((l) => ({
          sku: l.sku.trim(),
          quantity_ordered: Math.max(1, Number(l.quantity_ordered) || 1),
          unit_cost_cents: l.unit_cost_cents.trim()
            ? Math.round(Number(l.unit_cost_cents) * 100)
            : undefined,
        }));
      return createPurchaseOrder({
        supplier_id: supplierId,
        lines: payloadLines,
        currency,
        expected_delivery_date: expected.trim() || undefined,
      });
    },
    onSuccess: (po) => {
      toast.success("Purchase order created");
      void qc.invalidateQueries({ queryKey: ["purchasing", "pos"] });
      reset();
      onCreated(po);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to create purchase order"),
  });

  const validLines = lines.filter((l) => l.sku.trim());
  const canSubmit = !!supplierId && validLines.length > 0 && !createMut.isPending;

  const updateLine = (idx: number, patch: Partial<LineDraft>) =>
    setLines((prev) => prev.map((l, i) => (i === idx ? { ...l, ...patch } : l)));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>New Purchase Order</DialogTitle>
          <DialogDescription>
            Select a supplier and add line items. The PO is created in draft status.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="space-y-1 sm:col-span-1">
              <Label>Supplier</Label>
              <Select value={supplierId} onValueChange={setSupplierId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select supplier" />
                </SelectTrigger>
                <SelectContent>
                  {(suppliersQuery.data?.suppliers ?? []).map((s) => (
                    <SelectItem key={s.supplier_id} value={s.supplier_id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Currency</Label>
              <Input value={currency} onChange={(e) => setCurrency(e.target.value.toUpperCase())} maxLength={3} />
            </div>
            <div className="space-y-1">
              <Label>Expected delivery</Label>
              <Input
                type="date"
                value={expected}
                onChange={(e) => setExpected(e.target.value)}
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Line items</Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setLines((p) => [...p, emptyLine()])}
              >
                <Plus className="mr-1 h-3.5 w-3.5" /> Add line
              </Button>
            </div>
            <div className="space-y-2">
              {lines.map((l, idx) => (
                <div key={idx} className="grid grid-cols-12 gap-2">
                  <Input
                    className="col-span-6"
                    placeholder="SKU"
                    value={l.sku}
                    onChange={(e) => updateLine(idx, { sku: e.target.value })}
                  />
                  <Input
                    className="col-span-2"
                    type="number"
                    min={1}
                    placeholder="Qty"
                    value={l.quantity_ordered}
                    onChange={(e) => updateLine(idx, { quantity_ordered: e.target.value })}
                  />
                  <Input
                    className="col-span-3"
                    type="number"
                    min={0}
                    step="0.01"
                    placeholder="Unit cost"
                    value={l.unit_cost_cents}
                    onChange={(e) => updateLine(idx, { unit_cost_cents: e.target.value })}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="col-span-1"
                    disabled={lines.length === 1}
                    onClick={() => setLines((p) => p.filter((_, i) => i !== idx))}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
            <p className="text-right text-sm text-muted-foreground">
              Estimated subtotal:{" "}
              <span className="font-medium text-foreground">{formatCents(subtotal, currency)}</span>
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!canSubmit} onClick={() => createMut.mutate()}>
            {createMut.isPending ? "Creating…" : "Create PO"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
