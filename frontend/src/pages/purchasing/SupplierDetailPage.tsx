import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Pencil, Plus } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
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

import {
  getSupplier,
  setSupplierStatus,
  listSupplierProducts,
  upsertSupplierProduct,
  formatCents,
} from "@/api/endpoints/purchasing";
import { ApiError } from "@/api/client";
import { SupplierStatusBadge, fmtTs } from "./poStatus";
import { SupplierDialog } from "./SupplierDialog";

// ─── Product upsert dialog ────────────────────────────────────────────────────

function ProductDialog({
  supplierId,
  open,
  onOpenChange,
  onDone,
}: {
  supplierId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onDone: () => void;
}) {
  const [sku, setSku] = useState("");
  const [cost, setCost] = useState("");
  const [supplierSku, setSupplierSku] = useState("");
  const [leadTime, setLeadTime] = useState("0");
  const [minQty, setMinQty] = useState("1");
  const [preferred, setPreferred] = useState(false);

  const upsertMut = useMutation({
    mutationFn: () =>
      upsertSupplierProduct(supplierId, sku.trim(), {
        unit_cost_cents: Math.round((Number(cost) || 0) * 100),
        lead_time_days: Math.max(0, Number(leadTime) || 0),
        min_order_qty: Math.max(1, Number(minQty) || 1),
        supplier_sku: supplierSku.trim() || null,
        preferred,
      }),
    onSuccess: () => {
      toast.success("Product saved");
      setSku("");
      setCost("");
      setSupplierSku("");
      setLeadTime("0");
      setMinQty("1");
      setPreferred(false);
      onDone();
      onOpenChange(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to save product"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add / Update Catalog Product</DialogTitle>
          <DialogDescription>
            Map a SKU to this supplier with cost and lead-time data.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label>SKU</Label>
            <Input value={sku} onChange={(e) => setSku(e.target.value)} placeholder="WIDGET-001" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Unit cost</Label>
              <Input type="number" min={0} step="0.01" value={cost} onChange={(e) => setCost(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Supplier SKU</Label>
              <Input value={supplierSku} onChange={(e) => setSupplierSku(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Lead time (days)</Label>
              <Input type="number" min={0} value={leadTime} onChange={(e) => setLeadTime(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Min order qty</Label>
              <Input type="number" min={1} value={minQty} onChange={(e) => setMinQty(e.target.value)} />
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={preferred} onCheckedChange={(v) => setPreferred(v === true)} />
            Preferred supplier for this SKU
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!sku.trim() || upsertMut.isPending} onClick={() => upsertMut.mutate()}>
            {upsertMut.isPending ? "Saving…" : "Save product"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SupplierDetailPage() {
  const { supplierId = "" } = useParams<{ supplierId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [editOpen, setEditOpen] = useState(false);
  const [productOpen, setProductOpen] = useState(false);

  const supQuery = useQuery({
    queryKey: ["purchasing", "supplier", supplierId],
    queryFn: () => getSupplier(supplierId),
    enabled: !!supplierId,
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  });

  const prodQuery = useQuery({
    queryKey: ["purchasing", "supplier", supplierId, "products"],
    queryFn: () => listSupplierProducts(supplierId),
    enabled: !!supplierId && !!supQuery.data,
    retry: false,
  });

  const statusMut = useMutation({
    mutationFn: (status: string) => setSupplierStatus(supplierId, status),
    onSuccess: () => {
      toast.success("Supplier status updated");
      void supQuery.refetch();
      void qc.invalidateQueries({ queryKey: ["purchasing", "suppliers"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to update status"),
  });

  if (supQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (supQuery.error instanceof ApiError && supQuery.error.status === 404) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          Supplier not found (or the Purchasing module is disabled).
          <div className="mt-4">
            <Button variant="outline" onClick={() => navigate("/purchasing")}>
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to Purchasing
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  const sup = supQuery.data;
  if (!sup) return null;

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" className="-ml-2" onClick={() => navigate("/purchasing")}>
        <ArrowLeft className="mr-2 h-4 w-4" /> Back
      </Button>

      <PageHeader
        title={sup.name}
        description={`Supplier ${sup.supplier_id}`}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
            </Button>
            <Button
              variant={sup.status === "active" ? "ghost" : "default"}
              disabled={statusMut.isPending}
              onClick={() => statusMut.mutate(sup.status === "active" ? "inactive" : "active")}
            >
              {sup.status === "active" ? "Deactivate" : "Activate"}
            </Button>
          </div>
        }
      />

      <div className="flex items-center gap-3">
        <SupplierStatusBadge status={sup.status} />
        <Badge variant="outline">{sup.default_currency}</Badge>
        <span className="text-sm text-muted-foreground">Net {sup.payment_terms_days} days</span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Contact</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
          <Detail label="Email" value={sup.email || "—"} />
          <Detail label="Phone" value={sup.phone || "—"} />
          <Detail label="Created by" value={sup.created_by} />
          <Detail label="Created" value={fmtTs(sup.created_at)} />
          <Detail label="Updated" value={fmtTs(sup.updated_at)} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Catalog Products</CardTitle>
          <Button size="sm" onClick={() => setProductOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> Add product
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          {prodQuery.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-9 w-full" />
              ))}
            </div>
          ) : (prodQuery.data?.products.length ?? 0) === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              No catalog products mapped to this supplier.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>SKU</TableHead>
                  <TableHead>Supplier SKU</TableHead>
                  <TableHead className="text-right">Unit cost</TableHead>
                  <TableHead className="text-right">Lead time</TableHead>
                  <TableHead className="text-right">Min qty</TableHead>
                  <TableHead>Preferred</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(prodQuery.data?.products ?? []).map((p) => (
                  <TableRow key={p.sku}>
                    <TableCell className="font-mono text-xs">{p.sku}</TableCell>
                    <TableCell className="font-mono text-xs">{p.supplier_sku || "—"}</TableCell>
                    <TableCell className="text-right">{formatCents(p.unit_cost_cents, p.currency)}</TableCell>
                    <TableCell className="text-right">{p.lead_time_days}d</TableCell>
                    <TableCell className="text-right">{p.min_order_qty}</TableCell>
                    <TableCell>
                      {p.preferred ? <Badge variant="success">Preferred</Badge> : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <SupplierDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        existing={sup}
        onSaved={() => {
          setEditOpen(false);
          void supQuery.refetch();
        }}
      />
      <ProductDialog
        supplierId={sup.supplier_id}
        open={productOpen}
        onOpenChange={setProductOpen}
        onDone={() => void prodQuery.refetch()}
      />
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-mono text-sm break-all">{value}</div>
    </div>
  );
}
