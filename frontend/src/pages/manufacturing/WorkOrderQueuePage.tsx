import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Play, CheckCircle2, XCircle, PackageOpen } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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

import {
  cancelWorkOrder,
  completeWorkOrder,
  createWorkOrder,
  getWorkOrder,
  listBoms,
  listWorkCenters,
  listWorkOrders,
  releaseWorkOrder,
  startWorkOrder,
  type WorkOrderOut,
} from "@/api/endpoints/manufacturing";
import { StatusBadge, fmtTs, isFeatureDisabled } from "./lib";

const STATUS_FILTERS = ["all", "draft", "released", "in_progress", "completed", "cancelled"];

export default function WorkOrderQueuePage() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const woQuery = useQuery({
    queryKey: ["mfg", "work-orders", statusFilter],
    queryFn: () => listWorkOrders(statusFilter === "all" ? undefined : statusFilter),
    retry: false,
  });
  const featureOff = isFeatureDisabled(woQuery.error);

  const bomsQuery = useQuery({
    queryKey: ["mfg", "boms"],
    queryFn: () => listBoms(),
    enabled: createOpen,
  });
  const wcQuery = useQuery({
    queryKey: ["mfg", "work-centers"],
    queryFn: () => listWorkCenters("active"),
    enabled: createOpen,
  });

  // create draft
  const [productSku, setProductSku] = useState("");
  const [quantity, setQuantity] = useState(1);
  const [bomId, setBomId] = useState("");
  const [workCenterId, setWorkCenterId] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createWorkOrder({
        product_sku: productSku.trim(),
        quantity,
        bom_id: bomId || undefined,
        work_center_id: workCenterId || undefined,
      }),
    onSuccess: (wo) => {
      toast.success("Work order created");
      setCreateOpen(false);
      setProductSku("");
      setQuantity(1);
      setBomId("");
      setWorkCenterId("");
      setSelectedId(wo.work_order_id);
      void qc.invalidateQueries({ queryKey: ["mfg", "work-orders"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to create work order"),
  });

  function refresh() {
    void qc.invalidateQueries({ queryKey: ["mfg", "work-orders"] });
    if (selectedId) void qc.invalidateQueries({ queryKey: ["mfg", "work-order", selectedId] });
  }

  const releaseMut = useMutation({
    mutationFn: (id: string) => releaseWorkOrder(id),
    onSuccess: () => {
      toast.success("Work order released");
      refresh();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to release"),
  });
  const startMut = useMutation({
    mutationFn: (id: string) => startWorkOrder(id),
    onSuccess: () => {
      toast.success("Work order started");
      refresh();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to start"),
  });
  const completeMut = useMutation({
    mutationFn: (vars: { id: string; producedQty: number }) =>
      completeWorkOrder(vars.id, { produced_qty: vars.producedQty }),
    onSuccess: () => {
      toast.success("Work order completed");
      refresh();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to complete"),
  });
  const cancelMut = useMutation({
    mutationFn: (vars: { id: string; reason: string }) =>
      cancelWorkOrder(vars.id, { reason: vars.reason }),
    onSuccess: () => {
      toast.success("Work order cancelled");
      refresh();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to cancel"),
  });

  const workOrders = woQuery.data?.work_orders ?? [];

  function actionsFor(wo: WorkOrderOut) {
    return (
      <div className="flex flex-wrap justify-end gap-2">
        {wo.status === "draft" && (
          <Button size="sm" variant="secondary" onClick={() => releaseMut.mutate(wo.work_order_id)}>
            <PackageOpen className="mr-1 h-3.5 w-3.5" /> Release
          </Button>
        )}
        {wo.status === "released" && (
          <Button size="sm" onClick={() => startMut.mutate(wo.work_order_id)}>
            <Play className="mr-1 h-3.5 w-3.5" /> Start
          </Button>
        )}
        {wo.status === "in_progress" && (
          <Button
            size="sm"
            onClick={() => completeMut.mutate({ id: wo.work_order_id, producedQty: wo.quantity })}
          >
            <CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Complete
          </Button>
        )}
        {(wo.status === "draft" || wo.status === "released" || wo.status === "in_progress") && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => cancelMut.mutate({ id: wo.work_order_id, reason: "cancelled by operator" })}
          >
            <XCircle className="mr-1 h-3.5 w-3.5" /> Cancel
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Work Order Queue"
        description="Release, start, complete, and cancel production orders."
        actions={
          <Button onClick={() => setCreateOpen(true)} disabled={featureOff}>
            <Plus className="mr-2 h-4 w-4" /> New work order
          </Button>
        }
      />

      {featureOff ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Manufacturing is not enabled on this environment.
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="flex items-center gap-2">
            <Label className="text-sm">Status</Label>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUS_FILTERS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s === "all" ? "All" : s.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Work orders</CardTitle>
              <CardDescription>{workOrders.length} shown</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Product</TableHead>
                    <TableHead>Qty</TableHead>
                    <TableHead>Produced</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {woQuery.isLoading && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                        Loading…
                      </TableCell>
                    </TableRow>
                  )}
                  {!woQuery.isLoading && workOrders.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                        No work orders.
                      </TableCell>
                    </TableRow>
                  )}
                  {workOrders.map((wo) => (
                    <TableRow
                      key={wo.work_order_id}
                      className="cursor-pointer"
                      onClick={() => setSelectedId(wo.work_order_id)}
                    >
                      <TableCell className="font-medium">{wo.product_sku}</TableCell>
                      <TableCell>{wo.quantity}</TableCell>
                      <TableCell>{wo.produced_qty}</TableCell>
                      <TableCell>
                        <StatusBadge status={wo.status} />
                      </TableCell>
                      <TableCell>{fmtTs(wo.created_at)}</TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        {actionsFor(wo)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </>
      )}

      {selectedId && <WorkOrderDetail workOrderId={selectedId} onClose={() => setSelectedId(null)} />}

      {/* ── Create dialog ── */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New work order</DialogTitle>
            <DialogDescription>Schedule production of a finished product.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="space-y-1">
              <Label htmlFor="wo-product">Product SKU</Label>
              <Input id="wo-product" value={productSku} onChange={(e) => setProductSku(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="wo-qty">Quantity</Label>
              <Input
                id="wo-qty"
                type="number"
                min={1}
                value={quantity}
                onChange={(e) => setQuantity(Math.max(1, Number(e.target.value)))}
              />
            </div>
            <div className="space-y-1">
              <Label>BOM (optional)</Label>
              <Select value={bomId} onValueChange={setBomId}>
                <SelectTrigger>
                  <SelectValue placeholder="None" />
                </SelectTrigger>
                <SelectContent>
                  {(bomsQuery.data?.boms ?? []).map((b) => (
                    <SelectItem key={b.bom_id} value={b.bom_id}>
                      {b.name} ({b.product_sku})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Work center (optional)</Label>
              <Select value={workCenterId} onValueChange={setWorkCenterId}>
                <SelectTrigger>
                  <SelectValue placeholder="None" />
                </SelectTrigger>
                <SelectContent>
                  {(wcQuery.data?.work_centers ?? []).map((w) => (
                    <SelectItem key={w.work_center_id} value={w.work_center_id}>
                      {w.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending || !productSku.trim()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function WorkOrderDetail({
  workOrderId,
  onClose,
}: {
  workOrderId: string;
  onClose: () => void;
}) {
  const woQuery = useQuery({
    queryKey: ["mfg", "work-order", workOrderId],
    queryFn: () => getWorkOrder(workOrderId),
  });
  const wo = woQuery.data;

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Work order {wo && <StatusBadge status={wo.status} />}
          </DialogTitle>
          <DialogDescription>{wo ? wo.product_sku : workOrderId}</DialogDescription>
        </DialogHeader>
        {woQuery.isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
        {wo && (
          <div className="space-y-4 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <Field label="Quantity" value={String(wo.quantity)} />
              <Field label="Produced" value={String(wo.produced_qty)} />
              <Field label="BOM" value={wo.bom_id || "—"} />
              <Field label="Work center" value={wo.work_center_id || "—"} />
              <Field label="Created" value={fmtTs(wo.created_at)} />
              <Field label="Updated" value={fmtTs(wo.updated_at)} />
            </div>
            <div>
              <p className="mb-2 font-medium">Material issues</p>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Component</TableHead>
                    <TableHead>Required</TableHead>
                    <TableHead>Issued</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead>Issued at</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {wo.issues.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">
                        No material issued yet.
                      </TableCell>
                    </TableRow>
                  )}
                  {wo.issues.map((it, i) => (
                    <TableRow key={`${it.component_sku}-${i}`}>
                      <TableCell>{it.component_sku}</TableCell>
                      <TableCell>{it.required_quantity}</TableCell>
                      <TableCell>{it.issued_quantity}</TableCell>
                      <TableCell>{it.location_id}</TableCell>
                      <TableCell>{fmtTs(it.issued_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p>{value}</p>
    </div>
  );
}
