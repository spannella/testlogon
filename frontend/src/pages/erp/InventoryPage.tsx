import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Boxes, RefreshCw, Search } from "lucide-react";

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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

import {
  adjustInventory,
  getInventoryItem,
  listInventoryByStatus,
  setInventoryOnHand,
  type InventoryRecord,
  type InventoryStatus,
} from "@/api/endpoints/erp";
import { errMessage, fmtTs, isNotEnabledError, NotEnabledCard } from "./erpShared";

const STATUS_TABS: { value: InventoryStatus; label: string }[] = [
  { value: "low_stock", label: "Low stock" },
  { value: "out_of_stock", label: "Out of stock" },
  { value: "in_stock", label: "In stock" },
];

function statusBadge(status: InventoryStatus) {
  if (status === "out_of_stock") return <Badge variant="destructive">Out of stock</Badge>;
  if (status === "low_stock") return <Badge variant="warning">Low stock</Badge>;
  return <Badge variant="success">In stock</Badge>;
}

export default function InventoryPage() {
  const qc = useQueryClient();
  const [statusTab, setStatusTab] = useState<InventoryStatus>("low_stock");
  const [skuQuery, setSkuQuery] = useState("");
  const [lookedUpSku, setLookedUpSku] = useState<string | null>(null);

  // Adjust / set dialog state
  const [editRec, setEditRec] = useState<InventoryRecord | null>(null);
  const [mode, setMode] = useState<"set" | "adjust">("set");
  const [onHandInput, setOnHandInput] = useState("");
  const [deltaInput, setDeltaInput] = useState("");
  const [reorderInput, setReorderInput] = useState("");
  const [reasonInput, setReasonInput] = useState("");

  const listQuery = useQuery({
    queryKey: ["erp", "inventory", "list", statusTab],
    queryFn: () => listInventoryByStatus(statusTab),
    retry: false,
  });

  const lookupQuery = useQuery({
    queryKey: ["erp", "inventory", "item", lookedUpSku],
    queryFn: () => getInventoryItem(lookedUpSku!),
    enabled: !!lookedUpSku,
    retry: false,
  });

  const notEnabled = isNotEnabledError(listQuery.error);

  function openEdit(rec: InventoryRecord, m: "set" | "adjust") {
    setEditRec(rec);
    setMode(m);
    setOnHandInput(String(rec.on_hand));
    setDeltaInput("");
    setReorderInput(String(rec.reorder_point));
    setReasonInput("");
  }

  function refetchAll() {
    void listQuery.refetch();
    if (lookedUpSku) void lookupQuery.refetch();
  }

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!editRec) throw new Error("No record selected");
      if (mode === "set") {
        const onHand = Number(onHandInput);
        if (!Number.isFinite(onHand) || onHand < 0) throw new Error("On-hand must be a non-negative number");
        const reorder = reorderInput.trim() === "" ? undefined : Number(reorderInput);
        return setInventoryOnHand({
          sku: editRec.sku,
          on_hand: onHand,
          location_id: editRec.location_id,
          reorder_point: reorder,
          reason: reasonInput.trim() || undefined,
        });
      }
      const delta = Number(deltaInput);
      if (!Number.isFinite(delta) || delta === 0) throw new Error("Delta must be a non-zero number");
      return adjustInventory({
        sku: editRec.sku,
        delta,
        location_id: editRec.location_id,
        reason: reasonInput.trim() || undefined,
      });
    },
    onSuccess: (rec) => {
      toast.success(`Inventory updated for ${rec.sku}`);
      setEditRec(null);
      refetchAll();
      void qc.invalidateQueries({ queryKey: ["erp", "inventory"] });
    },
    onError: (err) => toast.error(errMessage(err, "Unable to update inventory")),
  });

  const items = listQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Inventory Levels"
        description="On-hand, reserved and available stock per SKU. Adjust quantities and reorder points."
        actions={
          <Button variant="outline" size="sm" onClick={refetchAll} disabled={listQuery.isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${listQuery.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {notEnabled ? (
        <NotEnabledCard module="Inventory & reservations" flag="INVENTORY_RESERVATIONS_ENABLED" />
      ) : (
        <>
          {/* SKU lookup */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Search className="h-4 w-4" /> SKU lookup
              </CardTitle>
              <CardDescription>Look up an exact SKU's stock record.</CardDescription>
            </CardHeader>
            <CardContent>
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  const sku = skuQuery.trim();
                  if (sku) setLookedUpSku(sku);
                }}
              >
                <div className="flex-1 min-w-[220px] space-y-1">
                  <Label htmlFor="sku-lookup">SKU</Label>
                  <Input
                    id="sku-lookup"
                    value={skuQuery}
                    onChange={(e) => setSkuQuery(e.target.value)}
                    placeholder="e.g. WIDGET-001"
                  />
                </div>
                <Button type="submit" disabled={!skuQuery.trim()}>
                  Look up
                </Button>
              </form>

              {lookedUpSku && (
                <div className="mt-4">
                  {lookupQuery.isLoading ? (
                    <Skeleton className="h-16 w-full" />
                  ) : lookupQuery.error ? (
                    <p className="text-sm text-muted-foreground">
                      No inventory record found for <span className="font-mono">{lookedUpSku}</span>.
                    </p>
                  ) : lookupQuery.data ? (
                    <InventoryRow
                      rec={lookupQuery.data}
                      onSet={() => openEdit(lookupQuery.data!, "set")}
                      onAdjust={() => openEdit(lookupQuery.data!, "adjust")}
                      asCard
                    />
                  ) : null}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Status-filtered list */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Boxes className="h-4 w-4" /> Stock by status
              </CardTitle>
              <CardDescription>Inventory records grouped by derived availability status.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Tabs value={statusTab} onValueChange={(v) => setStatusTab(v as InventoryStatus)}>
                <TabsList>
                  {STATUS_TABS.map((t) => (
                    <TabsTrigger key={t.value} value={t.value}>
                      {t.label}
                    </TabsTrigger>
                  ))}
                </TabsList>
              </Tabs>

              {listQuery.isLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                </div>
              ) : items.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  No SKUs are currently in the "{STATUS_TABS.find((t) => t.value === statusTab)?.label}" state.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>SKU</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead className="text-right">On hand</TableHead>
                      <TableHead className="text-right">Reserved</TableHead>
                      <TableHead className="text-right">Available</TableHead>
                      <TableHead className="text-right">Reorder pt</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Updated</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((rec) => (
                      <TableRow key={`${rec.sku}:${rec.location_id}`}>
                        <TableCell className="font-mono">{rec.sku}</TableCell>
                        <TableCell>{rec.location_id}</TableCell>
                        <TableCell className="text-right">{rec.on_hand}</TableCell>
                        <TableCell className="text-right">{rec.reserved}</TableCell>
                        <TableCell className="text-right font-medium">{rec.available}</TableCell>
                        <TableCell className="text-right">{rec.reorder_point}</TableCell>
                        <TableCell>{statusBadge(rec.status)}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{fmtTs(rec.updated_at)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button size="sm" variant="outline" onClick={() => openEdit(rec, "adjust")}>
                              Adjust
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => openEdit(rec, "set")}>
                              Set
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Adjust / set dialog */}
      <Dialog open={!!editRec} onOpenChange={(o) => !o && setEditRec(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {mode === "set" ? "Set on-hand" : "Adjust on-hand"} — {editRec?.sku}
            </DialogTitle>
            <DialogDescription>
              {mode === "set"
                ? "Overwrite the absolute on-hand quantity for this SKU."
                : "Apply a relative delta (positive to add, negative to remove) to on-hand."}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {mode === "set" ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor="on-hand">On hand</Label>
                  <Input
                    id="on-hand"
                    type="number"
                    min={0}
                    value={onHandInput}
                    onChange={(e) => setOnHandInput(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="reorder">Reorder point (optional)</Label>
                  <Input
                    id="reorder"
                    type="number"
                    min={0}
                    value={reorderInput}
                    onChange={(e) => setReorderInput(e.target.value)}
                  />
                </div>
              </>
            ) : (
              <div className="space-y-1">
                <Label htmlFor="delta">Delta</Label>
                <Input
                  id="delta"
                  type="number"
                  value={deltaInput}
                  onChange={(e) => setDeltaInput(e.target.value)}
                  placeholder="e.g. -5 or 10"
                />
              </div>
            )}
            <div className="space-y-1">
              <Label htmlFor="reason">Reason (optional)</Label>
              <Input
                id="reason"
                value={reasonInput}
                onChange={(e) => setReasonInput(e.target.value)}
                placeholder="e.g. cycle count, damage write-off"
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>Switch mode:</span>
              <Select value={mode} onValueChange={(v) => setMode(v as "set" | "adjust")}>
                <SelectTrigger className="h-7 w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="set">Set absolute</SelectItem>
                  <SelectItem value="adjust">Adjust delta</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditRec(null)}>
              Cancel
            </Button>
            <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
              {saveMut.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function InventoryRow({
  rec,
  onSet,
  onAdjust,
  asCard,
}: {
  rec: InventoryRecord;
  onSet: () => void;
  onAdjust: () => void;
  asCard?: boolean;
}) {
  return (
    <div className={asCard ? "rounded-md border p-4" : ""}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-mono font-medium">{rec.sku}</span>
            {statusBadge(rec.status)}
          </div>
          <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
            <span>Location: {rec.location_id}</span>
            <span>On hand: <b className="text-foreground">{rec.on_hand}</b></span>
            <span>Reserved: <b className="text-foreground">{rec.reserved}</b></span>
            <span>Available: <b className="text-foreground">{rec.available}</b></span>
            <span>Reorder pt: {rec.reorder_point}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={onAdjust}>
            Adjust
          </Button>
          <Button size="sm" variant="outline" onClick={onSet}>
            Set
          </Button>
        </div>
      </div>
    </div>
  );
}
