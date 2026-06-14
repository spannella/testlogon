import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Wrench } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
  createWorkOrder,
  listWorkOrdersForAsset,
  transitionWorkOrder,
  type AssetMaintenanceOrder,
  type FixedAsset,
} from "@/api/endpoints/fixedAssets";
import { dollarsToCents, fmtCents, fmtTs, prettyStatus, statusVariant } from "./lib";

interface Props {
  asset: FixedAsset;
}

export function WorkOrdersPanel({ asset }: Props) {
  const qc = useQueryClient();
  const assetId = asset.asset_id;

  const [createOpen, setCreateOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [assignee, setAssignee] = useState("");

  // Per-completion cost prompt state
  const [completeFor, setCompleteFor] = useState<AssetMaintenanceOrder | null>(null);
  const [completeCost, setCompleteCost] = useState("");

  const woQuery = useQuery({
    queryKey: ["fixed-assets", "work-orders", assetId],
    queryFn: () => listWorkOrdersForAsset(assetId, { limit: 100 }),
    retry: false,
  });

  const workOrders = woQuery.data?.items ?? [];

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["fixed-assets", "work-orders", assetId] });

  const createMut = useMutation({
    mutationFn: () =>
      createWorkOrder(assetId, {
        title: title.trim(),
        description: description.trim() || undefined,
        assignee_sub: assignee.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Work order created");
      setCreateOpen(false);
      setTitle("");
      setDescription("");
      setAssignee("");
      void invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to create work order"),
  });

  const transitionMut = useMutation({
    mutationFn: (vars: {
      workOrderId: string;
      target_status: "in_progress" | "completed" | "cancelled";
      cost_cents?: number;
    }) =>
      transitionWorkOrder(vars.workOrderId, assetId, {
        target_status: vars.target_status,
        cost_cents: vars.cost_cents,
      }),
    onSuccess: () => {
      toast.success("Work order updated");
      setCompleteFor(null);
      setCompleteCost("");
      void invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to update work order"),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Maintenance work orders for this asset
        </p>
        <Button
          size="sm"
          variant="outline"
          onClick={() => setCreateOpen(true)}
          disabled={asset.status === "disposed"}
        >
          <Plus className="mr-2 h-4 w-4" />
          New work order
        </Button>
      </div>

      {woQuery.isLoading ? (
        <p className="py-6 text-center text-sm text-muted-foreground">Loading work orders…</p>
      ) : workOrders.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-8 text-center">
          <Wrench className="h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">No work orders for this asset.</p>
        </div>
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Assignee</TableHead>
                <TableHead className="text-right">Cost</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {workOrders.map((wo: AssetMaintenanceOrder) => (
                <TableRow key={wo.work_order_id}>
                  <TableCell className="font-medium">{wo.title}</TableCell>
                  <TableCell>{wo.assignee_sub ?? "—"}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {fmtCents(wo.cost_cents)}
                  </TableCell>
                  <TableCell>{fmtTs(wo.created_at)}</TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(wo.wo_status)}>
                      {prettyStatus(wo.wo_status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      {wo.wo_status === "open" && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            transitionMut.mutate({
                              workOrderId: wo.work_order_id,
                              target_status: "in_progress",
                            })
                          }
                          disabled={transitionMut.isPending}
                        >
                          Start
                        </Button>
                      )}
                      {wo.wo_status === "in_progress" && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setCompleteFor(wo);
                            setCompleteCost("");
                          }}
                          disabled={transitionMut.isPending}
                        >
                          Complete
                        </Button>
                      )}
                      {(wo.wo_status === "open" || wo.wo_status === "in_progress") && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-destructive"
                          onClick={() =>
                            transitionMut.mutate({
                              workOrderId: wo.work_order_id,
                              target_status: "cancelled",
                            })
                          }
                          disabled={transitionMut.isPending}
                        >
                          Cancel
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create work order dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New work order</DialogTitle>
            <DialogDescription>Schedule maintenance for {asset.name}.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-2">
              <Label htmlFor="wo-title">Title</Label>
              <Input
                id="wo-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Replace cooling fan"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="wo-desc">Description</Label>
              <Textarea
                id="wo-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="wo-assignee">Assignee (user sub)</Label>
              <Input
                id="wo-assignee"
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
                placeholder="optional"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!title.trim() || createMut.isPending}
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Complete work order dialog (captures cost) */}
      <Dialog open={!!completeFor} onOpenChange={(o) => !o && setCompleteFor(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Complete work order</DialogTitle>
            <DialogDescription>
              Record the final maintenance cost for "{completeFor?.title}".
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2 py-2">
            <Label htmlFor="wo-cost">Cost ($)</Label>
            <Input
              id="wo-cost"
              value={completeCost}
              onChange={(e) => setCompleteCost(e.target.value)}
              placeholder="0.00"
              inputMode="decimal"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCompleteFor(null)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                completeFor &&
                transitionMut.mutate({
                  workOrderId: completeFor.work_order_id,
                  target_status: "completed",
                  cost_cents: completeCost ? dollarsToCents(completeCost) : undefined,
                })
              }
              disabled={transitionMut.isPending}
            >
              {transitionMut.isPending ? "Saving…" : "Mark complete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
