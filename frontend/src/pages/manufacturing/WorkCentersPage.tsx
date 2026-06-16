import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus } from "lucide-react";

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
  createWorkCenter,
  formatCents,
  listWorkCenters,
  updateWorkCenter,
} from "@/api/endpoints/manufacturing";
import { StatusBadge, fmtTs, isFeatureDisabled } from "./lib";

export default function WorkCentersPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);

  const wcQuery = useQuery({
    queryKey: ["mfg", "work-centers", "active"],
    queryFn: () => listWorkCenters("active"),
    retry: false,
  });
  const featureOff = isFeatureDisabled(wcQuery.error);

  const [name, setName] = useState("");
  const [capacity, setCapacity] = useState(0);
  const [costPerHour, setCostPerHour] = useState(0); // dollars in UI → cents to API

  const createMut = useMutation({
    mutationFn: () =>
      createWorkCenter({
        name: name.trim(),
        capacity_per_hour: capacity,
        cost_per_hour_cents: Math.round(costPerHour * 100),
      }),
    onSuccess: () => {
      toast.success("Work center created");
      setCreateOpen(false);
      setName("");
      setCapacity(0);
      setCostPerHour(0);
      void qc.invalidateQueries({ queryKey: ["mfg", "work-centers"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to create work center"),
  });

  const archiveMut = useMutation({
    mutationFn: (id: string) => updateWorkCenter(id, { status: "inactive" }),
    onSuccess: () => {
      toast.success("Work center archived");
      void qc.invalidateQueries({ queryKey: ["mfg", "work-centers"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to archive"),
  });

  const workCenters = wcQuery.data?.work_centers ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Work Centers"
        description="Production resources used by routing tasks (capacity and labor rate)."
        actions={
          <Button onClick={() => setCreateOpen(true)} disabled={featureOff}>
            <Plus className="mr-2 h-4 w-4" /> New work center
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
        <Card>
          <CardHeader>
            <CardTitle>Active work centers</CardTitle>
            <CardDescription>{workCenters.length} active</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Capacity / hr</TableHead>
                  <TableHead>Cost / hr</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {wcQuery.isLoading && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {!wcQuery.isLoading && workCenters.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                      No active work centers.
                    </TableCell>
                  </TableRow>
                )}
                {workCenters.map((w) => (
                  <TableRow key={w.work_center_id}>
                    <TableCell className="font-medium">{w.name}</TableCell>
                    <TableCell>{w.capacity_per_hour}</TableCell>
                    <TableCell>{formatCents(w.cost_per_hour_cents)}</TableCell>
                    <TableCell>
                      <StatusBadge status={w.status} />
                    </TableCell>
                    <TableCell>{fmtTs(w.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" onClick={() => archiveMut.mutate(w.work_center_id)}>
                        Archive
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New work center</DialogTitle>
            <DialogDescription>Capacity is units per hour; cost is the labor rate per hour.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="space-y-1">
              <Label htmlFor="wc-name">Name</Label>
              <Input id="wc-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <Label htmlFor="wc-cap">Capacity / hour</Label>
                <Input
                  id="wc-cap"
                  type="number"
                  min={0}
                  value={capacity}
                  onChange={(e) => setCapacity(Math.max(0, Number(e.target.value)))}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="wc-cost">Cost / hour ($)</Label>
                <Input
                  id="wc-cost"
                  type="number"
                  min={0}
                  step="0.01"
                  value={costPerHour}
                  onChange={(e) => setCostPerHour(Math.max(0, Number(e.target.value)))}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending || !name.trim()}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
