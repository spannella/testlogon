import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2, Layers, Hammer } from "lucide-react";

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
  addRoutingTask,
  createBom,
  deactivateBom,
  deleteRoutingTask,
  explodeBom,
  formatCents,
  getBom,
  getRoutingCost,
  listBoms,
  listRoutingTasks,
  listWorkCenters,
  type BomComponentIn,
  type BomOut,
} from "@/api/endpoints/manufacturing";
import { StatusBadge, fmtTs, isFeatureDisabled } from "./lib";

interface DraftComponent extends BomComponentIn {
  scrap_pct: number;
  unit_of_measure: string;
}

export default function BomEditorPage() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const bomsQuery = useQuery({
    queryKey: ["mfg", "boms"],
    queryFn: () => listBoms(),
    retry: false,
  });

  const featureOff = isFeatureDisabled(bomsQuery.error);

  // ── New-BOM dialog state ────────────────────────────────────────────
  const [productSku, setProductSku] = useState("");
  const [name, setName] = useState("");
  const [outputQty, setOutputQty] = useState(1);
  const [components, setComponents] = useState<DraftComponent[]>([]);
  const [compSku, setCompSku] = useState("");
  const [compQty, setCompQty] = useState(1);
  const [compScrap, setCompScrap] = useState(0);
  const [compUom, setCompUom] = useState("each");

  function addDraftComponent() {
    if (!compSku.trim() || compQty <= 0) {
      toast.error("Component SKU and a positive quantity are required");
      return;
    }
    setComponents((cs) => [
      ...cs,
      {
        component_sku: compSku.trim(),
        quantity_per: compQty,
        scrap_pct: compScrap,
        unit_of_measure: compUom.trim() || "each",
      },
    ]);
    setCompSku("");
    setCompQty(1);
    setCompScrap(0);
    setCompUom("each");
  }

  const createMut = useMutation({
    mutationFn: () =>
      createBom({
        product_sku: productSku.trim(),
        name: name.trim(),
        output_quantity: outputQty,
        components,
      }),
    onSuccess: (bom) => {
      toast.success("BOM created");
      setCreateOpen(false);
      setProductSku("");
      setName("");
      setOutputQty(1);
      setComponents([]);
      setSelectedId(bom.bom_id);
      void qc.invalidateQueries({ queryKey: ["mfg", "boms"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to create BOM"),
  });

  const deactivateMut = useMutation({
    mutationFn: (bomId: string) => deactivateBom(bomId),
    onSuccess: () => {
      toast.success("BOM deactivated");
      void qc.invalidateQueries({ queryKey: ["mfg", "boms"] });
      void qc.invalidateQueries({ queryKey: ["mfg", "bom", selectedId] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to deactivate"),
  });

  const boms = bomsQuery.data?.boms ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Bill of Materials"
        description="Define product recipes, component lines, and routing operations."
        actions={
          <Button onClick={() => setCreateOpen(true)} disabled={featureOff}>
            <Plus className="mr-2 h-4 w-4" /> New BOM
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
        <div className="grid gap-6 lg:grid-cols-[360px_1fr]">
          <Card>
            <CardHeader>
              <CardTitle>BOMs</CardTitle>
              <CardDescription>{boms.length} total</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1">
              {bomsQuery.isLoading && (
                <p className="text-sm text-muted-foreground">Loading…</p>
              )}
              {!bomsQuery.isLoading && boms.length === 0 && (
                <p className="text-sm text-muted-foreground">No BOMs yet.</p>
              )}
              {boms.map((b) => (
                <button
                  key={b.bom_id}
                  onClick={() => setSelectedId(b.bom_id)}
                  className={`flex w-full flex-col rounded-md border p-3 text-left transition hover:bg-accent ${
                    selectedId === b.bom_id ? "border-primary bg-accent" : "border-transparent"
                  }`}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="font-medium">{b.name}</span>
                    <StatusBadge status={b.status} />
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {b.product_sku} · {b.components.length} components
                  </span>
                </button>
              ))}
            </CardContent>
          </Card>

          {selectedId ? (
            <BomDetail
              bomId={selectedId}
              onDeactivate={(id) => deactivateMut.mutate(id)}
            />
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-sm text-muted-foreground">
                Select a BOM to view its components and routing.
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ── Create dialog ── */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>New Bill of Materials</DialogTitle>
            <DialogDescription>Define the finished product and its component lines.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <Label htmlFor="bom-product">Product SKU</Label>
                <Input id="bom-product" value={productSku} onChange={(e) => setProductSku(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="bom-output">Output quantity</Label>
                <Input
                  id="bom-output"
                  type="number"
                  min={1}
                  value={outputQty}
                  onChange={(e) => setOutputQty(Math.max(1, Number(e.target.value)))}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label htmlFor="bom-name">Name</Label>
              <Input id="bom-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>

            <div className="rounded-md border p-3">
              <p className="mb-2 text-sm font-medium">Components</p>
              {components.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>SKU</TableHead>
                      <TableHead>Qty / unit</TableHead>
                      <TableHead>Scrap %</TableHead>
                      <TableHead>UoM</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {components.map((c, i) => (
                      <TableRow key={`${c.component_sku}-${i}`}>
                        <TableCell>{c.component_sku}</TableCell>
                        <TableCell>{c.quantity_per}</TableCell>
                        <TableCell>{(c.scrap_pct * 100).toFixed(1)}%</TableCell>
                        <TableCell>{c.unit_of_measure}</TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setComponents((cs) => cs.filter((_, j) => j !== i))}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
              <div className="mt-3 grid grid-cols-[1fr_90px_90px_90px_auto] items-end gap-2">
                <div className="space-y-1">
                  <Label className="text-xs">Component SKU</Label>
                  <Input value={compSku} onChange={(e) => setCompSku(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Qty</Label>
                  <Input type="number" min={0} step="any" value={compQty} onChange={(e) => setCompQty(Number(e.target.value))} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Scrap</Label>
                  <Input type="number" min={0} max={0.99} step="0.01" value={compScrap} onChange={(e) => setCompScrap(Number(e.target.value))} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">UoM</Label>
                  <Input value={compUom} onChange={(e) => setCompUom(e.target.value)} />
                </div>
                <Button variant="secondary" onClick={addDraftComponent}>
                  Add
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending || !productSku.trim() || !name.trim()}
            >
              Create BOM
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── BOM detail (components + routing) ─────────────────────────────────

function BomDetail({
  bomId,
  onDeactivate,
}: {
  bomId: string;
  onDeactivate: (id: string) => void;
}) {
  const qc = useQueryClient();
  const [buildQty, setBuildQty] = useState(1);

  const bomQuery = useQuery({
    queryKey: ["mfg", "bom", bomId],
    queryFn: () => getBom(bomId),
  });
  const tasksQuery = useQuery({
    queryKey: ["mfg", "routing-tasks", bomId],
    queryFn: () => listRoutingTasks(bomId),
  });
  const costQuery = useQuery({
    queryKey: ["mfg", "routing-cost", bomId, buildQty],
    queryFn: () => getRoutingCost(bomId, buildQty),
  });
  const explodeQuery = useQuery({
    queryKey: ["mfg", "explode", bomId, buildQty],
    queryFn: () => explodeBom(bomId, buildQty),
  });
  const wcQuery = useQuery({
    queryKey: ["mfg", "work-centers"],
    queryFn: () => listWorkCenters("active"),
  });

  // routing-task draft
  const [taskWc, setTaskWc] = useState("");
  const [taskSeq, setTaskSeq] = useState(10);
  const [taskSetup, setTaskSetup] = useState(0);
  const [taskRun, setTaskRun] = useState(0);
  const [taskDesc, setTaskDesc] = useState("");

  const addTaskMut = useMutation({
    mutationFn: () =>
      addRoutingTask(bomId, {
        work_center_id: taskWc,
        sequence: taskSeq,
        setup_minutes: taskSetup,
        run_minutes_per_unit: taskRun,
        description: taskDesc.trim(),
      }),
    onSuccess: () => {
      toast.success("Routing task added");
      setTaskWc("");
      setTaskDesc("");
      void qc.invalidateQueries({ queryKey: ["mfg", "routing-tasks", bomId] });
      void qc.invalidateQueries({ queryKey: ["mfg", "routing-cost", bomId] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to add task"),
  });

  const delTaskMut = useMutation({
    mutationFn: (seq: number) => deleteRoutingTask(bomId, seq),
    onSuccess: () => {
      toast.success("Routing task removed");
      void qc.invalidateQueries({ queryKey: ["mfg", "routing-tasks", bomId] });
      void qc.invalidateQueries({ queryKey: ["mfg", "routing-cost", bomId] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to remove task"),
  });

  const bom: BomOut | undefined = bomQuery.data;
  const tasks = tasksQuery.data?.tasks ?? [];
  const cost = costQuery.data;
  const workCenters = wcQuery.data?.work_centers ?? [];

  if (bomQuery.isLoading) {
    return (
      <Card>
        <CardContent className="py-16 text-center text-sm text-muted-foreground">Loading BOM…</CardContent>
      </Card>
    );
  }
  if (!bom) {
    return (
      <Card>
        <CardContent className="py-16 text-center text-sm text-muted-foreground">BOM not found.</CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2">
                {bom.name} <StatusBadge status={bom.status} />
              </CardTitle>
              <CardDescription>
                {bom.product_sku} · output {bom.output_quantity} · updated {fmtTs(bom.updated_at)}
              </CardDescription>
            </div>
            {bom.status === "active" && (
              <Button variant="outline" size="sm" onClick={() => onDeactivate(bom.bom_id)}>
                Deactivate
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex items-center gap-3">
            <Label htmlFor="build-qty" className="text-sm">Build qty</Label>
            <Input
              id="build-qty"
              type="number"
              min={1}
              value={buildQty}
              onChange={(e) => setBuildQty(Math.max(1, Number(e.target.value)))}
              className="w-28"
            />
          </div>
          <p className="mb-2 flex items-center gap-2 text-sm font-medium">
            <Layers className="h-4 w-4" /> Components
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>SKU</TableHead>
                <TableHead>Qty / unit</TableHead>
                <TableHead>Scrap %</TableHead>
                <TableHead>UoM</TableHead>
                <TableHead>Required (exploded)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {bom.components.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">
                    No components.
                  </TableCell>
                </TableRow>
              )}
              {bom.components.map((c) => {
                const ex = explodeQuery.data?.components.find((e) => e.component_sku === c.component_sku);
                return (
                  <TableRow key={`${c.component_sku}-${c.seq}`}>
                    <TableCell className="font-medium">{c.component_sku}</TableCell>
                    <TableCell>{c.quantity_per}</TableCell>
                    <TableCell>{(c.scrap_pct * 100).toFixed(1)}%</TableCell>
                    <TableCell>{c.unit_of_measure}</TableCell>
                    <TableCell>{ex ? ex.required_qty : "—"}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Hammer className="h-4 w-4" /> Routing tasks
          </CardTitle>
          <CardDescription>
            {cost ? (
              <>
                Labor: <span className="font-medium">{formatCents(cost.total_labor_cost_cents)}</span> for {cost.quantity} unit(s) ·{" "}
                {cost.total_minutes} min total
              </>
            ) : (
              "Ordered operations and their work centers"
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Seq</TableHead>
                <TableHead>Work center</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Setup (min)</TableHead>
                <TableHead>Run/unit (min)</TableHead>
                <TableHead>Cost</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tasks.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">
                    No routing tasks.
                  </TableCell>
                </TableRow>
              )}
              {tasks.map((t) => {
                const ct = cost?.tasks.find((x) => x.sequence === t.sequence);
                return (
                  <TableRow key={t.sequence}>
                    <TableCell>{t.sequence}</TableCell>
                    <TableCell>
                      {workCenters.find((w) => w.work_center_id === t.work_center_id)?.name ?? t.work_center_id}
                    </TableCell>
                    <TableCell>{t.description || "—"}</TableCell>
                    <TableCell>{t.setup_minutes}</TableCell>
                    <TableCell>{t.run_minutes_per_unit}</TableCell>
                    <TableCell>{ct ? formatCents(ct.task_cost_cents) : "—"}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm" onClick={() => delTaskMut.mutate(t.sequence)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>

          <div className="grid grid-cols-[1fr_80px_90px_90px_auto] items-end gap-2 rounded-md border p-3">
            <div className="space-y-1">
              <Label className="text-xs">Work center</Label>
              <Select value={taskWc} onValueChange={setTaskWc}>
                <SelectTrigger>
                  <SelectValue placeholder="Select…" />
                </SelectTrigger>
                <SelectContent>
                  {workCenters.length === 0 && (
                    <SelectItem value="__none" disabled>
                      No active work centers
                    </SelectItem>
                  )}
                  {workCenters.map((w) => (
                    <SelectItem key={w.work_center_id} value={w.work_center_id}>
                      {w.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Seq</Label>
              <Input type="number" min={0} value={taskSeq} onChange={(e) => setTaskSeq(Number(e.target.value))} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Setup</Label>
              <Input type="number" min={0} value={taskSetup} onChange={(e) => setTaskSetup(Number(e.target.value))} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Run/unit</Label>
              <Input type="number" min={0} value={taskRun} onChange={(e) => setTaskRun(Number(e.target.value))} />
            </div>
            <Button
              variant="secondary"
              onClick={() => addTaskMut.mutate()}
              disabled={!taskWc || addTaskMut.isPending}
            >
              Add task
            </Button>
            <div className="col-span-full space-y-1">
              <Label className="text-xs">Description</Label>
              <Input value={taskDesc} onChange={(e) => setTaskDesc(e.target.value)} placeholder="Optional" />
            </div>
          </div>
        </CardContent>
      </Card>

      {wcQuery.data && workCenters.length === 0 && (
        <Badge variant="outline">Create a work center to add routing tasks.</Badge>
      )}
    </div>
  );
}
