import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  LayoutGrid,
  Play,
  Square,
  Trash2,
  Plus,
  Bot,
  Server,
  Activity,
  Clock,
  AlertCircle,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import {
  getFleetStatus,
  getCapacity,
  bulkStart,
  bulkStop,
  listTemplates,
  createTemplate,
  deleteTemplate,
  createFromTemplate,
} from "@/api/endpoints/agentFleet";
import type { WorkerTemplateIn } from "@/api/types";

// ─── Status badge colors ────────────────────────────────────────

function statusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "ready":
    case "running":
      return "default";
    case "provisioning":
      return "secondary";
    case "error":
      return "destructive";
    case "stopped":
    case "terminated":
      return "outline";
    default:
      return "secondary";
  }
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

// ─── Fleet Dashboard Component ──────────────────────────────────

export default function FleetDashboard() {
  const queryClient = useQueryClient();
  const [selectedWorkerId, setSelectedWorkerId] = useState<string | null>(null);
  const [templateDialogOpen, setTemplateDialogOpen] = useState(false);

  // ─── Queries ────────────────────────────────────────────────
  const {
    data: fleetStatus,
    isLoading: statusLoading,
  } = useQuery({
    queryKey: ["fleet", "status"],
    queryFn: getFleetStatus,
    refetchInterval: 10_000,
  });

  const { data: capacity } = useQuery({
    queryKey: ["fleet", "capacity"],
    queryFn: getCapacity,
    refetchInterval: 15_000,
  });

  const { data: templateData } = useQuery({
    queryKey: ["fleet", "templates"],
    queryFn: listTemplates,
  });

  // ─── Mutations ──────────────────────────────────────────────
  const startAllMut = useMutation({
    mutationFn: bulkStart,
    onSuccess: (data) => {
      toast.success(`Started ${data.count} worker(s)`);
      queryClient.invalidateQueries({ queryKey: ["fleet"] });
    },
    onError: () => toast.error("Failed to start workers"),
  });

  const stopAllMut = useMutation({
    mutationFn: bulkStop,
    onSuccess: (data) => {
      toast.success(`Stopped ${data.count} worker(s)`);
      queryClient.invalidateQueries({ queryKey: ["fleet"] });
    },
    onError: () => toast.error("Failed to stop workers"),
  });

  const deleteTemplateMut = useMutation({
    mutationFn: (id: string) => deleteTemplate(id),
    onSuccess: () => {
      toast.success("Template deleted");
      queryClient.invalidateQueries({ queryKey: ["fleet", "templates"] });
    },
    onError: () => toast.error("Failed to delete template"),
  });

  const createFromTemplateMut = useMutation({
    mutationFn: ({ templateId, label }: { templateId: string; label?: string }) =>
      createFromTemplate(templateId, label),
    onSuccess: () => {
      toast.success("Worker created from template");
      queryClient.invalidateQueries({ queryKey: ["fleet"] });
    },
    onError: () => toast.error("Failed to create worker from template"),
  });

  const workers = fleetStatus?.workers ?? [];
  const templates = templateData?.templates ?? [];
  const selectedWorker = workers.find((w) => w.worker_id === selectedWorkerId);

  const statusCounts = fleetStatus?.status_counts ?? {};
  const activeCount = (statusCounts.ready ?? 0) + (statusCounts.running ?? 0);

  return (
    <div className="space-y-6">
      {/* ─── Header ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <LayoutGrid className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Agent Fleet</h1>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => startAllMut.mutate()}
            disabled={startAllMut.isPending}
          >
            <Play className="mr-1 h-4 w-4" />
            Start All
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => stopAllMut.mutate()}
            disabled={stopAllMut.isPending}
          >
            <Square className="mr-1 h-4 w-4" />
            Stop All
          </Button>
        </div>
      </div>

      {/* ─── Stats Bar ───────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Total Workers</span>
            </div>
            <p className="mt-1 text-2xl font-bold">
              {statusLoading ? "--" : fleetStatus?.total_workers ?? 0}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Active</span>
            </div>
            <p className="mt-1 text-2xl font-bold">
              {statusLoading ? "--" : activeCount}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Queue Depth</span>
            </div>
            <p className="mt-1 text-2xl font-bold">
              {statusLoading ? "--" : fleetStatus?.queue_depth ?? 0}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Errors</span>
            </div>
            <p className="mt-1 text-2xl font-bold">
              {statusLoading ? "--" : statusCounts.error ?? 0}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* ─── Capacity Section ────────────────────────────────── */}
      {capacity && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Capacity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="mb-2 text-sm font-medium text-muted-foreground">
                  Queue by Type
                </p>
                {Object.entries(capacity.queue_by_type).length === 0 ? (
                  <p className="text-sm text-muted-foreground">No tickets in queue</p>
                ) : (
                  Object.entries(capacity.queue_by_type).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-sm">
                      <span>{type}</span>
                      <Badge variant="secondary">{count}</Badge>
                    </div>
                  ))
                )}
              </div>
              <div>
                <p className="mb-2 text-sm font-medium text-muted-foreground">
                  Workers by State
                </p>
                {Object.entries(capacity.workers_by_state).length === 0 ? (
                  <p className="text-sm text-muted-foreground">No workers</p>
                ) : (
                  Object.entries(capacity.workers_by_state).map(([state, count]) => (
                    <div key={state} className="flex items-center justify-between text-sm">
                      <span>{state}</span>
                      <Badge variant="secondary">{count}</Badge>
                    </div>
                  ))
                )}
              </div>
            </div>
            {capacity.recommended_action && (
              <p className="mt-3 text-sm text-amber-600 dark:text-amber-400">
                {capacity.recommended_action}
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* ─── Worker Grid ─────────────────────────────────────── */}
      <div>
        <h2 className="mb-3 text-lg font-semibold">Workers</h2>
        {workers.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center text-muted-foreground">
              <Bot className="mx-auto mb-3 h-8 w-8" />
              <p>No workers yet. Create your first worker to get started.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {workers.map((worker) => (
              <Card
                key={worker.worker_id}
                className="cursor-pointer transition-shadow hover:shadow-md"
                onClick={() => setSelectedWorkerId(worker.worker_id)}
              >
                <CardContent className="pt-4">
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <p className="truncate font-medium">{worker.label}</p>
                      <p className="text-sm text-muted-foreground">
                        {worker.agent_type} / {worker.tool}
                      </p>
                    </div>
                    <Badge variant={statusVariant(worker.worker_status)}>
                      {worker.worker_status}
                    </Badge>
                  </div>
                  {worker.current_ticket_title && (
                    <p className="mt-2 truncate text-sm text-muted-foreground">
                      Working on: {worker.current_ticket_title}
                    </p>
                  )}
                  <div className="mt-3 flex items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatUptime(worker.uptime_seconds)}
                    </span>
                    <span>
                      {worker.tickets_completed} completed
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* ─── Templates Section ───────────────────────────────── */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Templates</h2>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setTemplateDialogOpen(true)}
          >
            <Plus className="mr-1 h-4 w-4" />
            Save Template
          </Button>
        </div>
        {templates.length === 0 ? (
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              <p>No templates saved. Save a worker configuration as a template for quick reuse.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {templates.map((tmpl) => (
              <Card key={tmpl.template_id}>
                <CardContent className="pt-4">
                  <p className="font-medium">{tmpl.label}</p>
                  <p className="text-sm text-muted-foreground">
                    {tmpl.agent_type} / {tmpl.tool} / {tmpl.compute_type}
                  </p>
                  <div className="mt-3 flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        createFromTemplateMut.mutate({
                          templateId: tmpl.template_id,
                        })
                      }
                      disabled={createFromTemplateMut.isPending}
                    >
                      <Plus className="mr-1 h-3 w-3" />
                      Create
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => deleteTemplateMut.mutate(tmpl.template_id)}
                      disabled={deleteTemplateMut.isPending}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* ─── Worker Detail Drawer ────────────────────────────── */}
      <Sheet
        open={!!selectedWorkerId}
        onOpenChange={(open) => {
          if (!open) setSelectedWorkerId(null);
        }}
      >
        <SheetContent className="w-full sm:max-w-lg">
          {selectedWorker && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  {selectedWorker.label}
                  <Badge variant={statusVariant(selectedWorker.worker_status)}>
                    {selectedWorker.worker_status}
                  </Badge>
                </SheetTitle>
              </SheetHeader>
              <div className="mt-6 space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Agent Type</p>
                    <p className="font-medium">{selectedWorker.agent_type}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Tool</p>
                    <p className="font-medium">{selectedWorker.tool}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Agent State</p>
                    <p className="font-medium">{selectedWorker.agent_state}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Uptime</p>
                    <p className="font-medium">{formatUptime(selectedWorker.uptime_seconds)}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Tickets Completed</p>
                    <p className="font-medium">{selectedWorker.tickets_completed}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Est. Cost</p>
                    <p className="font-medium">
                      ${(selectedWorker.estimated_cost_cents / 100).toFixed(2)}
                    </p>
                  </div>
                </div>
                {selectedWorker.current_ticket_title && (
                  <div>
                    <p className="text-sm text-muted-foreground">Current Ticket</p>
                    <p className="font-medium">{selectedWorker.current_ticket_title}</p>
                  </div>
                )}
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      {/* ─── Create Template Dialog ──────────────────────────── */}
      <CreateTemplateDialog
        open={templateDialogOpen}
        onClose={() => setTemplateDialogOpen(false)}
      />
    </div>
  );
}

// ─── Create Template Dialog ─────────────────────────────────────

function CreateTemplateDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<WorkerTemplateIn>({
    label: "",
    agent_type: "coder",
    tool: "claude_code",
    compute_type: "ec2",
    instance_type: "t3.medium",
    llm_key_id: "",
    repo_url: "",
    branch_convention: "",
    idle_timeout_seconds: 7200,
  });

  const createMut = useMutation({
    mutationFn: (body: WorkerTemplateIn) => createTemplate(body),
    onSuccess: () => {
      toast.success("Template saved");
      queryClient.invalidateQueries({ queryKey: ["fleet", "templates"] });
      onClose();
    },
    onError: () => toast.error("Failed to save template"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Save Worker Template</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div>
            <Label>Label</Label>
            <Input
              value={form.label}
              onChange={(e) => setForm({ ...form, label: e.target.value })}
              placeholder="e.g., Backend Coder Standard"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Agent Type</Label>
              <Input
                value={form.agent_type}
                onChange={(e) => setForm({ ...form, agent_type: e.target.value })}
              />
            </div>
            <div>
              <Label>Tool</Label>
              <Input
                value={form.tool}
                onChange={(e) => setForm({ ...form, tool: e.target.value })}
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Compute Type</Label>
              <Input
                value={form.compute_type}
                onChange={(e) => setForm({ ...form, compute_type: e.target.value })}
              />
            </div>
            <div>
              <Label>Instance Type</Label>
              <Input
                value={form.instance_type}
                onChange={(e) => setForm({ ...form, instance_type: e.target.value })}
              />
            </div>
          </div>
          <div>
            <Label>LLM Key ID</Label>
            <Input
              value={form.llm_key_id}
              onChange={(e) => setForm({ ...form, llm_key_id: e.target.value })}
              placeholder="key_abc123"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate(form)}
            disabled={createMut.isPending || !form.label || !form.llm_key_id}
          >
            Save Template
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
