import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bot, Plus, Square, Play, Trash2, TerminalSquare } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import {
  listWorkers,
  getTools,
  getComputeOptions,
  createWorker,
  stopWorker,
  startWorker,
  terminateWorker,
} from "@/api/endpoints/agentWorkers";
import type {
  Worker,
  ToolInfo,
  ComputeOption,
  CreateWorkerIn,
} from "@/api/types";

// ─── Status badge colors ────────────────────────────────────────

function statusColor(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "ready":
    case "running":
      return "default";
    case "provisioning":
    case "installing":
      return "secondary";
    case "stopped":
      return "outline";
    case "error":
      return "destructive";
    case "terminated":
      return "outline";
    default:
      return "secondary";
  }
}

// ─── Worker Create Wizard ───────────────────────────────────────

const AGENT_TYPES = [
  { value: "coder", label: "Coder", desc: "Writes and refactors code" },
  { value: "qa", label: "QA", desc: "Runs tests and finds bugs" },
  { value: "reviewer", label: "Reviewer", desc: "Reviews pull requests" },
  { value: "devops", label: "DevOps", desc: "Infrastructure and deployment" },
  { value: "custom", label: "Custom", desc: "Custom agent type" },
] as const;

function WorkerCreateWizard({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const [step, setStep] = useState(1);
  const [agentType, setAgentType] = useState<string>("");
  const [tool, setTool] = useState<string>("");
  const [computeType, setComputeType] = useState<string>("");
  const [instanceType, setInstanceType] = useState<string>("");
  const [llmKeyId, setLlmKeyId] = useState<string>("");
  const [label, setLabel] = useState<string>("");
  const [repoUrl, setRepoUrl] = useState<string>("");
  const [idleTimeout, setIdleTimeout] = useState<number>(7200);

  const { data: toolsData } = useQuery({
    queryKey: ["agent-workers", "tools"],
    queryFn: getTools,
    staleTime: 24 * 60 * 60 * 1000,
  });

  const { data: computeData } = useQuery({
    queryKey: ["agent-workers", "compute-options"],
    queryFn: getComputeOptions,
    staleTime: 60 * 60 * 1000,
  });

  const createMut = useMutation({
    mutationFn: (body: CreateWorkerIn) => createWorker(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-workers"] });
      onOpenChange(false);
      resetForm();
    },
  });

  function resetForm() {
    setStep(1);
    setAgentType("");
    setTool("");
    setComputeType("");
    setInstanceType("");
    setLlmKeyId("");
    setLabel("");
    setRepoUrl("");
    setIdleTimeout(7200);
  }

  function handleCreate() {
    createMut.mutate({
      label,
      agent_type: agentType as CreateWorkerIn["agent_type"],
      tool: tool as CreateWorkerIn["tool"],
      compute_type: computeType as CreateWorkerIn["compute_type"],
      instance_type: instanceType,
      llm_key_id: llmKeyId,
      repo_url: repoUrl,
      idle_timeout_seconds: idleTimeout,
    });
  }

  const tools: ToolInfo[] = toolsData?.tools ?? [];
  const options: ComputeOption[] = computeData?.options ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Agent Worker</DialogTitle>
        </DialogHeader>
        <div className="text-xs text-muted-foreground mb-2">
          Step {step} of 5
        </div>

        {/* Step 1: Agent Type */}
        {step === 1 && (
          <div className="grid grid-cols-2 gap-3">
            {AGENT_TYPES.map((t) => (
              <Card
                key={t.value}
                className={`cursor-pointer transition-colors ${
                  agentType === t.value
                    ? "border-primary bg-primary/5"
                    : "hover:border-muted-foreground/30"
                }`}
                onClick={() => setAgentType(t.value)}
              >
                <CardContent className="p-3">
                  <div className="font-medium text-sm">{t.label}</div>
                  <div className="text-xs text-muted-foreground">{t.desc}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Step 2: Tool */}
        {step === 2 && (
          <div className="space-y-2">
            {tools.map((t) => (
              <Card
                key={t.tool}
                className={`cursor-pointer transition-colors ${
                  tool === t.tool
                    ? "border-primary bg-primary/5"
                    : "hover:border-muted-foreground/30"
                }`}
                onClick={() => setTool(t.tool)}
              >
                <CardContent className="p-3 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-sm">{t.display_name}</div>
                    <div className="text-xs text-muted-foreground">
                      {t.description}
                    </div>
                  </div>
                  {t.required_provider && (
                    <Badge variant="outline" className="text-xs">
                      {t.required_provider}
                    </Badge>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Step 3: Compute */}
        {step === 3 && (
          <div className="space-y-2">
            {options.map((o) => (
              <Card
                key={`${o.compute_type}-${o.instance_type}`}
                className={`cursor-pointer transition-colors ${
                  computeType === o.compute_type &&
                  instanceType === o.instance_type
                    ? "border-primary bg-primary/5"
                    : "hover:border-muted-foreground/30"
                }`}
                onClick={() => {
                  setComputeType(o.compute_type);
                  setInstanceType(o.instance_type);
                }}
              >
                <CardContent className="p-3 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-sm">
                      {o.instance_type}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {o.vcpu} vCPU, {o.memory_gb} GB RAM, ~{o.startup_seconds}s
                      startup
                    </div>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    {o.compute_type.toUpperCase()}
                  </Badge>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Step 4: LLM Key */}
        {step === 4 && (
          <div className="space-y-3">
            <Label>LLM API Key ID</Label>
            <Input
              placeholder="Enter your LLM key ID"
              value={llmKeyId}
              onChange={(e) => setLlmKeyId(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Enter the key ID from your LLM Provider Keys page.
            </p>
          </div>
        )}

        {/* Step 5: Config */}
        {step === 5 && (
          <div className="space-y-3">
            <div>
              <Label>Label</Label>
              <Input
                placeholder="My Coder Agent"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </div>
            <div>
              <Label>Repository URL (optional)</Label>
              <Input
                placeholder="https://github.com/org/repo.git"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
              />
            </div>
            <div>
              <Label>Idle Timeout (seconds)</Label>
              <Input
                type="number"
                min={600}
                max={86400}
                value={idleTimeout}
                onChange={(e) => setIdleTimeout(Number(e.target.value))}
              />
            </div>
          </div>
        )}

        <DialogFooter className="flex justify-between">
          <div>
            {step > 1 && (
              <Button variant="outline" onClick={() => setStep(step - 1)}>
                Back
              </Button>
            )}
          </div>
          <div>
            {step < 5 ? (
              <Button
                onClick={() => setStep(step + 1)}
                disabled={
                  (step === 1 && !agentType) ||
                  (step === 2 && !tool) ||
                  (step === 3 && (!computeType || !instanceType)) ||
                  (step === 4 && !llmKeyId)
                }
              >
                Next
              </Button>
            ) : (
              <Button
                onClick={handleCreate}
                disabled={!label || createMut.isPending}
              >
                {createMut.isPending ? "Creating..." : "Create Worker"}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Workers Page ───────────────────────────────────────────────

export default function WorkersPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [wizardOpen, setWizardOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: [
      "agent-workers",
      "list",
      statusFilter === "all" ? undefined : statusFilter,
      typeFilter === "all" ? undefined : typeFilter,
    ],
    queryFn: () =>
      listWorkers({
        status: statusFilter === "all" ? undefined : statusFilter,
        agent_type: typeFilter === "all" ? undefined : typeFilter,
      }),
    staleTime: 30_000,
    refetchInterval: 10_000,
  });

  const stopMut = useMutation({
    mutationFn: (id: string) => stopWorker(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agent-workers"] }),
  });

  const startMut = useMutation({
    mutationFn: (id: string) => startWorker(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agent-workers"] }),
  });

  const terminateMut = useMutation({
    mutationFn: (id: string) => terminateWorker(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agent-workers"] }),
  });

  const workers: Worker[] = data?.workers ?? [];

  return (
    <div className="container mx-auto py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="h-7 w-7 text-primary" />
          <h1 className="text-2xl font-bold">Agent Workers</h1>
        </div>
        <Button onClick={() => setWizardOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Worker
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="provisioning">Provisioning</SelectItem>
            <SelectItem value="ready">Ready</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="stopped">Stopped</SelectItem>
            <SelectItem value="error">Error</SelectItem>
            <SelectItem value="terminated">Terminated</SelectItem>
          </SelectContent>
        </Select>

        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Agent type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="coder">Coder</SelectItem>
            <SelectItem value="qa">QA</SelectItem>
            <SelectItem value="reviewer">Reviewer</SelectItem>
            <SelectItem value="devops">DevOps</SelectItem>
            <SelectItem value="custom">Custom</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Worker list */}
      {isLoading ? (
        <div className="text-center text-muted-foreground py-12">
          Loading workers...
        </div>
      ) : workers.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Bot className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No workers yet</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Create your first agent worker to get started.
            </p>
            <Button onClick={() => setWizardOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Create Worker
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {workers.map((w) => (
            <Card key={w.worker_id}>
              <CardContent className="flex items-center justify-between p-4">
                <div className="flex items-center gap-4">
                  <Bot className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <div className="font-medium">{w.label}</div>
                    <div className="text-xs text-muted-foreground">
                      {w.agent_type} &middot; {w.tool} &middot;{" "}
                      {w.compute_type}/{w.instance_type}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Badge variant={statusColor(w.worker_status)}>
                    {w.worker_status}
                  </Badge>
                  {(w.worker_status === "ready" ||
                    w.worker_status === "running") && (
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() =>
                        navigate(`/agents/session?workerId=${encodeURIComponent(w.worker_id)}`)
                      }
                    >
                      <TerminalSquare className="h-3 w-3 mr-1" />
                      Open Session
                    </Button>
                  )}
                  {(w.worker_status === "ready" ||
                    w.worker_status === "running") && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => stopMut.mutate(w.worker_id)}
                      disabled={stopMut.isPending}
                    >
                      <Square className="h-3 w-3 mr-1" />
                      Stop
                    </Button>
                  )}
                  {w.worker_status === "stopped" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => startMut.mutate(w.worker_id)}
                      disabled={startMut.isPending}
                    >
                      <Play className="h-3 w-3 mr-1" />
                      Start
                    </Button>
                  )}
                  {w.worker_status !== "terminated" && (
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => terminateMut.mutate(w.worker_id)}
                      disabled={terminateMut.isPending}
                    >
                      <Trash2 className="h-3 w-3 mr-1" />
                      Terminate
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <WorkerCreateWizard open={wizardOpen} onOpenChange={setWizardOpen} />
    </div>
  );
}
