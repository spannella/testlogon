import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  getDevOpsConfig,
  updateDevOpsConfig,
  validateDevOpsConfig,
  getDevOpsMetrics,
  listDeployments,
} from "@/api/endpoints/devopsAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
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
import { Server, RefreshCw, Trash2, Plus } from "lucide-react";
import type { DevOpsConfigIn, EnvironmentConfig } from "@/api/types";

const EMPTY_ENV: EnvironmentConfig = {
  name: "",
  requires_approval: false,
  deploy_commands: [],
  rollback_commands: [],
  health_check_urls: [],
  health_check_timeout_seconds: 120,
  smoke_test_command: "",
  rollback_window_seconds: 300,
};

function statusBadgeVariant(status: string): "default" | "destructive" | "secondary" | "outline" {
  if (status === "success" || status === "deployed") return "default";
  if (status === "failed" || status === "rolled_back" || status === "rejected") return "destructive";
  return "secondary";
}

function ConfigTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["devops-config", typeId],
    queryFn: () => getDevOpsConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });
  const config = data?.devops_config;

  const [deployLabels, setDeployLabels] = useState("type:deployment");
  const [infraLabels, setInfraLabels] = useState("type:infrastructure");
  const [incidentLabels, setIncidentLabels] = useState("type:incident");
  const [autoDeploy, setAutoDeploy] = useState(false);
  const [codingTool, setCodingTool] = useState<"claude_code" | "codex">("claude_code");
  const [maxOpTime, setMaxOpTime] = useState(1800);
  const [incidentSpaceId, setIncidentSpaceId] = useState("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  useEffect(() => {
    if (!config) return;
    setDeployLabels((config.deploy_ticket_labels ?? ["type:deployment"]).join(", "));
    setInfraLabels((config.infra_ticket_labels ?? ["type:infrastructure"]).join(", "));
    setIncidentLabels((config.incident_ticket_labels ?? ["type:incident"]).join(", "));
    setAutoDeploy(config.auto_deploy_on_qa_approved ?? false);
    setCodingTool((config.coding_tool as "claude_code" | "codex") ?? "claude_code");
    setMaxOpTime(config.max_operation_time_seconds ?? 1800);
    setIncidentSpaceId(config.incident_space_id ?? "");
  }, [config]);

  const csv = (s: string) =>
    s.split(",").map((x) => x.trim()).filter(Boolean);

  const buildBody = (): DevOpsConfigIn => ({
    environments: config?.environments ?? [{ ...EMPTY_ENV, name: "staging", deploy_commands: ["echo deploy"] }],
    deploy_ticket_labels: csv(deployLabels),
    infra_ticket_labels: csv(infraLabels),
    incident_ticket_labels: csv(incidentLabels),
    auto_deploy_on_qa_approved: autoDeploy,
    coding_tool: codingTool,
    max_operation_time_seconds: maxOpTime,
    incident_space_id: incidentSpaceId || null,
  });

  const saveMut = useMutation({
    mutationFn: () => updateDevOpsConfig(typeId, buildBody()),
    onSuccess: () => {
      setValidationErrors([]);
      queryClient.invalidateQueries({ queryKey: ["devops-config", typeId] });
    },
  });

  const validateMut = useMutation({
    mutationFn: () => validateDevOpsConfig(typeId, buildBody()),
    onSuccess: (res) => setValidationErrors(res.errors),
  });

  return (
    <div data-testid="devops-config-tab" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Ticket Labels</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Deployment labels (comma-separated)</Label>
            <Input data-testid="devops-deploy-labels" value={deployLabels} onChange={(e) => setDeployLabels(e.target.value)} />
          </div>
          <div>
            <Label>Infrastructure labels</Label>
            <Input value={infraLabels} onChange={(e) => setInfraLabels(e.target.value)} />
          </div>
          <div>
            <Label>Incident labels</Label>
            <Input value={incidentLabels} onChange={(e) => setIncidentLabels(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Automation Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <Label>Auto-deploy on QA approved</Label>
            <Switch data-testid="devops-auto-deploy" checked={autoDeploy} onCheckedChange={setAutoDeploy} />
          </div>
          <div>
            <Label>Coding tool</Label>
            <Select value={codingTool} onValueChange={(v) => setCodingTool(v as "claude_code" | "codex")}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="claude_code">claude_code</SelectItem>
                <SelectItem value="codex">codex</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Max operation time (s)</Label>
            <Input type="number" value={maxOpTime} onChange={(e) => setMaxOpTime(Number(e.target.value))} />
          </div>
          <div>
            <Label>Incident space id (optional)</Label>
            <Input value={incidentSpaceId} onChange={(e) => setIncidentSpaceId(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      {validationErrors.length > 0 && (
        <div data-testid="devops-validation-errors" className="rounded border border-destructive p-3 text-sm">
          <p className="font-semibold">Validation errors:</p>
          <ul className="list-disc pl-5">
            {validationErrors.map((err) => (
              <li key={err}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex gap-2">
        <Button variant="outline" onClick={() => validateMut.mutate()} disabled={validateMut.isPending}>
          Validate
        </Button>
        <Button data-testid="devops-save-btn" onClick={() => saveMut.mutate()} disabled={saveMut.isPending || isLoading}>
          Save
        </Button>
      </div>
    </div>
  );
}

function EnvironmentsTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["devops-config", typeId],
    queryFn: () => getDevOpsConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });
  const [envs, setEnvs] = useState<EnvironmentConfig[]>([]);

  useEffect(() => {
    if (data?.devops_config?.environments) setEnvs(data.devops_config.environments);
  }, [data]);

  const cfg = data?.devops_config;

  const saveMut = useMutation({
    mutationFn: () =>
      updateDevOpsConfig(typeId, {
        environments: envs,
        deploy_ticket_labels: cfg?.deploy_ticket_labels,
        infra_ticket_labels: cfg?.infra_ticket_labels,
        incident_ticket_labels: cfg?.incident_ticket_labels,
        auto_deploy_on_qa_approved: cfg?.auto_deploy_on_qa_approved,
        coding_tool: cfg?.coding_tool,
        max_operation_time_seconds: cfg?.max_operation_time_seconds,
        incident_space_id: cfg?.incident_space_id ?? null,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["devops-config", typeId] }),
  });

  const patchEnv = (i: number, patch: Partial<EnvironmentConfig>) =>
    setEnvs((prev) => prev.map((e, idx) => (idx === i ? { ...e, ...patch } : e)));

  return (
    <div data-testid="devops-environments-tab" className="space-y-4">
      <Button
        size="sm"
        onClick={() => setEnvs((prev) => [...prev, { ...EMPTY_ENV, name: `env-${prev.length + 1}`, deploy_commands: ["echo deploy"] }])}
      >
        <Plus className="h-4 w-4 mr-1" /> Add Environment
      </Button>
      {envs.length === 0 ? (
        <p className="text-sm text-muted-foreground">No environments configured.</p>
      ) : (
        envs.map((env, i) => (
          <Card key={i} data-testid={`devops-env-${i}`}>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-base">{env.name || "(unnamed)"}</CardTitle>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setEnvs((prev) => prev.filter((_, idx) => idx !== i))}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <Label>Name</Label>
                <Input value={env.name} onChange={(e) => patchEnv(i, { name: e.target.value })} />
              </div>
              <div className="flex items-center justify-between">
                <Label>Requires approval</Label>
                <Switch
                  checked={env.requires_approval}
                  onCheckedChange={(v) => patchEnv(i, { requires_approval: v })}
                />
              </div>
              <div>
                <Label>Deploy commands (one per line)</Label>
                <Textarea
                  rows={3}
                  value={env.deploy_commands.join("\n")}
                  onChange={(e) =>
                    patchEnv(i, { deploy_commands: e.target.value.split("\n").map((c) => c.trim()).filter(Boolean) })
                  }
                />
              </div>
              <div>
                <Label>Rollback commands (one per line)</Label>
                <Textarea
                  rows={2}
                  value={env.rollback_commands.join("\n")}
                  onChange={(e) =>
                    patchEnv(i, { rollback_commands: e.target.value.split("\n").map((c) => c.trim()).filter(Boolean) })
                  }
                />
              </div>
              <div>
                <Label>Health check URLs (one per line)</Label>
                <Textarea
                  rows={2}
                  value={env.health_check_urls.join("\n")}
                  onChange={(e) =>
                    patchEnv(i, { health_check_urls: e.target.value.split("\n").map((c) => c.trim()).filter(Boolean) })
                  }
                />
              </div>
              <div className="flex gap-4">
                <div>
                  <Label>Health timeout (s)</Label>
                  <Input
                    type="number"
                    value={env.health_check_timeout_seconds}
                    onChange={(e) => patchEnv(i, { health_check_timeout_seconds: Number(e.target.value) })}
                  />
                </div>
                <div>
                  <Label>Rollback window (s)</Label>
                  <Input
                    type="number"
                    value={env.rollback_window_seconds}
                    onChange={(e) => patchEnv(i, { rollback_window_seconds: Number(e.target.value) })}
                  />
                </div>
              </div>
              <div>
                <Label>Smoke test command (optional)</Label>
                <Input
                  value={env.smoke_test_command ?? ""}
                  onChange={(e) => patchEnv(i, { smoke_test_command: e.target.value })}
                />
              </div>
            </CardContent>
          </Card>
        ))
      )}
      <Button data-testid="devops-env-save-btn" onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
        Save Environments
      </Button>
    </div>
  );
}

function RunbooksTab({ typeId }: { typeId: string }) {
  const { data } = useQuery({
    queryKey: ["devops-config", typeId],
    queryFn: () => getDevOpsConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });
  const runbooks = data?.devops_config?.runbooks ?? [];
  return (
    <div data-testid="devops-runbooks-tab" className="space-y-3">
      {runbooks.length === 0 ? (
        <p className="text-sm text-muted-foreground">No runbooks configured.</p>
      ) : (
        runbooks.map((rb, i) => (
          <Card key={i}>
            <CardHeader>
              <CardTitle className="text-base">{rb.name}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>
                Trigger: <Badge variant="secondary">{rb.trigger_label}</Badge>
              </p>
              <pre className="rounded bg-muted p-2 text-xs">{rb.steps.join("\n")}</pre>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

function DeploymentsTab() {
  const { data, refetch, isFetching } = useQuery({
    queryKey: ["devops-deployments"],
    queryFn: () => listDeployments(50),
    staleTime: 30_000,
  });
  const rows = data?.deployments ?? [];
  return (
    <div data-testid="devops-deployments-tab" className="space-y-3">
      <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
        <RefreshCw className="h-4 w-4 mr-1" /> Refresh
      </Button>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No deployments yet.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Ticket</TableHead>
              <TableHead>Environment</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Duration</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.deployment_id || r.run_id}>
                <TableCell>{r.ticket_id || "-"}</TableCell>
                <TableCell>{r.environment}</TableCell>
                <TableCell>
                  <Badge variant={statusBadgeVariant(r.status)}>{r.status}</Badge>
                </TableCell>
                <TableCell>{r.version_deployed ?? "-"}</TableCell>
                <TableCell>{r.total_duration_seconds}s</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

function MetricsTab({ typeId }: { typeId: string }) {
  const [period, setPeriod] = useState(30);
  const { data } = useQuery({
    queryKey: ["devops-metrics", typeId, period],
    queryFn: () => getDevOpsMetrics(typeId, period),
    staleTime: 300_000,
  });
  return (
    <div data-testid="devops-metrics-tab" className="space-y-4">
      <div>
        <Label>Period</Label>
        <Select value={String(period)} onValueChange={(v) => setPeriod(Number(v))}>
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="7">7d</SelectItem>
            <SelectItem value="30">30d</SelectItem>
            <SelectItem value="90">90d</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Deploy Frequency</CardTitle>
          </CardHeader>
          <CardContent data-testid="metric-deploy-frequency" className="text-2xl font-bold">
            {data?.deployment_frequency ?? 0}/day
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Success Rate</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {((data?.success_rate ?? 0) * 100).toFixed(1)}%
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">MTTR</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{Math.round(data?.mttr_seconds ?? 0)}s</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Incidents</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{data?.incidents_count ?? 0}</CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Rollback Rate</CardTitle>
        </CardHeader>
        <CardContent>
          <Progress value={(data?.rollback_rate ?? 0) * 100} />
          <p className="mt-1 text-sm text-muted-foreground">{((data?.rollback_rate ?? 0) * 100).toFixed(1)}%</p>
        </CardContent>
      </Card>
    </div>
  );
}

export default function DevOpsAgentConfigPage() {
  const { typeId = "" } = useParams();
  return (
    <div data-testid="devops-config-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <Server className="h-6 w-6" />
        <h1 className="text-2xl font-bold">DevOps Agent Configuration</h1>
      </div>
      <Tabs defaultValue="config">
        <TabsList>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="environments">Environments</TabsTrigger>
          <TabsTrigger value="runbooks">Runbooks</TabsTrigger>
          <TabsTrigger value="deployments">Deployments</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
        </TabsList>
        <TabsContent value="config">
          <ConfigTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="environments">
          <EnvironmentsTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="runbooks">
          <RunbooksTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="deployments">
          <DeploymentsTab />
        </TabsContent>
        <TabsContent value="metrics">
          <MetricsTab typeId={typeId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
