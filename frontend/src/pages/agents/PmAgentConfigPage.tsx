import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  getPmConfig,
  updatePmConfig,
  validatePmConfig,
  listIdeas,
  updateIdeaStatus,
  runPmOperation,
  listSprints,
  createSprint,
  updateSprint,
  listReports,
  getReport,
} from "@/api/endpoints/pmAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
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
import { ClipboardList, RefreshCw } from "lucide-react";
import type { PmConfigIn } from "@/api/types";

const DEFAULT_FRAMEWORK: Record<string, string> = {
  P0: "Critical/blocking",
  P1: "High/next sprint",
  P2: "Medium/backlog",
  P3: "Low/nice-to-have",
};
const DEFAULT_WEIGHTS: Record<string, number> = {
  user_impact: 0.4,
  revenue_impact: 0.3,
  technical_debt: 0.15,
  effort_inverse: 0.15,
};
const DEFAULT_CAPACITY: Record<string, number> = { coder: 80, qa: 40, devops: 20, architect: 20 };

function PmConfigTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useQuery({
    queryKey: ["pm-config", typeId],
    queryFn: () => getPmConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });

  const [weights, setWeights] = useState<Record<string, number>>(DEFAULT_WEIGHTS);
  const [capacity, setCapacity] = useState<Record<string, number>>(DEFAULT_CAPACITY);
  const [sprintDuration, setSprintDuration] = useState(14);
  const [cadence, setCadence] = useState<"daily" | "weekly" | "both">("both");
  const [reportTime, setReportTime] = useState("09:00");
  const [blockerStale, setBlockerStale] = useState(48);
  const [ideaIntake, setIdeaIntake] = useState(true);
  const [autoPrioritize, setAutoPrioritize] = useState(true);
  const [autoCreate, setAutoCreate] = useState(false);
  const [escalation, setEscalation] = useState(true);
  const [codingTool, setCodingTool] = useState<"claude_code" | "codex">("claude_code");
  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    if (!config) return;
    setWeights(config.priority_weights ?? DEFAULT_WEIGHTS);
    setCapacity(config.capacity_per_agent_type ?? DEFAULT_CAPACITY);
    setSprintDuration(config.sprint_duration_days ?? 14);
    setCadence(config.reporting_cadence ?? "both");
    setReportTime(config.report_time_utc ?? "09:00");
    setBlockerStale(config.blocker_stale_hours ?? 48);
    setIdeaIntake(config.idea_intake_enabled ?? true);
    setAutoPrioritize(config.auto_prioritize ?? true);
    setAutoCreate(config.auto_create_feature_requests ?? false);
    setEscalation(config.escalation_on_conflict ?? true);
    setCodingTool((config.coding_tool as "claude_code" | "codex") ?? "claude_code");
  }, [config]);

  const buildBody = (): PmConfigIn => ({
    priority_framework: DEFAULT_FRAMEWORK,
    priority_weights: weights,
    sprint_duration_days: sprintDuration,
    capacity_per_agent_type: capacity,
    reporting_cadence: cadence,
    report_time_utc: reportTime,
    idea_intake_enabled: ideaIntake,
    auto_prioritize: autoPrioritize,
    auto_create_feature_requests: autoCreate,
    blocker_stale_hours: blockerStale,
    escalation_on_conflict: escalation,
    coding_tool: codingTool,
  });

  const saveMut = useMutation({
    mutationFn: () => updatePmConfig(typeId, buildBody()),
    onSuccess: () => {
      setErrors([]);
      queryClient.invalidateQueries({ queryKey: ["pm-config", typeId] });
    },
  });
  const validateMut = useMutation({
    mutationFn: () => validatePmConfig(typeId, buildBody()),
    onSuccess: (res) => setErrors(res.errors),
  });

  const weightSum = Object.values(weights).reduce((a, b) => a + Number(b), 0);

  return (
    <div data-testid="pm-config-tab" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Priority Weights (must sum to 1.0)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Object.keys(weights).map((k) => (
            <div key={k} className="flex items-center gap-2">
              <Label className="w-40">{k}</Label>
              <Input
                type="number"
                step="0.05"
                value={weights[k]}
                onChange={(e) => setWeights({ ...weights, [k]: Number(e.target.value) })}
              />
            </div>
          ))}
          <p className={`text-sm ${Math.abs(weightSum - 1) > 0.01 ? "text-destructive" : "text-muted-foreground"}`}>
            Sum: {weightSum.toFixed(2)}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Capacity per Agent Type (hours / sprint)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Object.keys(capacity).map((k) => (
            <div key={k} className="flex items-center gap-2">
              <Label className="w-40">{k}</Label>
              <Input
                type="number"
                value={capacity[k]}
                onChange={(e) => setCapacity({ ...capacity, [k]: Number(e.target.value) })}
              />
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sprint & Reporting</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-4">
            <div>
              <Label>Sprint duration (days)</Label>
              <Input type="number" value={sprintDuration} onChange={(e) => setSprintDuration(Number(e.target.value))} />
            </div>
            <div>
              <Label>Blocker stale hours</Label>
              <Input type="number" value={blockerStale} onChange={(e) => setBlockerStale(Number(e.target.value))} />
            </div>
            <div>
              <Label>Report time (UTC)</Label>
              <Input value={reportTime} onChange={(e) => setReportTime(e.target.value)} />
            </div>
          </div>
          <div>
            <Label>Reporting cadence</Label>
            <Select value={cadence} onValueChange={(v) => setCadence(v as "daily" | "weekly" | "both")}>
              <SelectTrigger data-testid="pm-cadence">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">daily</SelectItem>
                <SelectItem value="weekly">weekly</SelectItem>
                <SelectItem value="both">both</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Coding tool (idea triage)</Label>
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
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Behavior Toggles</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <ToggleRow label="Idea intake enabled" checked={ideaIntake} onChange={setIdeaIntake} />
          <ToggleRow label="Auto-prioritize backlog" checked={autoPrioritize} onChange={setAutoPrioritize} />
          <ToggleRow label="Auto-create feature requests from ideas" checked={autoCreate} onChange={setAutoCreate} />
          <ToggleRow label="Escalate on priority conflict" checked={escalation} onChange={setEscalation} />
        </CardContent>
      </Card>

      {errors.length > 0 && (
        <div data-testid="pm-validation-errors" className="rounded border border-destructive p-3 text-sm">
          <p className="font-semibold">Validation errors:</p>
          <ul className="list-disc pl-5">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex gap-2">
        <Button variant="outline" onClick={() => validateMut.mutate()} disabled={validateMut.isPending}>
          Validate
        </Button>
        <Button data-testid="pm-save-btn" onClick={() => saveMut.mutate()} disabled={saveMut.isPending || isLoading}>
          Save
        </Button>
      </div>
    </div>
  );
}

function ToggleRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center gap-2">
      <Switch checked={checked} onCheckedChange={onChange} />
      <Label>{label}</Label>
    </div>
  );
}

function IdeasTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data, refetch, isFetching } = useQuery({
    queryKey: ["pm-ideas", typeId],
    queryFn: () => listIdeas({ limit: 100 }),
    staleTime: 10_000,
  });
  const ideas = data?.ideas ?? [];

  const triageMut = useMutation({
    mutationFn: () => runPmOperation(typeId, `triage_${Date.now()}`, "idea_triage"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["pm-ideas", typeId] }),
  });
  const statusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "accepted" | "rejected" }) =>
      updateIdeaStatus(id, status),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["pm-ideas", typeId] }),
  });

  return (
    <div data-testid="pm-ideas-tab" className="space-y-4">
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className="h-4 w-4 mr-1" /> Refresh
        </Button>
        <Button size="sm" data-testid="pm-triage-btn" onClick={() => triageMut.mutate()} disabled={triageMut.isPending}>
          Triage submitted ideas
        </Button>
      </div>
      {ideas.length === 0 ? (
        <p className="text-sm text-muted-foreground">No ideas submitted yet.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Title</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Impact</TableHead>
              <TableHead>Effort</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ideas.map((i) => (
              <TableRow key={i.idea_id} data-testid="pm-idea-row">
                <TableCell>{i.title}</TableCell>
                <TableCell>
                  <Badge variant="secondary">{i.status}</Badge>
                </TableCell>
                <TableCell>{i.priority_suggestion ?? "—"}</TableCell>
                <TableCell>{i.impact_score ?? "—"}</TableCell>
                <TableCell>{i.effort_score ?? "—"}</TableCell>
                <TableCell className="flex gap-1">
                  {i.status !== "converted" && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => statusMut.mutate({ id: i.idea_id, status: "accepted" })}>
                        Accept
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => statusMut.mutate({ id: i.idea_id, status: "rejected" })}>
                        Reject
                      </Button>
                    </>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

function SprintsTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["pm-sprints", typeId],
    queryFn: () => listSprints(typeId),
    staleTime: 10_000,
  });
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const sprints = data?.sprints ?? [];

  const createMut = useMutation({
    mutationFn: () => createSprint(typeId, { start_date: start, end_date: end }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["pm-sprints", typeId] }),
  });
  const updateMut = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "activate" | "close" }) =>
      updateSprint(id, action, typeId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["pm-sprints", typeId] }),
  });

  return (
    <div data-testid="pm-sprints-tab" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Create Sprint</CardTitle>
        </CardHeader>
        <CardContent className="flex items-end gap-2">
          <div>
            <Label>Start (YYYY-MM-DD)</Label>
            <Input data-testid="pm-sprint-start" value={start} onChange={(e) => setStart(e.target.value)} placeholder="2026-06-01" />
          </div>
          <div>
            <Label>End (YYYY-MM-DD)</Label>
            <Input data-testid="pm-sprint-end" value={end} onChange={(e) => setEnd(e.target.value)} placeholder="2026-06-15" />
          </div>
          <Button data-testid="pm-create-sprint" onClick={() => createMut.mutate()} disabled={createMut.isPending || !start || !end}>
            Create
          </Button>
        </CardContent>
      </Card>
      {sprints.length === 0 ? (
        <p className="text-sm text-muted-foreground">No sprints yet.</p>
      ) : (
        sprints.map((s) => (
          <Card key={s.sprint_id} data-testid="pm-sprint-card">
            <CardHeader>
              <CardTitle className="text-sm">
                Sprint #{s.sprint_number} <Badge variant="secondary">{s.status}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>{s.start_date} → {s.end_date}</p>
              <p>
                {s.completed_hours}/{s.planned_hours}h · {s.tickets_completed}/{s.tickets_planned} tickets · velocity {s.velocity}
              </p>
              <div className="flex gap-2">
                {s.status === "planned" && (
                  <Button size="sm" variant="outline" onClick={() => updateMut.mutate({ id: s.sprint_id, action: "activate" })}>
                    Activate
                  </Button>
                )}
                {s.status === "active" && (
                  <Button size="sm" variant="outline" onClick={() => updateMut.mutate({ id: s.sprint_id, action: "close" })}>
                    Close
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

function ReportsTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ["pm-reports", typeId],
    queryFn: () => listReports(typeId),
    staleTime: 10_000,
  });
  const [openId, setOpenId] = useState<string | null>(null);
  const { data: report } = useQuery({
    queryKey: ["pm-report", openId, typeId],
    queryFn: () => (openId ? getReport(openId, typeId) : Promise.resolve(undefined)),
    enabled: !!openId,
  });
  const reports = data?.reports ?? [];

  const genMut = useMutation({
    mutationFn: () => runPmOperation(typeId, `report_${Date.now()}`, "report_generate", "daily"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["pm-reports", typeId] }),
  });

  return (
    <div data-testid="pm-reports-tab" className="space-y-4">
      <Button size="sm" data-testid="pm-generate-report" onClick={() => genMut.mutate()} disabled={genMut.isPending}>
        Generate daily report
      </Button>
      {reports.length === 0 ? (
        <p className="text-sm text-muted-foreground">No reports generated yet.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Type</TableHead>
              <TableHead>Created</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports.map((r) => (
              <TableRow key={r.report_id} data-testid="pm-report-row">
                <TableCell>
                  <Badge variant="secondary">{r.report_type}</Badge>
                </TableCell>
                <TableCell>{new Date(r.created_at * 1000).toLocaleString()}</TableCell>
                <TableCell>
                  <Button size="sm" variant="ghost" onClick={() => setOpenId(r.report_id)}>
                    View
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {report && (
        <Card data-testid="pm-report-detail">
          <CardHeader>
            <CardTitle className="text-sm">{report.report_type} report</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap text-sm">{report.content}</pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function PmAgentConfigPage() {
  const { typeId = "" } = useParams();
  return (
    <div data-testid="pm-config-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <ClipboardList className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Project Manager Agent</h1>
      </div>
      <Tabs defaultValue="config">
        <TabsList>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="ideas">Ideas</TabsTrigger>
          <TabsTrigger value="sprints">Sprints</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>
        <TabsContent value="config">
          <PmConfigTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="ideas">
          <IdeasTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="sprints">
          <SprintsTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="reports">
          <ReportsTab typeId={typeId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
