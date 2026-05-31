import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  getCoderConfig,
  updateCoderConfig,
  validateCoderConfig,
  getEligibleTickets,
  getCoderMetrics,
} from "@/api/endpoints/coderAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
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
import { Code2, RefreshCw } from "lucide-react";
import type { CoderConfigIn } from "@/api/types";

function CoderConfigTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useQuery({
    queryKey: ["coder-config", typeId],
    queryFn: () => getCoderConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });

  const [repoUrl, setRepoUrl] = useState("");
  const [branchBase, setBranchBase] = useState("main");
  const [branchPattern, setBranchPattern] = useState("feat/{ticket_id}-{slug}");
  const [testCommands, setTestCommands] = useState("just test\njust e2e");
  const [testTimeout, setTestTimeout] = useState(600);
  const [retryLimit, setRetryLimit] = useState(3);
  const [prTemplate, setPrTemplate] = useState("Closes #{ticket_id}\n\n{summary}");
  const [skillLevel, setSkillLevel] = useState<"junior" | "mid" | "senior">("mid");
  const [timeBudget, setTimeBudget] = useState(3600);
  const [codingTool, setCodingTool] = useState<"claude_code" | "codex">("claude_code");
  const [model, setModel] = useState("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  useEffect(() => {
    if (!config) return;
    setRepoUrl(config.repo_url ?? "");
    setBranchBase(config.repo_branch_base ?? "main");
    setBranchPattern(config.branch_pattern ?? "feat/{ticket_id}-{slug}");
    setTestCommands((config.test_commands ?? []).join("\n"));
    setTestTimeout(config.test_timeout_seconds ?? 600);
    setRetryLimit(config.test_retry_limit ?? 3);
    setPrTemplate(config.pr_template ?? "Closes #{ticket_id}\n\n{summary}");
    setSkillLevel((config.skill_level as "junior" | "mid" | "senior") ?? "mid");
    setTimeBudget(config.max_ticket_time_seconds ?? 3600);
    setCodingTool((config.coding_tool as "claude_code" | "codex") ?? "claude_code");
    setModel(config.coding_tool_model ?? "");
  }, [config]);

  const buildBody = (): CoderConfigIn => ({
    repo_url: repoUrl,
    repo_branch_base: branchBase,
    branch_pattern: branchPattern,
    test_commands: testCommands
      .split("\n")
      .map((c) => c.trim())
      .filter(Boolean),
    test_timeout_seconds: testTimeout,
    test_retry_limit: retryLimit,
    pr_template: prTemplate,
    skill_level: skillLevel,
    max_ticket_time_seconds: timeBudget,
    coding_tool: codingTool,
    coding_tool_model: model || null,
  });

  const saveMut = useMutation({
    mutationFn: () => updateCoderConfig(typeId, buildBody()),
    onSuccess: () => {
      setValidationErrors([]);
      queryClient.invalidateQueries({ queryKey: ["coder-config", typeId] });
    },
  });

  const validateMut = useMutation({
    mutationFn: () => validateCoderConfig(typeId, buildBody()),
    onSuccess: (res) => setValidationErrors(res.errors),
  });

  const branchPreview = branchPattern
    .replace("{ticket_id}", "tkt_abc123")
    .replace("{slug}", "add-user-search");

  return (
    <div data-testid="coder-config-tab" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Repository</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Repository URL</Label>
            <Input
              data-testid="coder-repo-url"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/org/repo.git"
            />
          </div>
          <div>
            <Label>Base branch</Label>
            <Input value={branchBase} onChange={(e) => setBranchBase(e.target.value)} />
          </div>
          <div>
            <Label>Branch pattern</Label>
            <Input value={branchPattern} onChange={(e) => setBranchPattern(e.target.value)} />
            <p className="text-xs text-muted-foreground mt-1">Preview: {branchPreview}</p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Test Suite</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Test commands (one per line)</Label>
            <Textarea
              value={testCommands}
              onChange={(e) => setTestCommands(e.target.value)}
              rows={3}
            />
          </div>
          <div className="flex gap-4">
            <div>
              <Label>Timeout (s)</Label>
              <Input
                type="number"
                value={testTimeout}
                onChange={(e) => setTestTimeout(Number(e.target.value))}
              />
            </div>
            <div>
              <Label>Retry limit</Label>
              <Input
                type="number"
                value={retryLimit}
                onChange={(e) => setRetryLimit(Number(e.target.value))}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>PR Template</CardTitle>
        </CardHeader>
        <CardContent>
          <Textarea value={prTemplate} onChange={(e) => setPrTemplate(e.target.value)} rows={4} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Agent Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Skill level</Label>
            <Select value={skillLevel} onValueChange={(v) => setSkillLevel(v as "junior" | "mid" | "senior")}>
              <SelectTrigger data-testid="coder-skill-level">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="junior">junior</SelectItem>
                <SelectItem value="mid">mid</SelectItem>
                <SelectItem value="senior">senior</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Time budget (s)</Label>
            <Input
              type="number"
              value={timeBudget}
              onChange={(e) => setTimeBudget(Number(e.target.value))}
            />
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
            <Label>Model override (optional)</Label>
            <Input value={model} onChange={(e) => setModel(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      {validationErrors.length > 0 && (
        <div data-testid="coder-validation-errors" className="rounded border border-destructive p-3 text-sm">
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
        <Button data-testid="coder-save-btn" onClick={() => saveMut.mutate()} disabled={saveMut.isPending || isLoading}>
          Save
        </Button>
      </div>
    </div>
  );
}

function EligibleTicketsTab({ typeId }: { typeId: string }) {
  const { data, refetch, isFetching } = useQuery({
    queryKey: ["coder-eligible", typeId],
    queryFn: () => getEligibleTickets(typeId),
    staleTime: 10_000,
  });
  const tickets = data?.tickets ?? [];
  return (
    <div data-testid="eligible-tickets-tab" className="space-y-3">
      <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
        <RefreshCw className="h-4 w-4 mr-1" /> Refresh
      </Button>
      {tickets.length === 0 ? (
        <p className="text-sm text-muted-foreground">No eligible tickets.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Ticket ID</TableHead>
              <TableHead>Subject</TableHead>
              <TableHead>Labels</TableHead>
              <TableHead>Complexity</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tickets.map((t) => (
              <TableRow key={t.ticket_id}>
                <TableCell>{t.ticket_id}</TableCell>
                <TableCell>{t.subject}</TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {t.labels.map((l) => (
                      <Badge key={l} variant="secondary">
                        {l}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell>{t.complexity ?? "-"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

function CoderMetricsTab({ typeId }: { typeId: string }) {
  const { data } = useQuery({
    queryKey: ["coder-metrics", typeId],
    queryFn: () => getCoderMetrics(typeId, 30),
    staleTime: 300_000,
  });
  const skillEntries = Object.entries(data?.tickets_by_skill_level ?? {});
  return (
    <div data-testid="coder-metrics-tab" className="space-y-4">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Completed</CardTitle>
          </CardHeader>
          <CardContent data-testid="metric-completed" className="text-2xl font-bold">
            {data?.completed_count ?? 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Avg Duration (s)</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{data?.avg_duration_seconds ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Failure Rate</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {((data?.failure_rate ?? 0) * 100).toFixed(1)}%
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Escalation Rate</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {((data?.escalation_rate ?? 0) * 100).toFixed(1)}%
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Tickets by skill level</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {skillEntries.length === 0 ? (
            <p className="text-sm text-muted-foreground">No data yet.</p>
          ) : (
            skillEntries.map(([skill, count]) => (
              <div key={skill} className="flex items-center gap-2">
                <span className="w-20 text-sm">{skill}</span>
                <div className="h-4 bg-primary rounded" style={{ width: `${count * 24}px` }} />
                <span className="text-sm">{count}</span>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function CoderAgentConfigPage() {
  const { typeId = "" } = useParams();
  return (
    <div data-testid="coder-config-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <Code2 className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Coder Agent Configuration</h1>
      </div>
      <Tabs defaultValue="config">
        <TabsList>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="eligible">Eligible Tickets</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
        </TabsList>
        <TabsContent value="config">
          <CoderConfigTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="eligible">
          <EligibleTicketsTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="metrics">
          <CoderMetricsTab typeId={typeId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
