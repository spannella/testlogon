import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  getQaConfig,
  updateQaConfig,
  validateQaConfig,
  getQaEligibleTickets,
  getQaMetrics,
} from "@/api/endpoints/qaAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
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
import { TestTube2, RefreshCw } from "lucide-react";
import type { QaConfigIn } from "@/api/types";

type Framework = "playwright" | "cypress" | "pytest";
type Browser = "chromium" | "firefox" | "webkit";
type Scope = "full" | "affected" | "none";
type Tool = "claude_code" | "codex";

function QaConfigTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useQuery({
    queryKey: ["qa-config", typeId],
    queryFn: () => getQaConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });

  const [framework, setFramework] = useState<Framework>("playwright");
  const [browser, setBrowser] = useState<Browser>("chromium");
  const [testDir, setTestDir] = useState("frontend/e2e/");
  const [filePattern, setFilePattern] = useState("{feature}.spec.ts");
  const [runCommand, setRunCommand] = useState("cd frontend && npx playwright test");
  const [runSpecific, setRunSpecific] = useState("cd frontend && npx playwright test e2e/{file}");
  const [scope, setScope] = useState<Scope>("affected");
  const [regressionCommand, setRegressionCommand] = useState("just e2e");
  const [screenshotEnabled, setScreenshotEnabled] = useState(true);
  const [screenshotOnFailure, setScreenshotOnFailure] = useState(false);
  const [screenshotPrefix, setScreenshotPrefix] = useState("qa-screenshots/");
  const [visualThreshold, setVisualThreshold] = useState(0.01);
  const [maxTime, setMaxTime] = useState(1800);
  const [flakyRetries, setFlakyRetries] = useState(2);
  const [prReview, setPrReview] = useState(true);
  const [codingTool, setCodingTool] = useState<Tool>("claude_code");
  const [model, setModel] = useState("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  useEffect(() => {
    if (!config) return;
    setFramework((config.test_framework as Framework) ?? "playwright");
    setBrowser((config.browser as Browser) ?? "chromium");
    setTestDir(config.test_dir ?? "frontend/e2e/");
    setFilePattern(config.test_file_pattern ?? "{feature}.spec.ts");
    setRunCommand(config.test_run_command ?? "cd frontend && npx playwright test");
    setRunSpecific(config.test_run_specific_command ?? "cd frontend && npx playwright test e2e/{file}");
    setScope((config.regression_scope as Scope) ?? "affected");
    setRegressionCommand(config.regression_command ?? "just e2e");
    setScreenshotEnabled(config.screenshot_enabled ?? true);
    setScreenshotOnFailure(config.screenshot_on_failure ?? false);
    setScreenshotPrefix(config.screenshot_s3_prefix ?? "qa-screenshots/");
    setVisualThreshold(config.visual_diff_threshold ?? 0.01);
    setMaxTime(config.max_test_time_seconds ?? 1800);
    setFlakyRetries(config.flaky_retry_count ?? 2);
    setPrReview(config.pr_review_enabled ?? true);
    setCodingTool((config.coding_tool as Tool) ?? "claude_code");
    setModel(config.coding_tool_model ?? "");
  }, [config]);

  const buildBody = (): QaConfigIn => ({
    test_framework: framework,
    browser,
    test_dir: testDir,
    test_file_pattern: filePattern,
    test_run_command: runCommand,
    test_run_specific_command: runSpecific,
    regression_scope: scope,
    regression_command: regressionCommand,
    screenshot_enabled: screenshotEnabled,
    screenshot_on_failure: screenshotOnFailure,
    screenshot_s3_prefix: screenshotPrefix,
    visual_diff_threshold: visualThreshold,
    max_test_time_seconds: maxTime,
    flaky_retry_count: flakyRetries,
    pr_review_enabled: prReview,
    coding_tool: codingTool,
    coding_tool_model: model || null,
  });

  const saveMut = useMutation({
    mutationFn: () => updateQaConfig(typeId, buildBody()),
    onSuccess: () => {
      setValidationErrors([]);
      queryClient.invalidateQueries({ queryKey: ["qa-config", typeId] });
    },
  });

  const validateMut = useMutation({
    mutationFn: () => validateQaConfig(typeId, buildBody()),
    onSuccess: (res) => setValidationErrors(res.errors),
  });

  return (
    <div data-testid="qa-config-tab" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Test Framework Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Test framework</Label>
            <Select value={framework} onValueChange={(v) => setFramework(v as Framework)}>
              <SelectTrigger data-testid="qa-framework">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="playwright">playwright</SelectItem>
                <SelectItem value="cypress">cypress</SelectItem>
                <SelectItem value="pytest">pytest</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Browser</Label>
            <Select value={browser} onValueChange={(v) => setBrowser(v as Browser)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="chromium">chromium</SelectItem>
                <SelectItem value="firefox">firefox</SelectItem>
                <SelectItem value="webkit">webkit</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Test directory</Label>
            <Input value={testDir} onChange={(e) => setTestDir(e.target.value)} />
          </div>
          <div>
            <Label>Test file pattern</Label>
            <Input value={filePattern} onChange={(e) => setFilePattern(e.target.value)} />
          </div>
          <div>
            <Label>Test run command</Label>
            <Input className="font-mono" value={runCommand} onChange={(e) => setRunCommand(e.target.value)} />
          </div>
          <div>
            <Label>Run specific test command</Label>
            <Input className="font-mono" value={runSpecific} onChange={(e) => setRunSpecific(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Regression Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Regression scope</Label>
            <Select value={scope} onValueChange={(v) => setScope(v as Scope)}>
              <SelectTrigger data-testid="qa-regression-scope">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="full">full</SelectItem>
                <SelectItem value="affected">affected</SelectItem>
                <SelectItem value="none">none</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Regression command</Label>
            <Input className="font-mono" value={regressionCommand} onChange={(e) => setRegressionCommand(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Screenshot Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-2">
            <Switch checked={screenshotEnabled} onCheckedChange={setScreenshotEnabled} />
            <Label>Screenshots enabled</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={screenshotOnFailure} onCheckedChange={setScreenshotOnFailure} />
            <Label>Screenshot on failure only</Label>
          </div>
          <div>
            <Label>Screenshot S3 prefix</Label>
            <Input value={screenshotPrefix} onChange={(e) => setScreenshotPrefix(e.target.value)} />
          </div>
          <div>
            <Label>Visual diff threshold (0.0 - 1.0)</Label>
            <Input
              type="number"
              step="0.01"
              min={0}
              max={1}
              value={visualThreshold}
              onChange={(e) => setVisualThreshold(Number(e.target.value))}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Execution Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Max test time (s)</Label>
            <Input
              type="number"
              min={300}
              max={14400}
              value={maxTime}
              onChange={(e) => setMaxTime(Number(e.target.value))}
            />
          </div>
          <div>
            <Label>Flaky retry count</Label>
            <Input
              type="number"
              min={0}
              max={5}
              value={flakyRetries}
              onChange={(e) => setFlakyRetries(Number(e.target.value))}
            />
          </div>
          <div>
            <Label>Coding tool</Label>
            <Select value={codingTool} onValueChange={(v) => setCodingTool(v as Tool)}>
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

      <Card>
        <CardHeader>
          <CardTitle>Integration Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-2">
            <Switch checked={prReview} onCheckedChange={setPrReview} />
            <Label>PR review enabled</Label>
          </div>
        </CardContent>
      </Card>

      {validationErrors.length > 0 && (
        <div data-testid="qa-validation-errors" className="rounded border border-destructive p-3 text-sm">
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
        <Button data-testid="qa-save-btn" onClick={() => saveMut.mutate()} disabled={saveMut.isPending || isLoading}>
          Save
        </Button>
      </div>
    </div>
  );
}

function QaEligibleTab({ typeId }: { typeId: string }) {
  const { data, refetch, isFetching } = useQuery({
    queryKey: ["qa-eligible", typeId],
    queryFn: () => getQaEligibleTickets(typeId, 50),
    staleTime: 10_000,
  });
  const tickets = data?.tickets ?? [];
  return (
    <div data-testid="qa-eligible-tab" className="space-y-3">
      <p className="text-sm text-muted-foreground">These tickets are ready for QA.</p>
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
              <TableHead>Status</TableHead>
              <TableHead>PR</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tickets.map((t) => (
              <TableRow key={t.ticket_id}>
                <TableCell>{t.ticket_id}</TableCell>
                <TableCell>{t.subject}</TableCell>
                <TableCell>
                  <Badge variant="secondary">{t.status}</Badge>
                </TableCell>
                <TableCell>
                  {t.pr_url ? (
                    <a className="text-primary underline" href={t.pr_url} target="_blank" rel="noreferrer">
                      PR
                    </a>
                  ) : (
                    "-"
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

function StatCard({ title, value, testId }: { title: string; value: string; testId?: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent data-testid={testId} className="text-2xl font-bold">
        {value}
      </CardContent>
    </Card>
  );
}

function QaMetricsTab({ typeId }: { typeId: string }) {
  const [periodDays, setPeriodDays] = useState(30);
  const { data } = useQuery({
    queryKey: ["qa-metrics", typeId, periodDays],
    queryFn: () => getQaMetrics(typeId, periodDays),
    staleTime: 300_000,
  });
  return (
    <div data-testid="qa-metrics-tab" className="space-y-4">
      <div className="w-40">
        <Select value={String(periodDays)} onValueChange={(v) => setPeriodDays(Number(v))}>
          <SelectTrigger>
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
        <StatCard title="Tickets Tested" value={String(data?.tested_count ?? 0)} testId="qa-metric-tested" />
        <StatCard title="Pass Rate" value={`${((data?.pass_rate ?? 0) * 100).toFixed(1)}%`} testId="qa-metric-pass-rate" />
        <StatCard title="Bugs Found" value={String(data?.bugs_found_count ?? 0)} />
        <StatCard title="Avg Duration" value={`${Math.round(data?.avg_duration_seconds ?? 0)}s`} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Flaky Test Rate</CardTitle>
        </CardHeader>
        <CardContent>
          <Progress value={(data?.flaky_test_rate ?? 0) * 100} />
          <p className="mt-1 text-sm">{((data?.flaky_test_rate ?? 0) * 100).toFixed(2)}%</p>
        </CardContent>
      </Card>
    </div>
  );
}

export default function QaAgentConfigPage() {
  const { typeId = "" } = useParams();
  return (
    <div data-testid="qa-config-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <TestTube2 className="h-6 w-6" />
        <h1 className="text-2xl font-bold">QA Agent Configuration</h1>
      </div>
      <Tabs defaultValue="config">
        <TabsList>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="eligible">Eligible Tickets</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
        </TabsList>
        <TabsContent value="config">
          <QaConfigTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="eligible">
          <QaEligibleTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="metrics">
          <QaMetricsTab typeId={typeId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
