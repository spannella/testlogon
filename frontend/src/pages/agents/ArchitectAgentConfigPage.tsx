import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  getArchitectConfig,
  updateArchitectConfig,
  validateArchitectConfig,
  getArchitectEligibleTickets,
  getDecomposition,
  getDependencyGraph,
  getArchitectMetrics,
} from "@/api/endpoints/architectAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
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
import { Compass, RefreshCw } from "lucide-react";
import type { ArchitectConfigIn } from "@/api/types";
import DependencyGraphView from "./DependencyGraphView";

function ArchitectConfigTab({ typeId }: { typeId: string }) {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useQuery({
    queryKey: ["architect-config", typeId],
    queryFn: () => getArchitectConfig(typeId).catch(() => undefined),
    staleTime: 60_000,
  });

  const [repoUrl, setRepoUrl] = useState("");
  const [repoBranch, setRepoBranch] = useState("main");
  const [referenceDocs, setReferenceDocs] = useState("CLAUDE.md\ndocs/dynamodb.md");
  const [scanPaths, setScanPaths] = useState("app/services/\napp/routers/\nfrontend/src/");
  const [ticketTemplate, setTicketTemplate] = useState("");
  const [guidelines, setGuidelines] = useState("");
  const [maxTickets, setMaxTickets] = useState(8);
  const [analysisTime, setAnalysisTime] = useState(900);
  const [specStyle, setSpecStyle] = useState<"full" | "compact">("compact");
  const [codingTool, setCodingTool] = useState<"claude_code" | "codex">("claude_code");
  const [model, setModel] = useState("");
  const [requireReview, setRequireReview] = useState(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  useEffect(() => {
    if (!config) return;
    setRepoUrl(config.repo_url ?? "");
    setRepoBranch(config.repo_branch ?? "main");
    setReferenceDocs((config.reference_docs ?? []).join("\n"));
    setScanPaths((config.scan_paths ?? []).join("\n"));
    setTicketTemplate(config.ticket_template ?? "");
    setGuidelines(config.architecture_guidelines ?? "");
    setMaxTickets(config.max_tickets_per_feature ?? 8);
    setAnalysisTime(config.max_analysis_time_seconds ?? 900);
    setSpecStyle((config.ticket_spec_style as "full" | "compact") ?? "compact");
    setCodingTool((config.coding_tool as "claude_code" | "codex") ?? "claude_code");
    setModel(config.coding_tool_model ?? "");
    setRequireReview(config.require_design_review ?? false);
  }, [config]);

  const buildBody = (): ArchitectConfigIn => ({
    repo_url: repoUrl,
    repo_branch: repoBranch,
    reference_docs: referenceDocs.split("\n").map((c) => c.trim()).filter(Boolean),
    scan_paths: scanPaths.split("\n").map((c) => c.trim()).filter(Boolean),
    ticket_template: ticketTemplate,
    architecture_guidelines: guidelines,
    max_tickets_per_feature: maxTickets,
    max_analysis_time_seconds: analysisTime,
    ticket_spec_style: specStyle,
    coding_tool: codingTool,
    coding_tool_model: model || null,
    require_design_review: requireReview,
  });

  const saveMut = useMutation({
    mutationFn: () => updateArchitectConfig(typeId, buildBody()),
    onSuccess: () => {
      setValidationErrors([]);
      queryClient.invalidateQueries({ queryKey: ["architect-config", typeId] });
    },
  });

  const validateMut = useMutation({
    mutationFn: () => validateArchitectConfig(typeId, buildBody()),
    onSuccess: (res) => setValidationErrors(res.errors),
  });

  return (
    <div data-testid="architect-config-tab" className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Repository</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Repository URL</Label>
            <Input
              data-testid="architect-repo-url"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/org/repo.git"
            />
          </div>
          <div>
            <Label>Branch</Label>
            <Input value={repoBranch} onChange={(e) => setRepoBranch(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Codebase Analysis</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Reference docs (one per line)</Label>
            <Textarea
              data-testid="architect-reference-docs"
              value={referenceDocs}
              onChange={(e) => setReferenceDocs(e.target.value)}
              rows={3}
            />
          </div>
          <div>
            <Label>Scan paths (one per line)</Label>
            <Textarea value={scanPaths} onChange={(e) => setScanPaths(e.target.value)} rows={3} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Ticket Template & Guidelines</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Ticket template (placeholders: {"{subject}, {overview}, {data_model}, …"})</Label>
            <Textarea
              data-testid="architect-ticket-template"
              value={ticketTemplate}
              onChange={(e) => setTicketTemplate(e.target.value)}
              rows={4}
              placeholder="# {subject}\n\n## Overview\n{overview}"
            />
          </div>
          <div>
            <Label>Architecture guidelines</Label>
            <Textarea value={guidelines} onChange={(e) => setGuidelines(e.target.value)} rows={4} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Decomposition Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-4">
            <div>
              <Label>Max tickets per feature</Label>
              <Input
                type="number"
                value={maxTickets}
                onChange={(e) => setMaxTickets(Number(e.target.value))}
              />
            </div>
            <div>
              <Label>Analysis time budget (s)</Label>
              <Input
                type="number"
                value={analysisTime}
                onChange={(e) => setAnalysisTime(Number(e.target.value))}
              />
            </div>
          </div>
          <div>
            <Label>Ticket spec style</Label>
            <Select value={specStyle} onValueChange={(v) => setSpecStyle(v as "full" | "compact")}>
              <SelectTrigger data-testid="architect-spec-style">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="compact">compact</SelectItem>
                <SelectItem value="full">full</SelectItem>
              </SelectContent>
            </Select>
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
          <div className="flex items-center gap-2">
            <Switch
              data-testid="architect-require-review"
              checked={requireReview}
              onCheckedChange={setRequireReview}
            />
            <Label>Require design review before creating tickets</Label>
          </div>
        </CardContent>
      </Card>

      {validationErrors.length > 0 && (
        <div data-testid="architect-validation-errors" className="rounded border border-destructive p-3 text-sm">
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
        <Button data-testid="architect-save-btn" onClick={() => saveMut.mutate()} disabled={saveMut.isPending || isLoading}>
          Save
        </Button>
      </div>
    </div>
  );
}

function FeaturesTab({ typeId }: { typeId: string }) {
  const { data, refetch, isFetching } = useQuery({
    queryKey: ["architect-eligible", typeId],
    queryFn: () => getArchitectEligibleTickets(typeId, 50),
    staleTime: 10_000,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const tickets = data?.tickets ?? [];

  return (
    <div data-testid="architect-features-tab" className="space-y-4">
      <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
        <RefreshCw className="h-4 w-4 mr-1" /> Refresh
      </Button>
      <FeatureLookup onSelect={setSelected} />
      {tickets.length === 0 ? (
        <p className="text-sm text-muted-foreground">No open feature requests pending decomposition.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Ticket ID</TableHead>
              <TableHead>Subject</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Labels</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tickets.map((t) => (
              <TableRow key={t.ticket_id} data-testid="architect-feature-row">
                <TableCell>{t.ticket_id}</TableCell>
                <TableCell>{t.subject}</TableCell>
                <TableCell>{t.status}</TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {t.labels.map((l) => (
                      <Badge key={l} variant="secondary">
                        {l}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell>
                  <Button size="sm" variant="ghost" onClick={() => setSelected(t.ticket_id)}>
                    View
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {selected && <DecompositionDetail featureTicketId={selected} />}
    </div>
  );
}

function FeatureLookup({ onSelect }: { onSelect: (id: string) => void }) {
  const [value, setValue] = useState("");
  return (
    <div className="flex items-end gap-2">
      <div className="flex-1">
        <Label>View a decomposed feature</Label>
        <Input
          data-testid="architect-feature-lookup"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="feature ticket id"
        />
      </div>
      <Button variant="outline" onClick={() => value && onSelect(value)}>
        Open
      </Button>
    </div>
  );
}

function DecompositionDetail({ featureTicketId }: { featureTicketId: string }) {
  const { data: decomp } = useQuery({
    queryKey: ["architect-decomposition", featureTicketId],
    queryFn: () => getDecomposition(featureTicketId).catch(() => undefined),
  });
  const { data: graph } = useQuery({
    queryKey: ["architect-graph", featureTicketId],
    queryFn: () => getDependencyGraph(featureTicketId).catch(() => undefined),
  });

  if (!decomp) {
    return (
      <p className="text-sm text-muted-foreground">
        No decomposition available for {featureTicketId}.
      </p>
    );
  }

  return (
    <div className="space-y-4" data-testid="architect-decomposition-detail">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Architecture Summary — {featureTicketId}</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="whitespace-pre-wrap text-sm">{decomp.decomposition_summary}</pre>
          <div className="mt-2 flex gap-2">
            <Badge variant="secondary">{decomp.total_tickets_created} tickets</Badge>
            <Badge variant="secondary">{decomp.total_estimated_hours}h</Badge>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Dependency Graph</CardTitle>
        </CardHeader>
        <CardContent>
          {graph ? (
            <DependencyGraphView graph={graph} />
          ) : (
            <p className="text-sm text-muted-foreground">No graph available.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ArchitectMetricsTab({ typeId }: { typeId: string }) {
  const { data } = useQuery({
    queryKey: ["architect-metrics", typeId],
    queryFn: () => getArchitectMetrics(typeId, 30),
    staleTime: 300_000,
  });
  return (
    <div data-testid="architect-metrics-tab" className="space-y-4">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Features Decomposed</CardTitle>
          </CardHeader>
          <CardContent data-testid="metric-features-decomposed" className="text-2xl font-bold">
            {data?.features_decomposed ?? 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Avg Tickets / Feature</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{data?.avg_tickets_per_feature ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Avg Hours / Feature</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{data?.avg_hours_per_feature ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Decomposition Rate</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{data?.decomposition_rate ?? 0}</CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function ArchitectAgentConfigPage() {
  const { typeId = "" } = useParams();
  return (
    <div data-testid="architect-config-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <Compass className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Solution Architect Agent</h1>
      </div>
      <Tabs defaultValue="config">
        <TabsList>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="features">Features</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
        </TabsList>
        <TabsContent value="config">
          <ArchitectConfigTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="features">
          <FeaturesTab typeId={typeId} />
        </TabsContent>
        <TabsContent value="metrics">
          <ArchitectMetricsTab typeId={typeId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
