import { Fragment, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listSecurityFindings,
  updateFindingStatus,
  listSecurityAudits,
  triggerSecurityAudit,
  getFindingTrends,
  getComplianceStatus,
} from "@/api/endpoints/complianceAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { ShieldAlert, RefreshCw } from "lucide-react";
import type { SecurityFinding } from "@/api/types";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-gray-400 text-white",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      data-testid={`severity-badge-${severity}`}
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${
        SEVERITY_BADGE[severity] ?? "bg-gray-300"
      }`}
    >
      {severity}
    </span>
  );
}

function SummaryCards() {
  const { data } = useQuery({
    queryKey: ["compliance-findings", "open"],
    queryFn: () => listSecurityFindings({ status: "open", limit: 200 }),
    staleTime: 10_000,
  });
  const findings = data?.findings ?? [];
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    total: findings.length,
  };
  const { data: compliance } = useQuery({
    queryKey: ["compliance-status"],
    queryFn: () => getComplianceStatus(),
    staleTime: 10_000,
  });
  const failing = Object.values(compliance?.frameworks ?? {}).filter(
    (f) => f.status === "failing",
  ).length;
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Open Critical</CardTitle>
        </CardHeader>
        <CardContent data-testid="summary-critical" className="text-2xl font-bold text-red-600">
          {counts.critical}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Open High</CardTitle>
        </CardHeader>
        <CardContent data-testid="summary-high" className="text-2xl font-bold text-orange-500">
          {counts.high}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Total Findings</CardTitle>
        </CardHeader>
        <CardContent data-testid="summary-total" className="text-2xl font-bold">
          {counts.total}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Frameworks Failing</CardTitle>
        </CardHeader>
        <CardContent data-testid="summary-frameworks" className="text-2xl font-bold">
          {failing}
        </CardContent>
      </Card>
    </div>
  );
}

function FindingsTab() {
  const queryClient = useQueryClient();
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, refetch, isFetching } = useQuery({
    queryKey: ["compliance-findings", severity, status],
    queryFn: () =>
      listSecurityFindings({
        severity: severity === "all" ? undefined : severity,
        status: status === "all" ? undefined : status,
        limit: 100,
      }),
    staleTime: 5_000,
  });

  const statusMut = useMutation({
    mutationFn: ({ id, s }: { id: string; s: "acknowledged" | "false_positive" }) =>
      updateFindingStatus(id, s),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compliance-findings"] });
      queryClient.invalidateQueries({ queryKey: ["compliance-status"] });
    },
  });

  const findings = data?.findings ?? [];

  return (
    <div data-testid="findings-list" className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger data-testid="filter-severity" className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">critical</SelectItem>
            <SelectItem value="high">high</SelectItem>
            <SelectItem value="medium">medium</SelectItem>
            <SelectItem value="low">low</SelectItem>
            <SelectItem value="info">info</SelectItem>
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger data-testid="filter-status" className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="open">open</SelectItem>
            <SelectItem value="acknowledged">acknowledged</SelectItem>
            <SelectItem value="remediated">remediated</SelectItem>
            <SelectItem value="false_positive">false_positive</SelectItem>
            <SelectItem value="accepted_risk">accepted_risk</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className="mr-1 h-4 w-4" /> Refresh
        </Button>
      </div>

      {findings.length === 0 ? (
        <p data-testid="findings-empty" className="text-sm text-muted-foreground">
          No findings match the current filters.
        </p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Status</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.map((f: SecurityFinding) => (
              <Fragment key={f.finding_id}>
                <TableRow
                  data-testid={`finding-row-${f.finding_id}`}
                  className="cursor-pointer"
                  onClick={() => setExpanded(expanded === f.finding_id ? null : f.finding_id)}
                >
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell>{f.category}</TableCell>
                  <TableCell>{f.title}</TableCell>
                  <TableCell className="text-xs">{f.source_ref || "-"}</TableCell>
                  <TableCell>
                    <Badge data-testid={`finding-status-${f.finding_id}`} variant="secondary">
                      {f.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {f.status === "open" && (
                      <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                        <Button
                          size="sm"
                          variant="outline"
                          data-testid={`ack-${f.finding_id}`}
                          onClick={() => statusMut.mutate({ id: f.finding_id, s: "acknowledged" })}
                        >
                          Acknowledge
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          data-testid={`fp-${f.finding_id}`}
                          onClick={() => statusMut.mutate({ id: f.finding_id, s: "false_positive" })}
                        >
                          False positive
                        </Button>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
                {expanded === f.finding_id && (
                  <TableRow>
                    <TableCell colSpan={6}>
                      <div data-testid={`finding-detail-${f.finding_id}`} className="space-y-2 text-sm">
                        <p>{f.description}</p>
                        {f.file_path && (
                          <p className="text-xs text-muted-foreground">
                            {f.file_path}
                            {f.line_range ? `:${f.line_range}` : ""}
                          </p>
                        )}
                        {f.code_snippet && (
                          <pre className="overflow-x-auto rounded bg-muted p-2 text-xs">
                            {f.code_snippet}
                          </pre>
                        )}
                        {f.remediation && (
                          <p className="text-xs">
                            <span className="font-semibold">Remediation:</span> {f.remediation}
                          </p>
                        )}
                        {f.remediation_ticket_id && (
                          <p className="text-xs">Ticket: {f.remediation_ticket_id}</p>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

function AuditsTab() {
  const queryClient = useQueryClient();
  const { data, isFetching, refetch } = useQuery({
    queryKey: ["compliance-audits"],
    queryFn: () => listSecurityAudits(50),
    staleTime: 5_000,
  });
  const triggerMut = useMutation({
    mutationFn: () => triggerSecurityAudit(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compliance-audits"] });
    },
  });
  const audits = data?.audits ?? [];
  return (
    <div data-testid="audit-history" className="space-y-3">
      <div className="flex gap-2">
        <Button
          data-testid="run-audit-btn"
          onClick={() => triggerMut.mutate()}
          disabled={triggerMut.isPending}
        >
          Run Audit Now
        </Button>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className="mr-1 h-4 w-4" /> Refresh
        </Button>
      </div>
      {audits.length === 0 ? (
        <p className="text-sm text-muted-foreground">No audits yet. Run one to scan the codebase.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Audit ID</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Files</TableHead>
              <TableHead>Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {audits.map((a) => {
              const total = Object.values(a.finding_counts ?? {}).reduce((s, n) => s + n, 0);
              return (
                <TableRow key={a.audit_id} data-testid={`audit-row-${a.audit_id}`}>
                  <TableCell className="font-mono text-xs">{a.audit_id.slice(0, 12)}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{a.status}</Badge>
                  </TableCell>
                  <TableCell>{a.files_scanned}</TableCell>
                  <TableCell>
                    {total === 0 ? (
                      <span className="text-green-600">All clear</span>
                    ) : (
                      <div className="flex gap-1">
                        {Object.entries(a.finding_counts)
                          .filter(([, n]) => n > 0)
                          .map(([sev, n]) => (
                            <span key={sev} className="text-xs">
                              {sev}:{n}
                            </span>
                          ))}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

function CompliancePanel() {
  const { data } = useQuery({
    queryKey: ["compliance-status"],
    queryFn: () => getComplianceStatus(),
    staleTime: 10_000,
  });
  const frameworks = Object.entries(data?.frameworks ?? {});
  return (
    <div data-testid="compliance-panel" className="grid grid-cols-1 gap-4 md:grid-cols-2">
      {frameworks.length === 0 ? (
        <p className="text-sm text-muted-foreground">No compliance data yet.</p>
      ) : (
        frameworks.map(([key, fw]) => (
          <Card key={key} data-testid={`framework-${key}`}>
            <CardHeader>
              <CardTitle className="flex items-center justify-between text-sm">
                {fw.name}
                <Badge
                  variant={fw.status === "passing" ? "secondary" : "destructive"}
                >
                  {fw.status}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm">
              <p>Open findings: {fw.open_findings}</p>
              <div className="mt-2 h-2 w-full rounded bg-muted">
                <div
                  className={`h-2 rounded ${fw.status === "passing" ? "bg-green-500" : "bg-red-500"}`}
                  style={{ width: fw.open_findings > 0 ? "100%" : "0%" }}
                />
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

function TrendsTab() {
  const { data } = useQuery({
    queryKey: ["compliance-trends"],
    queryFn: () => getFindingTrends(90),
    staleTime: 30_000,
  });
  const weeks = data?.weeks ?? [];
  return (
    <div data-testid="trends-panel" className="space-y-3">
      <p className="text-sm text-muted-foreground">
        {data?.total ?? 0} findings over the last {data?.days ?? 90} days.
      </p>
      {weeks.length === 0 ? (
        <p className="text-sm text-muted-foreground">No trend data yet.</p>
      ) : (
        <div className="flex items-end gap-2">
          {weeks.map((w) => (
            <div key={w.week_start} className="flex flex-col items-center">
              <div
                className="w-8 rounded bg-primary"
                style={{ height: `${Math.min(w.total * 16 + 4, 160)}px` }}
              />
              <span className="text-xs">{w.total}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ComplianceAgentConfigPage() {
  return (
    <div data-testid="security-dashboard-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Compliance &amp; Security Agent</h1>
      </div>
      <SummaryCards />
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="audits">Audits</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
        </TabsList>
        <TabsContent value="findings">
          <FindingsTab />
        </TabsContent>
        <TabsContent value="audits">
          <AuditsTab />
        </TabsContent>
        <TabsContent value="compliance">
          <CompliancePanel />
        </TabsContent>
        <TabsContent value="trends">
          <TrendsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
