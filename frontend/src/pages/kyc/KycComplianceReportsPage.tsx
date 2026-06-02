import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  downloadKycReportExport,
  generateKycSar,
  getKycAuditTrail,
  getKycDeadlineReport,
  getKycProcessingTimeReport,
  getKycRetentionReport,
  getKycScreeningReport,
  getKycVolumeReport,
} from "@/api/endpoints/kycCompliance";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function toUnixOrUndefined(value: string): number | undefined {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : Math.floor(ms / 1000);
}

function fmtTs(ts?: number | null): string {
  if (ts == null) return "—";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function ExportButtons({
  reportType,
  start,
  end,
}: {
  reportType: string;
  start?: number;
  end?: number;
}) {
  const exportMut = useMutation({
    mutationFn: (format: "csv" | "pdf") =>
      downloadKycReportExport(reportType, { format, start_date: start, end_date: end }),
    onError: () => toast.error("Export failed"),
  });
  return (
    <div className="flex gap-2">
      <Button variant="outline" size="sm" onClick={() => exportMut.mutate("csv")}>
        Export CSV
      </Button>
      <Button variant="outline" size="sm" onClick={() => exportMut.mutate("pdf")}>
        Export PDF
      </Button>
    </div>
  );
}

export default function KycComplianceReportsPage() {
  const [startStr, setStartStr] = useState("");
  const [endStr, setEndStr] = useState("");
  const start = toUnixOrUndefined(startStr);
  const end = toUnixOrUndefined(endStr);

  const volume = useQuery({
    queryKey: ["kyc-reports", "volume", start, end],
    queryFn: () => getKycVolumeReport(start, end),
    staleTime: 60_000,
  });
  const screening = useQuery({
    queryKey: ["kyc-reports", "screening", start, end],
    queryFn: () => getKycScreeningReport(start, end),
    staleTime: 60_000,
  });
  const processing = useQuery({
    queryKey: ["kyc-reports", "processing-time", start, end],
    queryFn: () => getKycProcessingTimeReport(start, end),
    staleTime: 60_000,
  });
  const deadlines = useQuery({
    queryKey: ["kyc-reports", "deadlines"],
    queryFn: () => getKycDeadlineReport(),
    staleTime: 30_000,
  });
  const retention = useQuery({
    queryKey: ["kyc-reports", "retention"],
    queryFn: () => getKycRetentionReport(),
    staleTime: 60_000,
  });

  // Audit trail
  const [auditUserSub, setAuditUserSub] = useState("");
  const [auditQuerySub, setAuditQuerySub] = useState("");
  const audit = useQuery({
    queryKey: ["kyc-reports", "audit-trail", auditQuerySub],
    queryFn: () => getKycAuditTrail(auditQuerySub),
    enabled: !!auditQuerySub,
  });

  // SAR generator
  const [sarUserSub, setSarUserSub] = useState("");
  const [sarReason, setSarReason] = useState("");
  const [sarTxns, setSarTxns] = useState("");
  const sarMut = useMutation({
    mutationFn: () =>
      generateKycSar({
        user_sub: sarUserSub,
        reason: sarReason,
        transaction_ids: sarTxns
          ? sarTxns.split(",").map((t) => t.trim()).filter(Boolean)
          : undefined,
      }),
    onSuccess: (sar) => toast.success(`SAR generated: ${sar.sar_id}`),
    onError: () => toast.error("SAR generation failed (min 10-char reason required)"),
  });

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold">KYC Compliance Reports</h1>
        <Badge variant="outline">Admin / Root Access</Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Date Range</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <Label htmlFor="start-date">Start</Label>
            <Input
              id="start-date"
              type="date"
              value={startStr}
              onChange={(e) => setStartStr(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="end-date">End</Label>
            <Input
              id="end-date"
              type="date"
              value={endStr}
              onChange={(e) => setEndStr(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="volume">
        <TabsList>
          <TabsTrigger value="volume">Volume</TabsTrigger>
          <TabsTrigger value="screening">Screening</TabsTrigger>
          <TabsTrigger value="processing-time">Processing Time</TabsTrigger>
          <TabsTrigger value="deadlines">Deadlines</TabsTrigger>
          <TabsTrigger value="retention">Retention</TabsTrigger>
          <TabsTrigger value="sar">SAR Generator</TabsTrigger>
        </TabsList>

        <TabsContent value="volume" className="mt-4">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Volume Report</CardTitle>
              <ExportButtons reportType="volume" start={start} end={end} />
            </CardHeader>
            <CardContent className="space-y-3">
              {volume.data && (
                <>
                  <div className="flex gap-6 text-sm">
                    <span>Total: {volume.data.total_cases}</span>
                    <span>Approval: {volume.data.approval_rate}%</span>
                    <span>Rejection: {volume.data.rejection_rate}%</span>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Status</TableHead>
                        <TableHead>Count</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {Object.entries(volume.data.counts_by_status).map(([status, count]) => (
                        <TableRow key={status}>
                          <TableCell>{status}</TableCell>
                          <TableCell>{count}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="screening" className="mt-4">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Screening Report</CardTitle>
              <ExportButtons reportType="screening" start={start} end={end} />
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {screening.data && (
                <>
                  <div>Total screenings: {screening.data.total_screenings}</div>
                  <div>Hits: {screening.data.total_hits}</div>
                  <div>Hit rate: {screening.data.hit_rate_pct}%</div>
                  <div>False positives: {screening.data.false_positive_count}</div>
                  <div>Escalated: {screening.data.escalated_count}</div>
                  <div>Confirmed: {screening.data.confirmed_count}</div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="processing-time" className="mt-4">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Processing Time Report</CardTitle>
              <ExportButtons reportType="processing-time" start={start} end={end} />
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {processing.data && (
                <>
                  <div>Decided cases: {processing.data.total_decided}</div>
                  <div>Average: {processing.data.avg_seconds}s</div>
                  <div>p50: {processing.data.p50_seconds ?? "—"}s</div>
                  <div>p90: {processing.data.p90_seconds ?? "—"}s</div>
                  <div>p95: {processing.data.p95_seconds ?? "—"}s</div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="deadlines" className="mt-4">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Deadline Tracker</CardTitle>
              <ExportButtons reportType="deadlines" />
            </CardHeader>
            <CardContent>
              {deadlines.data && (
                <>
                  <div className="mb-3 flex gap-6 text-sm">
                    <span>Overdue: {deadlines.data.total_overdue}</span>
                    <span>Critical: {deadlines.data.critical_count}</span>
                    <span>Warning: {deadlines.data.warning_count}</span>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Case ID</TableHead>
                        <TableHead>User</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Age (h)</TableHead>
                        <TableHead>Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {deadlines.data.cases.map((c) => (
                        <TableRow
                          key={c.case_id}
                          className={c.severity === "critical" ? "bg-red-50" : "bg-yellow-50"}
                        >
                          <TableCell>{c.case_id}</TableCell>
                          <TableCell>{c.user_sub}</TableCell>
                          <TableCell>{c.status}</TableCell>
                          <TableCell>{c.age_hours}</TableCell>
                          <TableCell>{c.severity}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="retention" className="mt-4">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Retention Report</CardTitle>
              <ExportButtons reportType="retention" />
            </CardHeader>
            <CardContent>
              {retention.data && (
                <>
                  <div className="mb-3 flex gap-6 text-sm">
                    <span
                      className={retention.data.overdue_purge_count > 0 ? "text-red-600" : ""}
                    >
                      Overdue purges: {retention.data.overdue_purge_count}
                    </span>
                    <span>Already purged: {retention.data.already_purged_count}</span>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Case</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Purge Due</TableHead>
                        <TableHead>Overdue</TableHead>
                        <TableHead>Files</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {retention.data.inventory.map((item) => (
                        <TableRow
                          key={item.case_id}
                          className={item.purge_overdue ? "bg-red-50" : ""}
                        >
                          <TableCell>{item.case_id}</TableCell>
                          <TableCell>{item.status}</TableCell>
                          <TableCell>{fmtTs(item.purge_due_at)}</TableCell>
                          <TableCell>{item.purge_overdue ? "yes" : "no"}</TableCell>
                          <TableCell>{item.file_count}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sar" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Generate Suspicious Activity Report</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="sar-user">User Sub</Label>
                <Input
                  id="sar-user"
                  value={sarUserSub}
                  onChange={(e) => setSarUserSub(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="sar-reason">Reason (min 10 chars)</Label>
                <Textarea
                  id="sar-reason"
                  value={sarReason}
                  onChange={(e) => setSarReason(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="sar-txns">Transaction IDs (comma-separated)</Label>
                <Input
                  id="sar-txns"
                  value={sarTxns}
                  onChange={(e) => setSarTxns(e.target.value)}
                />
              </div>
              <Button
                onClick={() => sarMut.mutate()}
                disabled={!sarUserSub || sarReason.length < 10 || sarMut.isPending}
              >
                Generate SAR
              </Button>
              {sarMut.data && (
                <div className="rounded border p-3 text-sm">
                  <div>SAR ID: {sarMut.data.sar_id}</div>
                  <div>Generated: {fmtTs(sarMut.data.generated_at)}</div>
                  <div>KYC cases: {sarMut.data.kyc_cases.length}</div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">User Audit Trail</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="audit-user">User Sub</Label>
              <Input
                id="audit-user"
                value={auditUserSub}
                onChange={(e) => setAuditUserSub(e.target.value)}
              />
            </div>
            <Button variant="outline" onClick={() => setAuditQuerySub(auditUserSub)}>
              Load Audit Trail
            </Button>
          </div>
          {audit.data && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Outcome</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {audit.data.events.map((ev, i) => (
                  <TableRow key={`${ev.event_name}-${i}`}>
                    <TableCell>{ev.event_name}</TableCell>
                    <TableCell>{ev.actor_sub}</TableCell>
                    <TableCell>{fmtTs(ev.timestamp)}</TableCell>
                    <TableCell>{ev.outcome ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
