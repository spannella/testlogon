import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { BarChart3, FileText, Lock, Store } from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
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
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  getXReport,
  getZReport,
  fmtCents,
  type SessionReportOut,
} from "@/api/endpoints/pos";

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function StatRow({ label, value, bold }: { label: string; value: string; bold?: boolean }) {
  return (
    <div className={`flex justify-between text-sm ${bold ? "font-semibold" : ""}`}>
      <span className={bold ? "" : "text-muted-foreground"}>{label}</span>
      <span className="tabular-nums">{value}</span>
    </div>
  );
}

export default function PosReportsPage() {
  const [sessionId, setSessionId] = useState("");
  const [report, setReport] = useState<SessionReportOut | null>(null);

  const xMut = useMutation({
    mutationFn: () => getXReport(sessionId.trim()),
    onSuccess: (r) => {
      setReport(r);
      toast.success("X report generated (mid-shift snapshot)");
    },
    onError: (e: any) =>
      toast.error(
        e?.status === 404
          ? "Session not found, or POS is disabled on the backend."
          : e?.message || "Failed to generate X report",
      ),
  });

  const zMut = useMutation({
    mutationFn: () => getZReport(sessionId.trim()),
    onSuccess: (r) => {
      setReport(r);
      toast.success("Z report generated (end-of-shift)");
    },
    onError: (e: any) =>
      toast.error(
        e?.status === 404
          ? "Session not found, or POS is disabled on the backend."
          : e?.message || "Failed to generate Z report",
      ),
  });

  const isZ = report?.report_kind === "z";
  const currency = "USD";

  return (
    <div className="space-y-6">
      <PageHeader
        title="POS Session Reports"
        description="Generate an X (mid-shift) or Z (end-of-shift) till summary for a register session."
        actions={
          <Button variant="outline" asChild>
            <Link to="/ofbiz/pos">
              <Store className="mr-2 h-4 w-4" /> Terminal
            </Link>
          </Button>
        }
      />

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <BarChart3 className="h-4 w-4" /> Run a report
          </CardTitle>
          <CardDescription>
            X = read-only running totals. Z = finalizes the shift (stamps the Z print time).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="sid">Session ID</Label>
            <Input
              id="sid"
              placeholder="sess_…"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <Button
              onClick={() => xMut.mutate()}
              disabled={!sessionId.trim() || xMut.isPending}
              variant="outline"
              className="flex-1"
            >
              <FileText className="mr-2 h-4 w-4" />
              {xMut.isPending ? "Generating…" : "X report"}
            </Button>
            <Button
              onClick={() => zMut.mutate()}
              disabled={!sessionId.trim() || zMut.isPending}
              className="flex-1"
            >
              <Lock className="mr-2 h-4 w-4" />
              {zMut.isPending ? "Generating…" : "Z report"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {!report ? (
        <Card>
          <CardContent className="py-10">
            <EmptyState
              icon={<BarChart3 className="h-7 w-7" />}
              title="No report yet"
              description="Enter a session ID and run an X or Z report to view the till summary."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Header / sales */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                {isZ ? <Lock className="h-4 w-4" /> : <FileText className="h-4 w-4" />}
                {isZ ? "Z Report — end of shift" : "X Report — mid-shift"}
                <Badge variant={isZ ? "default" : "secondary"} className="ml-2 uppercase">
                  {report.report_kind}
                </Badge>
              </CardTitle>
              <CardDescription>
                Register {report.register_id} · session {report.session_id}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm sm:grid-cols-3">
                <div>
                  <p className="text-muted-foreground">Opened</p>
                  <p>{fmtTs(report.opened_at)}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Closed</p>
                  <p>{fmtTs(report.closed_at)}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Generated</p>
                  <p>{fmtTs(report.generated_at)}</p>
                </div>
                {isZ && (
                  <div>
                    <p className="text-muted-foreground">Z printed</p>
                    <p>{fmtTs(report.z_report_printed_at)}</p>
                  </div>
                )}
              </div>

              <Separator />

              <div className="space-y-1.5">
                <StatRow label="Gross sales" value={fmtCents(report.gross_sales_cents, currency)} />
                <StatRow label="Discounts" value={`-${fmtCents(report.discount_cents, currency)}`} />
                <StatRow label="Net sales (pre-tax)" value={fmtCents(report.net_sales_cents, currency)} />
                <StatRow label="Tax" value={fmtCents(report.tax_cents, currency)} />
                <StatRow label="Refunds" value={`-${fmtCents(report.refund_total_cents, currency)}`} />
                <Separator className="my-1" />
                <StatRow label="Transactions settled" value={String(report.transaction_count)} bold />
                <StatRow label="Voids" value={String(report.void_count)} />
              </div>
            </CardContent>
          </Card>

          {/* Cash drawer */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Cash drawer</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              <StatRow label="Opening float" value={fmtCents(report.cash.opening_float_cents, currency)} />
              <StatRow label="Cash in" value={`+${fmtCents(report.cash.cash_in_cents, currency)}`} />
              <StatRow label="Change out" value={`-${fmtCents(report.cash.change_out_cents, currency)}`} />
              <Separator className="my-1" />
              <StatRow label="Expected cash" value={fmtCents(report.cash.expected_cash_cents, currency)} bold />
              {report.cash.counted_cash_cents != null ? (
                <>
                  <StatRow label="Counted cash" value={fmtCents(report.cash.counted_cash_cents, currency)} />
                  <StatRow
                    label="Over / short"
                    value={
                      (report.cash.over_short_cents ?? 0) >= 0
                        ? `+${fmtCents(report.cash.over_short_cents ?? 0, currency)}`
                        : `-${fmtCents(-(report.cash.over_short_cents ?? 0), currency)}`
                    }
                    bold
                  />
                </>
              ) : (
                <p className="pt-1 text-xs text-muted-foreground">
                  Counted cash appears after the session is closed (X report shows expected only).
                </p>
              )}
            </CardContent>
          </Card>

          {/* Tender breakdown */}
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-base">Tender breakdown</CardTitle>
            </CardHeader>
            <CardContent>
              {report.tender_breakdown.length === 0 ? (
                <p className="py-4 text-center text-sm text-muted-foreground">No tenders recorded.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tender</TableHead>
                      <TableHead className="text-right">Gross</TableHead>
                      <TableHead className="text-right">Refunds</TableHead>
                      <TableHead className="text-right">Net</TableHead>
                      <TableHead className="text-right">Txns</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {report.tender_breakdown.map((t) => (
                      <TableRow key={t.kind}>
                        <TableCell className="capitalize font-medium">{t.kind}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {fmtCents(t.gross_cents, currency)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {fmtCents(t.refund_cents, currency)}
                        </TableCell>
                        <TableCell className="text-right font-medium tabular-nums">
                          {fmtCents(t.net_cents, currency)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{t.transaction_count}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
