import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Receipt } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { EmptyState } from "@/components/shared/EmptyState";
import { ApiError } from "@/api/client";
import {
  approvePayrollRun,
  createPayrollRun,
  getPayrollRunLines,
  listPayrollRuns,
  postPayrollRun,
  type PayrollRun,
  type PayrollRunStatus,
} from "@/api/endpoints/hr";
import { dateInputToTs, fmtCents, fmtDate, fmtDateTime, isFeatureDisabled } from "./hrShared";

const STATUS_FILTERS: Array<{ label: string; value: string }> = [
  { label: "All statuses", value: "" },
  { label: "Draft", value: "DRAFT" },
  { label: "Approved", value: "APPROVED" },
  { label: "Posted", value: "POSTED" },
];

function statusBadge(status: PayrollRunStatus) {
  const variant =
    status === "DRAFT" ? "outline" : status === "APPROVED" ? "warning" : "success";
  return <Badge variant={variant as never}>{status}</Badge>;
}

const todayInput = () => new Date().toISOString().slice(0, 10);

export function PayrollPanel({ onDisabled }: { onDisabled: () => void }) {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [periodStart, setPeriodStart] = useState(todayInput());
  const [periodEnd, setPeriodEnd] = useState(todayInput());
  const [currency, setCurrency] = useState("USD");
  const [linesFor, setLinesFor] = useState<PayrollRun | null>(null);

  const runsQuery = useQuery({
    queryKey: ["hr", "payroll", { statusFilter }],
    queryFn: () => listPayrollRuns({ status: statusFilter || undefined, limit: 100 }),
    retry: false,
  });

  if (runsQuery.isError && isFeatureDisabled(runsQuery.error)) {
    onDisabled();
  }

  const linesQuery = useQuery({
    queryKey: ["hr", "payroll", "lines", linesFor?.payroll_run_id],
    queryFn: () => getPayrollRunLines(linesFor!.payroll_run_id),
    enabled: !!linesFor,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createPayrollRun({
        period_start: dateInputToTs(periodStart),
        period_end: dateInputToTs(periodEnd),
        currency: currency.trim().toLowerCase(),
      }),
    onSuccess: () => {
      toast.success("Payroll run created");
      setCreateOpen(false);
      qc.invalidateQueries({ queryKey: ["hr", "payroll"] });
    },
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.detail : "Failed to create payroll run"),
  });

  const approveMut = useMutation({
    mutationFn: (id: string) => approvePayrollRun(id),
    onSuccess: () => {
      toast.success("Payroll run approved");
      qc.invalidateQueries({ queryKey: ["hr", "payroll"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to approve"),
  });

  const postMut = useMutation({
    mutationFn: (id: string) => postPayrollRun(id),
    onSuccess: () => {
      toast.success("Payroll run posted");
      qc.invalidateQueries({ queryKey: ["hr", "payroll"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to post"),
  });

  const runs: PayrollRun[] = runsQuery.data?.items ?? [];
  const lines = linesQuery.data?.lines ?? [];
  const linesTotal = lines.reduce((sum, l) => sum + (l.gross_cents || 0), 0);
  const linesCurrency = lines[0]?.currency || "USD";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <Select
          value={statusFilter || "__all__"}
          onValueChange={(v) => setStatusFilter(v === "__all__" ? "" : v)}
        >
          <SelectTrigger className="w-48" aria-label="Filter payroll runs by status">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_FILTERS.map((f) => (
              <SelectItem key={f.value || "all"} value={f.value || "__all__"}>
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New payroll run
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {runsQuery.isLoading ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading payroll runs…</div>
          ) : runs.length === 0 ? (
            <EmptyState
              icon={<Receipt className="h-10 w-10" />}
              title="No payroll runs"
              description="Create a payroll run for a pay period to begin the approve → post workflow."
              action={{ label: "New payroll run", onClick: () => setCreateOpen(true) }}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Period</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Approved by</TableHead>
                  <TableHead>Posted</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((r) => (
                  <TableRow key={r.payroll_run_id}>
                    <TableCell className="text-sm">
                      {fmtDate(r.period_start)} – {fmtDate(r.period_end)}
                    </TableCell>
                    <TableCell>{statusBadge(r.status)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {r.approved_by || "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {r.posted_at ? fmtDateTime(r.posted_at) : "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="ghost" onClick={() => setLinesFor(r)}>
                          Lines
                        </Button>
                        {r.status === "DRAFT" && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={approveMut.isPending}
                            onClick={() => approveMut.mutate(r.payroll_run_id)}
                          >
                            Approve
                          </Button>
                        )}
                        {r.status === "APPROVED" && (
                          <Button
                            size="sm"
                            disabled={postMut.isPending}
                            onClick={() => postMut.mutate(r.payroll_run_id)}
                          >
                            Post
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New payroll run</DialogTitle>
            <DialogDescription>
              Generates draft pay lines for active employments in this period.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="pr-start">Period start</Label>
                <Input
                  id="pr-start"
                  type="date"
                  value={periodStart}
                  onChange={(e) => setPeriodStart(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="pr-end">Period end</Label>
                <Input
                  id="pr-end"
                  type="date"
                  value={periodEnd}
                  onChange={(e) => setPeriodEnd(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pr-currency">Currency</Label>
              <Input
                id="pr-currency"
                value={currency}
                maxLength={3}
                onChange={(e) => setCurrency(e.target.value.toUpperCase())}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!periodStart || !periodEnd || createMut.isPending}
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Lines dialog */}
      <Dialog open={!!linesFor} onOpenChange={(o) => !o && setLinesFor(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Payroll lines</DialogTitle>
            <DialogDescription>
              {linesFor && (
                <>
                  Period {fmtDate(linesFor.period_start)} – {fmtDate(linesFor.period_end)} ·{" "}
                  {linesFor.status}
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          {linesQuery.isLoading ? (
            <div className="p-6 text-center text-sm text-muted-foreground">Loading lines…</div>
          ) : lines.length === 0 ? (
            <div className="p-6 text-center text-sm text-muted-foreground">
              No pay lines for this run.
            </div>
          ) : (
            <div className="space-y-3">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Party</TableHead>
                    <TableHead>Employment</TableHead>
                    <TableHead className="text-right">Gross</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {lines.map((l) => (
                    <TableRow key={l.employment_id}>
                      <TableCell className="font-mono text-xs">{l.party_id || "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{l.employment_id}</TableCell>
                      <TableCell className="text-right font-medium">
                        {fmtCents(l.gross_cents, l.currency)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="flex items-center justify-between border-t pt-3 text-sm">
                <span className="text-muted-foreground">
                  {lines.length} line{lines.length === 1 ? "" : "s"}
                </span>
                <span className="font-semibold">{fmtCents(linesTotal, linesCurrency)}</span>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setLinesFor(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
