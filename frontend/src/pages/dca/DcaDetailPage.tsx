import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  CalendarClock,
  ArrowLeft,
  Pause,
  Play,
  Ban,
  Zap,
  Wallet,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  useDcaPlans,
  useDcaHistory,
  usePauseDcaPlan,
  useResumeDcaPlan,
  useCancelDcaPlan,
  useRunDcaPlanNow,
} from "@/hooks/useDca";
import type { DcaPlan, DcaStatus } from "@/lib/dca";
import {
  formatCents,
  frequencyLabel,
  nextRun,
  upcomingRuns,
  budgetRemainingCents,
  estimatedRunsRemaining,
  budgetSpentFraction,
} from "@/lib/dca";
import { PendingBackend, ServerRunnerNote, targetKindLabel } from "./DcaShared";

const STATUS_VARIANT: Record<DcaStatus, "default" | "secondary" | "destructive" | "outline"> = {
  active: "default",
  paused: "secondary",
  completed: "outline",
  cancelled: "destructive",
};

function fmtTs(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return "—";
  return new Date(sec * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-medium tabular-nums">{value}</span>
    </div>
  );
}

export default function DcaDetailPage() {
  const { id } = useParams<{ id: string }>();
  const plansQ = useDcaPlans();
  const historyQ = useDcaHistory(id);
  const pause = usePauseDcaPlan();
  const resume = useResumeDcaPlan();
  const cancel = useCancelDcaPlan();
  const runNow = useRunDcaPlanNow(id);

  const [cancelOpen, setCancelOpen] = useState(false);
  const [runOpen, setRunOpen] = useState(false);

  const plan: DcaPlan | undefined = (plansQ.data?.plans ?? []).find((p) => p.plan_id === id);

  if (plansQ.isLoading) {
    return (
      <div className="mx-auto w-full max-w-3xl space-y-4 p-4 md:p-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (plansQ.isError) {
    return (
      <div className="mx-auto w-full max-w-3xl space-y-4 p-4 md:p-6">
        <Button asChild variant="ghost" size="sm">
          <Link to="/dca">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Link>
        </Button>
        <PendingBackend label="This recurring-buy plan" />
      </div>
    );
  }

  if (!plan) {
    return (
      <div className="mx-auto w-full max-w-3xl space-y-4 p-4 md:p-6">
        <Button asChild variant="ghost" size="sm">
          <Link to="/dca">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Link>
        </Button>
        <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
          This plan was not found. It may have been cancelled.
        </div>
      </div>
    );
  }

  const remaining = budgetRemainingCents(plan);
  const runsLeft = estimatedRunsRemaining(plan);
  const nextMs = plan.status === "active" ? nextRun(plan, Date.now()) : null;
  const upcoming = plan.status === "active" ? upcomingRuns(plan, Date.now(), 5) : [];
  const runs = historyQ.data?.runs ?? [];
  const isActive = plan.status === "active";
  const isPaused = plan.status === "paused";
  const isLive = isActive || isPaused;

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 md:p-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/dca">
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to recurring buys
        </Link>
      </Button>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <CalendarClock className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">{plan.target.label}</h1>
            <p className="text-sm text-muted-foreground">
              {targetKindLabel(plan.target.kind)} ·{" "}
              {frequencyLabel(plan.frequency, plan.day_of_week, plan.day_of_month)} ·{" "}
              {formatCents(plan.amount_cents)} per buy
            </p>
          </div>
        </div>
        <Badge variant={STATUS_VARIANT[plan.status] ?? "outline"}>{plan.status}</Badge>
      </div>

      <ServerRunnerNote />

      <div className="flex flex-wrap gap-2">
        {isActive && (
          <Button
            variant="outline"
            onClick={() => pause.mutate(plan.plan_id)}
            disabled={pause.isPending}
            data-testid="detail-pause"
          >
            <Pause className="mr-1.5 h-4 w-4" /> Pause
          </Button>
        )}
        {isPaused && (
          <Button
            variant="outline"
            onClick={() => resume.mutate(plan.plan_id)}
            disabled={resume.isPending}
            data-testid="detail-resume"
          >
            <Play className="mr-1.5 h-4 w-4" /> Resume
          </Button>
        )}
        {isLive && (
          <Button
            onClick={() => setRunOpen(true)}
            disabled={runNow.isPending}
            data-testid="detail-run-now"
          >
            <Zap className="mr-1.5 h-4 w-4" /> Buy now
          </Button>
        )}
        {isLive && (
          <Button variant="ghost" onClick={() => setCancelOpen(true)} className="text-destructive">
            <Ban className="mr-1.5 h-4 w-4" /> Cancel plan
          </Button>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Plan</CardTitle>
          </CardHeader>
          <CardContent className="divide-y">
            <InfoRow label="Amount per buy" value={formatCents(plan.amount_cents)} />
            <InfoRow
              label="Frequency"
              value={frequencyLabel(plan.frequency, plan.day_of_week, plan.day_of_month)}
            />
            <InfoRow label="Started" value={fmtTs(plan.start_ts)} />
            <InfoRow label="Ends" value={plan.end_ts ? fmtTs(plan.end_ts) : "No end"} />
            <InfoRow
              label="Next run"
              value={nextMs != null ? fmtTs(Math.floor(nextMs / 1000)) : "—"}
            />
            <InfoRow
              label="Funding"
              value={
                <span className="inline-flex items-center gap-1">
                  <Wallet className="h-3.5 w-3.5" /> USD cash wallet
                </span>
              }
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Progress</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <InfoRow label="Buys executed" value={plan.buys_count} />
            <InfoRow label="Total spent" value={formatCents(plan.spent_cents)} />
            {plan.total_budget_cents != null && plan.total_budget_cents > 0 ? (
              <>
                <InfoRow label="Total budget" value={formatCents(plan.total_budget_cents)} />
                <InfoRow label="Remaining" value={formatCents(remaining ?? 0)} />
                <InfoRow
                  label="Est. buys left"
                  value={runsLeft != null ? runsLeft : "—"}
                />
                <div className="pt-1">
                  <Progress value={Math.round(budgetSpentFraction(plan) * 100)} className="h-2" />
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No budget cap — this plan runs until cancelled.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {upcoming.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Upcoming runs</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-1 text-sm">
              {upcoming.map((ms, i) => (
                <li key={ms} className="flex items-center justify-between tabular-nums">
                  <span>
                    {i + 1}. {fmtTs(Math.floor(ms / 1000))}
                  </span>
                  <span className="text-muted-foreground">{formatCents(plan.amount_cents)}</span>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Execution history</CardTitle>
        </CardHeader>
        <CardContent>
          {historyQ.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : historyQ.isError ? (
            <PendingBackend label="Execution history" />
          ) : runs.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              No buys have run yet. The server-side runner records each execution here.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead className="text-right">Amount</TableHead>
                  <TableHead className="text-right">Filled qty</TableHead>
                  <TableHead className="text-right">Price</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((r, i) => (
                  <TableRow key={`${r.ts}-${i}`} data-testid="dca-run-row">
                    <TableCell className="text-sm tabular-nums">{fmtTs(r.ts)}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(r.amount_cents)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.filled_qty != null ? r.filled_qty : "—"}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.price != null ? formatCents(r.price) : "—"}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          r.status === "filled"
                            ? "default"
                            : r.status === "failed"
                              ? "destructive"
                              : "secondary"
                        }
                      >
                        {r.status}
                      </Badge>
                      {r.note ? (
                        <span className="ml-2 text-xs text-muted-foreground">{r.note}</span>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={runOpen}
        onOpenChange={setRunOpen}
        title="Buy now?"
        description={`This executes one ${formatCents(
          plan.amount_cents,
        )} buy of ${plan.target.label} immediately, debiting your USD cash wallet, in addition to the scheduled runs.`}
        confirmLabel="Buy now"
        loading={runNow.isPending}
        onConfirm={() =>
          runNow.mutate(undefined, {
            onSuccess: () => toast.success("Buy queued."),
            onSettled: () => setRunOpen(false),
          })
        }
      />

      <ConfirmDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        title="Cancel this recurring buy?"
        description={`This permanently stops the ${formatCents(
          plan.amount_cents,
        )} ${plan.frequency} buy of ${plan.target.label}. Buys already executed are unaffected.`}
        variant="danger"
        confirmLabel="Cancel plan"
        cancelLabel="Keep plan"
        loading={cancel.isPending}
        onConfirm={() =>
          cancel.mutate(plan.plan_id, { onSettled: () => setCancelOpen(false) })
        }
      />
    </div>
  );
}
