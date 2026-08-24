import { useState } from "react";
import { Link } from "react-router-dom";
import { CalendarClock, Plus, Pause, Play, Ban, Wallet } from "lucide-react";
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
  usePauseDcaPlan,
  useResumeDcaPlan,
  useCancelDcaPlan,
} from "@/hooks/useDca";
import type { DcaPlan, DcaStatus } from "@/lib/dca";
import {
  formatCents,
  frequencyLabel,
  nextRun,
  budgetRemainingCents,
  budgetSpentFraction,
} from "@/lib/dca";
import { PendingBackend, ServerRunnerNote, targetKindLabel } from "./DcaShared";

const STATUS_VARIANT: Record<DcaStatus, "default" | "secondary" | "destructive" | "outline"> = {
  active: "default",
  paused: "secondary",
  completed: "outline",
  cancelled: "destructive",
};

function StatusBadge({ status }: { status: DcaStatus }) {
  return <Badge variant={STATUS_VARIANT[status] ?? "outline"}>{status}</Badge>;
}

function nextRunLabel(plan: DcaPlan): string {
  if (plan.status !== "active") return "—";
  const ms = nextRun(plan, Date.now());
  if (ms == null) return "—";
  return new Date(ms).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function BudgetCell({ plan }: { plan: DcaPlan }) {
  const remaining = budgetRemainingCents(plan);
  if (remaining == null) {
    return <span className="text-muted-foreground">Uncapped · {formatCents(plan.spent_cents)} spent</span>;
  }
  const pct = Math.round(budgetSpentFraction(plan) * 100);
  return (
    <div className="min-w-[8rem] space-y-1">
      <div className="flex justify-between text-xs">
        <span>{formatCents(plan.spent_cents)}</span>
        <span className="text-muted-foreground">/ {formatCents(plan.total_budget_cents)}</span>
      </div>
      <Progress value={pct} className="h-1.5" />
    </div>
  );
}

export default function DcaPlansPage() {
  const plansQ = useDcaPlans();
  const pause = usePauseDcaPlan();
  const resume = useResumeDcaPlan();
  const cancel = useCancelDcaPlan();

  const [cancelTarget, setCancelTarget] = useState<DcaPlan | null>(null);

  const plans = plansQ.data?.plans ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <CalendarClock className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Recurring buys</h1>
            <p className="text-sm text-muted-foreground">
              Dollar-cost-average into a market, creator token, or strategy on a schedule — funded
              from your USD cash wallet.
            </p>
          </div>
        </div>
        <Button asChild data-testid="new-dca-cta">
          <Link to="/dca/new">
            <Plus className="mr-1.5 h-4 w-4" /> New recurring buy
          </Link>
        </Button>
      </div>

      <ServerRunnerNote />

      <p className="flex items-center gap-2 text-xs text-muted-foreground">
        <Wallet className="h-3.5 w-3.5" />
        Buys draw from your USD cash wallet.{" "}
        <Link to="/custody/cash" className="font-medium text-primary underline-offset-4 hover:underline">
          Add cash
        </Link>
      </p>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">My plans</CardTitle>
        </CardHeader>
        <CardContent>
          {plansQ.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : plansQ.isError ? (
            <PendingBackend label="Your recurring-buy plans" />
          ) : plans.length === 0 ? (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              You have no recurring buys yet.{" "}
              <Link
                to="/dca/new"
                className="font-medium text-primary underline-offset-4 hover:underline"
              >
                Create one
              </Link>
              .
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead className="text-right">Amount</TableHead>
                  <TableHead>Frequency</TableHead>
                  <TableHead>Next run</TableHead>
                  <TableHead>Budget</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-[9rem]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {plans.map((p) => (
                  <TableRow key={p.plan_id} data-testid="dca-plan-row">
                    <TableCell className="max-w-[14rem]">
                      <Link
                        to={`/dca/${encodeURIComponent(p.plan_id)}`}
                        className="block truncate font-medium hover:underline"
                      >
                        {p.target.label}
                      </Link>
                      <div className="text-xs text-muted-foreground">
                        {targetKindLabel(p.target.kind)}
                      </div>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(p.amount_cents)}
                    </TableCell>
                    <TableCell className="text-sm">
                      {frequencyLabel(p.frequency, p.day_of_week, p.day_of_month)}
                    </TableCell>
                    <TableCell className="text-sm tabular-nums">{nextRunLabel(p)}</TableCell>
                    <TableCell>
                      <BudgetCell plan={p} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={p.status} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        {p.status === "active" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => pause.mutate(p.plan_id)}
                            disabled={pause.isPending}
                            title="Pause"
                            data-testid="dca-pause"
                          >
                            <Pause className="h-4 w-4" />
                          </Button>
                        )}
                        {p.status === "paused" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => resume.mutate(p.plan_id)}
                            disabled={resume.isPending}
                            title="Resume"
                            data-testid="dca-resume"
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                        )}
                        {(p.status === "active" || p.status === "paused") && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setCancelTarget(p)}
                            title="Cancel"
                            data-testid="dca-cancel"
                          >
                            <Ban className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                        <Button asChild variant="ghost" size="sm">
                          <Link to={`/dca/${encodeURIComponent(p.plan_id)}`}>Open</Link>
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={cancelTarget != null}
        onOpenChange={(o) => !o && setCancelTarget(null)}
        title="Cancel this recurring buy?"
        description={
          cancelTarget
            ? `This permanently stops the ${formatCents(
                cancelTarget.amount_cents,
              )} ${cancelTarget.frequency} buy of ${cancelTarget.target.label}. Buys already executed are unaffected.`
            : undefined
        }
        variant="danger"
        confirmLabel="Cancel plan"
        cancelLabel="Keep plan"
        loading={cancel.isPending}
        onConfirm={() => {
          if (cancelTarget) {
            cancel.mutate(cancelTarget.plan_id, { onSettled: () => setCancelTarget(null) });
          }
        }}
      />
    </div>
  );
}
