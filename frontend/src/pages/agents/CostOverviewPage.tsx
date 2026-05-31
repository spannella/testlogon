import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  getDailyCostSummary,
  getCostTrends,
  listAlerts,
} from "@/api/endpoints/accountantAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DollarSign, AlertTriangle, BarChart3, Wallet, ListChecks } from "lucide-react";
import OptimizationsPanel, { formatCents } from "./OptimizationsPanel";

function todayStr(): string {
  return new Date().toISOString().slice(0, 10);
}

function SummaryCard({
  label,
  cents,
  testid,
}: {
  label: string;
  cents: number;
  testid: string;
}) {
  return (
    <Card data-testid={testid}>
      <CardContent className="p-4">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="mt-1 text-2xl font-bold">{formatCents(cents)}</p>
      </CardContent>
    </Card>
  );
}

export default function CostOverviewPage() {
  const today = todayStr();
  const { data: daily } = useQuery({
    queryKey: ["accountant", "daily", today],
    queryFn: () => getDailyCostSummary(today),
    staleTime: 15_000,
  });
  const { data: trends } = useQuery({
    queryKey: ["accountant", "trends", 30],
    queryFn: () => getCostTrends(30),
    staleTime: 30_000,
  });
  const { data: alertData } = useQuery({
    queryKey: ["accountant", "alerts", "unack"],
    queryFn: () => listAlerts(false),
    staleTime: 15_000,
  });

  const weekCents = useMemo(() => {
    const weeks = trends?.weeks ?? [];
    return weeks.length ? weeks[weeks.length - 1]!.total_cents : 0;
  }, [trends]);
  const monthCents = useMemo(
    () => (trends?.weeks ?? []).reduce((acc, w) => acc + w.total_cents, 0),
    [trends],
  );

  const alerts = alertData?.alerts ?? [];

  return (
    <div className="space-y-6 p-4" data-testid="cost-overview-page">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <Wallet className="h-6 w-6" /> Cost Overview
        </h1>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/costs/breakdown">
              <BarChart3 className="mr-1 h-4 w-4" /> Breakdown
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/costs/budgets">
              <DollarSign className="mr-1 h-4 w-4" /> Budgets
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/costs/alerts">
              <AlertTriangle className="mr-1 h-4 w-4" /> Alerts
            </Link>
          </Button>
        </div>
      </div>

      {alerts.length > 0 && (
        <Card className="border-l-4 border-l-red-500" data-testid="alert-banner">
          <CardContent className="flex items-center justify-between p-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <span className="font-medium">
                {alerts.length} unacknowledged cost alert{alerts.length === 1 ? "" : "s"}
              </span>
            </div>
            <Button asChild size="sm" variant="outline">
              <Link to="/agents/costs/alerts">View Alerts</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        <SummaryCard label="Today" cents={daily?.total_cents ?? 0} testid="summary-today" />
        <SummaryCard label="This Week" cents={weekCents} testid="summary-week" />
        <SummaryCard label="This Month" cents={monthCents} testid="summary-month" />
      </div>

      <Card data-testid="cost-area-chart">
        <CardHeader>
          <CardTitle className="text-base">Daily Cost (LLM vs Compute)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-1" style={{ height: 120 }}>
            {(trends?.weeks ?? []).flatMap((w) => [
              <div key={`${w.week_start}-llm`} className="flex flex-1 flex-col justify-end">
                <div
                  className="bg-blue-500"
                  style={{ height: `${Math.min(100, w.llm_cents / 100)}px` }}
                  title={`LLM ${formatCents(w.llm_cents)}`}
                />
                <div
                  className="bg-green-500"
                  style={{ height: `${Math.min(100, w.compute_cents / 100)}px` }}
                  title={`Compute ${formatCents(w.compute_cents)}`}
                />
              </div>,
            ])}
            {(trends?.weeks ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No cost data yet.</p>
            )}
          </div>
          <div className="mt-2 flex gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="inline-block h-3 w-3 bg-blue-500" /> LLM
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block h-3 w-3 bg-green-500" /> Compute
            </span>
          </div>
        </CardContent>
      </Card>

      <Card data-testid="agent-type-pie">
        <CardHeader>
          <CardTitle className="text-base">By Agent Type (today)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Object.entries(daily?.by_agent_type ?? {}).map(([type, cents]) => (
            <div key={type} className="flex items-center justify-between">
              <Badge variant="outline" className="flex items-center gap-1">
                <ListChecks className="h-3 w-3" /> {type}
              </Badge>
              <span className="text-sm font-medium">{formatCents(cents)}</span>
            </div>
          ))}
          {Object.keys(daily?.by_agent_type ?? {}).length === 0 && (
            <p className="text-sm text-muted-foreground">No spend recorded today.</p>
          )}
        </CardContent>
      </Card>

      <OptimizationsPanel />
    </div>
  );
}
