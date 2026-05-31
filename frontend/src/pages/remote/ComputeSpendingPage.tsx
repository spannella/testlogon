import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getSpending,
  getResources,
  getHistory,
  getBudget,
  setBudget,
} from "@/api/endpoints/computeBilling";
import type {
  SpendingSummaryOut,
  ResourceBreakdownOut,
  BillingLedgerOut,
  BudgetOut,
  ResourceBreakdownEntry,
  BillingLedgerEntry,
} from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Receipt, Server, Container, DollarSign } from "lucide-react";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatMinutes(minutes: number): string {
  if (minutes < 60) return `${minutes.toFixed(1)} min`;
  const hours = minutes / 60;
  return `${hours.toFixed(1)} hr`;
}

function BudgetMeter({
  totalCents,
  budgetCents,
  thresholds,
}: {
  totalCents: number;
  budgetCents: number;
  thresholds: number[];
}) {
  const pct = budgetCents > 0 ? Math.min((totalCents / budgetCents) * 100, 100) : 0;
  const barColor = pct >= 100 ? "bg-red-500" : pct >= 80 ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span>{formatCents(totalCents)} spent</span>
        <span>of {formatCents(budgetCents)} budget</span>
      </div>
      <div className="relative h-4 w-full rounded-full bg-muted overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${barColor}`}
          style={{ width: `${pct}%` }}
          data-testid="budget-meter-bar"
        />
        {thresholds.map((t) => (
          <div
            key={t}
            className="absolute top-0 h-full w-0.5 bg-foreground/30"
            style={{ left: `${t}%` }}
          />
        ))}
      </div>
      <p className="text-xs text-muted-foreground text-right" data-testid="budget-pct">
        {pct.toFixed(1)}% used
      </p>
    </div>
  );
}

function ResourceRow({ r }: { r: ResourceBreakdownEntry }) {
  return (
    <tr className="border-b" data-testid="resource-row">
      <td className="py-2 px-3">
        <div className="font-medium">{r.resource_label || r.resource_id}</div>
        <div className="text-xs text-muted-foreground">{r.resource_id}</div>
      </td>
      <td className="py-2 px-3">
        <Badge variant={r.resource_type === "ec2" ? "default" : "secondary"}>
          {r.resource_type === "ec2" ? (
            <><Server className="h-3 w-3 mr-1" /> EC2</>
          ) : (
            <><Container className="h-3 w-3 mr-1" /> K8s</>
          )}
        </Badge>
      </td>
      <td className="py-2 px-3 text-sm">{r.instance_type_or_preset}</td>
      <td className="py-2 px-3 text-sm font-medium">{formatCents(r.total_cents)}</td>
      <td className="py-2 px-3 text-sm">{formatMinutes(r.total_minutes)}</td>
    </tr>
  );
}

function LedgerRow({ e }: { e: BillingLedgerEntry }) {
  return (
    <tr className="border-b text-sm" data-testid="ledger-row">
      <td className="py-2 px-3">{new Date(e.created_at * 1000).toLocaleString()}</td>
      <td className="py-2 px-3">{e.resource_id}</td>
      <td className="py-2 px-3">
        <Badge variant="outline">{e.event}</Badge>
      </td>
      <td className="py-2 px-3 font-medium">{formatCents(e.amount_cents)}</td>
      <td className="py-2 px-3 text-muted-foreground">{formatCents(e.wallet_balance_after)}</td>
    </tr>
  );
}

export default function ComputeSpendingPage() {
  const [activeTab, setActiveTab] = useState<"breakdown" | "ledger" | "budget">("breakdown");
  const [budgetInput, setBudgetInput] = useState("");
  const queryClient = useQueryClient();

  const { data: spending } = useQuery<SpendingSummaryOut>({
    queryKey: ["compute-billing", "spending"],
    queryFn: () => getSpending(),
  });

  const { data: resources } = useQuery<ResourceBreakdownOut>({
    queryKey: ["compute-billing", "resources"],
    queryFn: () => getResources(),
  });

  const { data: ledger } = useQuery<BillingLedgerOut>({
    queryKey: ["compute-billing", "history"],
    queryFn: () => getHistory({ limit: 50 }),
    enabled: activeTab === "ledger",
  });

  const { data: budget } = useQuery<BudgetOut>({
    queryKey: ["compute-billing", "budget"],
    queryFn: () => getBudget(),
    enabled: activeTab === "budget",
  });

  const saveBudgetMut = useMutation({
    mutationFn: (cents: number) => setBudget({ budget_monthly_cents: cents }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["compute-billing"] });
    },
  });

  const tabClasses = (tab: string) =>
    `px-4 py-2 text-sm font-medium rounded-t-lg ${
      activeTab === tab
        ? "bg-background border border-b-0 border-border"
        : "text-muted-foreground hover:text-foreground"
    }`;

  return (
    <div className="container mx-auto max-w-5xl py-6 space-y-6">
      <div className="flex items-center gap-3">
        <Receipt className="h-6 w-6" />
        <h1 className="text-2xl font-bold" data-testid="page-title">Compute Spending</h1>
      </div>

      {/* Summary card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <DollarSign className="h-5 w-5" />
            {spending?.month || "Current Month"} Spending
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {spending && (
            <>
              <BudgetMeter
                totalCents={spending.total_cents}
                budgetCents={spending.budget_cents}
                thresholds={[50, 80, 100]}
              />
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center">
                  <p className="text-2xl font-bold" data-testid="total-spending">
                    {formatCents(spending.total_cents)}
                  </p>
                  <p className="text-xs text-muted-foreground">Total</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold" data-testid="ec2-spending">
                    {formatCents(spending.ec2_total_cents)}
                  </p>
                  <p className="text-xs text-muted-foreground">EC2</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold" data-testid="k8s-spending">
                    {formatCents(spending.k8s_total_cents)}
                  </p>
                  <p className="text-xs text-muted-foreground">K8s</p>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        <button className={tabClasses("breakdown")} onClick={() => setActiveTab("breakdown")}>
          Breakdown
        </button>
        <button className={tabClasses("ledger")} onClick={() => setActiveTab("ledger")}>
          Ledger
        </button>
        <button className={tabClasses("budget")} onClick={() => setActiveTab("budget")}>
          Budget
        </button>
      </div>

      {/* Tab content */}
      {activeTab === "breakdown" && (
        <Card>
          <CardContent className="pt-4">
            {resources && resources.resources.length > 0 ? (
              <table className="w-full" data-testid="resource-table">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="py-2 px-3">Resource</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Instance</th>
                    <th className="py-2 px-3">Cost</th>
                    <th className="py-2 px-3">Runtime</th>
                  </tr>
                </thead>
                <tbody>
                  {resources.resources.map((r) => (
                    <ResourceRow key={r.resource_id} r={r} />
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No compute resources billed this month.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "ledger" && (
        <Card>
          <CardContent className="pt-4">
            {ledger && ledger.entries.length > 0 ? (
              <table className="w-full" data-testid="ledger-table">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="py-2 px-3">Time</th>
                    <th className="py-2 px-3">Resource</th>
                    <th className="py-2 px-3">Event</th>
                    <th className="py-2 px-3">Amount</th>
                    <th className="py-2 px-3">Balance After</th>
                  </tr>
                </thead>
                <tbody>
                  {ledger.entries.map((e) => (
                    <LedgerRow key={e.entry_id} e={e} />
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No billing entries yet.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "budget" && budget && (
        <Card>
          <CardHeader>
            <CardTitle>Budget Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm text-muted-foreground mb-1">Current monthly budget</p>
              <p className="text-xl font-bold" data-testid="budget-amount">
                {formatCents(budget.budget_monthly_cents)}
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground mb-1">Current month spending</p>
              <p className="text-lg" data-testid="budget-current-spending">
                {formatCents(budget.current_month_total_cents)} ({budget.current_month_pct.toFixed(1)}%)
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground mb-1">Alert thresholds</p>
              <div className="flex gap-2">
                {budget.alert_thresholds.map((t) => (
                  <Badge key={t} variant="outline">{t}%</Badge>
                ))}
              </div>
            </div>
            <div className="flex gap-2 items-end pt-4 border-t">
              <div className="flex-1">
                <label className="text-sm text-muted-foreground">New budget (cents)</label>
                <Input
                  type="number"
                  min={100}
                  max={1000000}
                  value={budgetInput}
                  onChange={(e) => setBudgetInput(e.target.value)}
                  placeholder="e.g. 5000"
                  data-testid="budget-input"
                />
              </div>
              <Button
                onClick={() => {
                  const cents = parseInt(budgetInput, 10);
                  if (cents >= 100 && cents <= 1000000) {
                    saveBudgetMut.mutate(cents);
                    setBudgetInput("");
                  }
                }}
                disabled={saveBudgetMut.isPending}
                data-testid="save-budget-btn"
              >
                Save Budget
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
