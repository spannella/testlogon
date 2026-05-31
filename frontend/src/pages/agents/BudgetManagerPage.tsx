import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listBudgets,
  createBudget,
  updateBudget,
  deleteBudget,
} from "@/api/endpoints/accountantAgent";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, Trash2 } from "lucide-react";
import type { CostBudget, CostBudgetIn } from "@/api/types";
import { formatCents } from "./OptimizationsPanel";

function BudgetCard({ budget }: { budget: CostBudget }) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: () => deleteBudget(budget.budget_id),
    onSuccess: () => {
      toast.success("Budget deleted");
      qc.invalidateQueries({ queryKey: ["accountant", "budgets"] });
    },
  });
  const toggleAutoPause = useMutation({
    mutationFn: (next: boolean) => updateBudget(budget.budget_id, { auto_pause_on_exceed: next }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accountant", "budgets"] }),
  });
  // Utilization is shown relative to the limit; spend defaults to 0 here.
  const pct = 0;
  return (
    <Card data-testid="budget-card">
      <CardContent className="space-y-2 p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-semibold" data-testid="budget-name">
              {budget.name}
            </p>
            <p className="text-xs text-muted-foreground">
              {budget.scope}
              {budget.scope_ref ? ` · ${budget.scope_ref}` : ""} · {budget.period}
            </p>
          </div>
          <Button
            size="icon"
            variant="ghost"
            onClick={() => del.mutate()}
            data-testid="budget-delete"
            aria-label="Delete budget"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
        <Progress value={pct} />
        <p className="text-sm text-muted-foreground">
          {formatCents(0)} / {formatCents(budget.limit_cents)} (alert at {budget.alert_threshold_pct}%)
        </p>
        <div className="flex items-center gap-2">
          <Switch
            checked={budget.auto_pause_on_exceed}
            onCheckedChange={(v) => toggleAutoPause.mutate(v)}
            data-testid="budget-autopause"
          />
          <Label className="text-sm">Auto-pause on exceed</Label>
        </div>
      </CardContent>
    </Card>
  );
}

function CreateBudgetDialog() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [scope, setScope] = useState<CostBudgetIn["scope"]>("overall");
  const [scopeRef, setScopeRef] = useState("");
  const [period, setPeriod] = useState<CostBudgetIn["period"]>("daily");
  const [limitDollars, setLimitDollars] = useState("50");
  const [threshold, setThreshold] = useState("80");

  const create = useMutation({
    mutationFn: () =>
      createBudget({
        name,
        scope,
        scope_ref: scope === "overall" ? null : scopeRef,
        period,
        limit_cents: Math.round(parseFloat(limitDollars || "0") * 100),
        alert_threshold_pct: parseInt(threshold || "80", 10),
      }),
    onSuccess: () => {
      toast.success("Budget created");
      qc.invalidateQueries({ queryKey: ["accountant", "budgets"] });
      setOpen(false);
      setName("");
    },
    onError: () => toast.error("Failed to create budget"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button data-testid="create-budget-button">
          <Plus className="mr-1 h-4 w-4" /> New Budget
        </Button>
      </DialogTrigger>
      <DialogContent data-testid="budget-form-dialog">
        <DialogHeader>
          <DialogTitle>Create Budget</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label htmlFor="budget-name-input">Name</Label>
            <Input
              id="budget-name-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="budget-name-input"
            />
          </div>
          <div>
            <Label>Scope</Label>
            <Select value={scope} onValueChange={(v) => setScope(v as CostBudgetIn["scope"])}>
              <SelectTrigger data-testid="budget-scope-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="overall">Overall</SelectItem>
                <SelectItem value="agent_type">Agent Type</SelectItem>
                <SelectItem value="agent_instance">Agent Instance</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {scope !== "overall" && (
            <div>
              <Label htmlFor="budget-scope-ref">Scope Ref</Label>
              <Input
                id="budget-scope-ref"
                value={scopeRef}
                onChange={(e) => setScopeRef(e.target.value)}
                placeholder="e.g. coder"
                data-testid="budget-scope-ref"
              />
            </div>
          )}
          <div>
            <Label>Period</Label>
            <Select value={period} onValueChange={(v) => setPeriod(v as CostBudgetIn["period"])}>
              <SelectTrigger data-testid="budget-period-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label htmlFor="budget-limit">Limit ($)</Label>
              <Input
                id="budget-limit"
                type="number"
                value={limitDollars}
                onChange={(e) => setLimitDollars(e.target.value)}
                data-testid="budget-limit-input"
              />
            </div>
            <div>
              <Label htmlFor="budget-threshold">Alert %</Label>
              <Input
                id="budget-threshold"
                type="number"
                value={threshold}
                onChange={(e) => setThreshold(e.target.value)}
                data-testid="budget-threshold-input"
              />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => create.mutate()}
            disabled={!name || create.isPending}
            data-testid="budget-save-button"
          >
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function BudgetManagerPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["accountant", "budgets"],
    queryFn: listBudgets,
    staleTime: 10_000,
  });
  const budgets = data ?? [];
  return (
    <div className="space-y-4 p-4" data-testid="budget-manager-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Budget Manager</h1>
        <CreateBudgetDialog />
      </div>
      {isLoading && <p className="text-sm text-muted-foreground">Loading budgets…</p>}
      {!isLoading && budgets.length === 0 && (
        <p className="text-sm text-muted-foreground" data-testid="budgets-empty">
          No budgets yet. Create one to start tracking spend against a cap.
        </p>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        {budgets.map((b) => (
          <BudgetCard key={b.budget_id} budget={b} />
        ))}
      </div>
    </div>
  );
}
