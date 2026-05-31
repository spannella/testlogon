import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { listAlerts, acknowledgeAlert } from "@/api/endpoints/accountantAgent";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { CostAlert } from "@/api/types";
import { formatCents } from "./OptimizationsPanel";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  warning: "bg-yellow-500 text-black",
  info: "bg-blue-500 text-white",
};

function AlertCard({ alert }: { alert: CostAlert }) {
  const qc = useQueryClient();
  const ack = useMutation({
    mutationFn: () => acknowledgeAlert(alert.alert_id),
    onSuccess: () => {
      toast.success("Alert acknowledged");
      qc.invalidateQueries({ queryKey: ["accountant", "alerts"] });
    },
  });
  return (
    <Card data-testid="alert-card">
      <CardContent className="space-y-2 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            <span
              className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${
                SEVERITY_BADGE[alert.severity] ?? "bg-gray-400 text-white"
              }`}
              data-testid={`alert-severity-${alert.severity}`}
            >
              {alert.severity}
            </span>
            <span className="font-semibold">{alert.title}</span>
          </div>
          {!alert.acknowledged && (
            <Button size="sm" variant="outline" onClick={() => ack.mutate()} data-testid="alert-ack">
              <CheckCircle2 className="mr-1 h-4 w-4" /> Acknowledge
            </Button>
          )}
          {alert.acknowledged && <Badge variant="secondary">Acknowledged</Badge>}
        </div>
        <p className="text-sm text-muted-foreground">{alert.message}</p>
        {alert.budget_limit_cents != null && (
          <p className="text-xs text-muted-foreground">
            Spent {formatCents(alert.current_spend_cents)} of {formatCents(alert.budget_limit_cents)}
          </p>
        )}
        {alert.auto_action_taken && (
          <Badge variant="destructive" data-testid="alert-auto-action">
            {alert.auto_action_taken}
          </Badge>
        )}
      </CardContent>
    </Card>
  );
}

export default function CostAlertsPage() {
  const [filter, setFilter] = useState<"unack" | "all">("unack");
  const { data, isLoading } = useQuery({
    queryKey: ["accountant", "alerts", filter],
    queryFn: () => listAlerts(filter === "unack" ? false : undefined),
    staleTime: 10_000,
  });
  const alerts = data?.alerts ?? [];
  return (
    <div className="space-y-4 p-4" data-testid="cost-alerts-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Cost Alerts</h1>
        <Select value={filter} onValueChange={(v) => setFilter(v as "unack" | "all")}>
          <SelectTrigger className="w-44" data-testid="alert-filter">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="unack">Unacknowledged</SelectItem>
            <SelectItem value="all">All</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {isLoading && <p className="text-sm text-muted-foreground">Loading alerts…</p>}
      {!isLoading && alerts.length === 0 && (
        <p className="text-sm text-muted-foreground" data-testid="alerts-empty">
          No alerts — your budgets are on track.
        </p>
      )}
      <div className="space-y-3">
        {alerts.map((a) => (
          <AlertCard key={a.alert_id} alert={a} />
        ))}
      </div>
    </div>
  );
}
