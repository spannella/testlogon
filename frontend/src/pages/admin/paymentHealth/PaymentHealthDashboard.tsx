import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  getAllProviderStatus,
  getProviderTimeline,
  getProviderErrors,
  getProviderConfig,
  getProviderUptime,
  updateProviderConfig,
  toggleProvider,
  getIncidents,
} from "@/api/endpoints/paymentProviderHealth";
import type { PaymentHealthProviderStatus } from "@/api/types";

const PROVIDERS = ["stripe", "paypal", "ccbill"];

function statusColor(status: string): string {
  if (status === "healthy") return "bg-green-500";
  if (status === "degraded") return "bg-yellow-500";
  return "bg-red-500";
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" {
  if (status === "healthy") return "default";
  if (status === "degraded") return "secondary";
  return "destructive";
}

function fmtTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function ProviderStatusCard({
  p,
  isRoot,
  onToggle,
}: {
  p: PaymentHealthProviderStatus;
  isRoot: boolean;
  onToggle: (p: PaymentHealthProviderStatus) => void;
}) {
  return (
    <Card data-testid={`provider-card-${p.provider}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="capitalize flex items-center gap-2">
            <span className={`inline-block h-3 w-3 rounded-full ${statusColor(p.status)}`} />
            {p.provider}
          </CardTitle>
          <Badge variant={statusBadgeVariant(p.status)} className="capitalize">
            {p.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-1 text-sm">
        <div className="flex justify-between">
          <span className="text-muted-foreground">Success rate</span>
          <span>{p.success_rate}%</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Avg latency</span>
          <span>{p.avg_latency_ms} ms</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">p95 latency</span>
          <span>{p.p95_latency_ms} ms</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Success / Failure</span>
          <span>
            {p.total_success} / {p.total_failure}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Enabled</span>
          <Badge variant={p.enabled ? "default" : "destructive"}>
            {p.enabled ? "on" : "off"}
          </Badge>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Last checked</span>
          <span>{fmtTime(p.last_check_at)}</span>
        </div>
        {isRoot && (
          <Button
            size="sm"
            variant="outline"
            className="mt-2 w-full"
            onClick={() => onToggle(p)}
            data-testid={`toggle-${p.provider}`}
          >
            {p.enabled ? "Disable provider" : "Enable provider"}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export default function PaymentHealthDashboard() {
  const accessToken = useAuthStore((s) => s.accessToken);
  const isRoot = getRoleFromAccessToken(accessToken) === "root";
  const queryClient = useQueryClient();

  const [selectedProvider, setSelectedProvider] = useState("stripe");
  const [toggleTarget, setToggleTarget] = useState<PaymentHealthProviderStatus | null>(null);
  const [toggleReason, setToggleReason] = useState("");
  const [errorThreshold, setErrorThreshold] = useState("");
  const [latencyThreshold, setLatencyThreshold] = useState("");

  const statusQuery = useQuery({
    queryKey: ["payment-health", "status"],
    queryFn: () => getAllProviderStatus(),
  });

  const timelineQuery = useQuery({
    queryKey: ["payment-health", "timeline", selectedProvider],
    queryFn: () => getProviderTimeline(selectedProvider, { hours: 24 }),
  });

  const errorsQuery = useQuery({
    queryKey: ["payment-health", "errors", selectedProvider],
    queryFn: () => getProviderErrors(selectedProvider, { hours: 24 }),
  });

  const incidentsQuery = useQuery({
    queryKey: ["payment-health", "incidents"],
    queryFn: () => getIncidents({ limit: 50 }),
  });

  const uptimeQuery = useQuery({
    queryKey: ["payment-health", "uptime", selectedProvider],
    queryFn: () => getProviderUptime(selectedProvider, { days: 30 }),
  });

  const configQuery = useQuery({
    queryKey: ["payment-health", "config", selectedProvider],
    queryFn: () => getProviderConfig(selectedProvider),
  });

  const toggleMut = useMutation({
    mutationFn: (vars: { provider: string; enabled: boolean; reason: string }) =>
      toggleProvider(vars.provider, { enabled: vars.enabled, reason: vars.reason }),
    onSuccess: () => {
      toast.success("Provider updated");
      setToggleTarget(null);
      setToggleReason("");
      queryClient.invalidateQueries({ queryKey: ["payment-health", "status"] });
      queryClient.invalidateQueries({ queryKey: ["payment-health", "config"] });
    },
    onError: () => toast.error("Failed to toggle provider"),
  });

  const configMut = useMutation({
    mutationFn: (vars: { provider: string; error?: number; latency?: number }) =>
      updateProviderConfig(vars.provider, {
        alert_error_rate_threshold: vars.error,
        alert_latency_threshold_ms: vars.latency,
      }),
    onSuccess: () => {
      toast.success("Alert thresholds saved");
      queryClient.invalidateQueries({ queryKey: ["payment-health", "config"] });
    },
    onError: () => toast.error("Failed to save thresholds"),
  });

  const providers = statusQuery.data ?? [];
  const timeline = timelineQuery.data?.data ?? [];
  const errorTypes = useMemo(
    () => Object.entries(errorsQuery.data?.error_types ?? {}),
    [errorsQuery.data],
  );
  const config = configQuery.data;

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">Payment Provider Health</h1>
        <p className="text-muted-foreground text-sm">
          Live health status, error rates, latency, and incident history for Stripe, PayPal, and CCBill.
        </p>
      </div>

      {/* Status cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {providers.map((p) => (
          <ProviderStatusCard
            key={p.provider}
            p={p}
            isRoot={isRoot}
            onToggle={(prov) => setToggleTarget(prov)}
          />
        ))}
      </div>

      {/* Provider selector */}
      <div className="flex items-center gap-3">
        <Label>Provider</Label>
        <Select value={selectedProvider} onValueChange={setSelectedProvider}>
          <SelectTrigger className="w-48" data-testid="provider-select">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PROVIDERS.map((p) => (
              <SelectItem key={p} value={p} className="capitalize">
                {p}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Tabs defaultValue="timeline">
        <TabsList>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="errors">Errors</TabsTrigger>
          <TabsTrigger value="incidents">Incidents</TabsTrigger>
          <TabsTrigger value="uptime">Uptime</TabsTrigger>
          {isRoot && <TabsTrigger value="config">Config</TabsTrigger>}
        </TabsList>

        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle>Health Timeline (24h)</CardTitle>
            </CardHeader>
            <CardContent>
              {timeline.length === 0 ? (
                <p className="text-sm text-muted-foreground">No data for this window.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Hour</TableHead>
                      <TableHead>Success</TableHead>
                      <TableHead>Failure</TableHead>
                      <TableHead>Avg latency</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {timeline.map((b) => (
                      <TableRow key={b.hour}>
                        <TableCell>{b.hour}</TableCell>
                        <TableCell>{b.success}</TableCell>
                        <TableCell>{b.failure}</TableCell>
                        <TableCell>{b.avg_latency_ms} ms</TableCell>
                        <TableCell className="capitalize">{b.status}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="errors">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Error Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                {errorTypes.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No errors recorded.</p>
                ) : (
                  <ul className="space-y-1 text-sm">
                    {errorTypes.map(([type, count]) => (
                      <li key={type} className="flex justify-between">
                        <span>{type}</span>
                        <span className="font-medium">{count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Recent Failures</CardTitle>
              </CardHeader>
              <CardContent>
                {(errorsQuery.data?.recent_failures ?? []).length === 0 ? (
                  <p className="text-sm text-muted-foreground">No recent failures.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>Error</TableHead>
                        <TableHead>Op</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(errorsQuery.data?.recent_failures ?? []).map((f, i) => (
                        <TableRow key={i}>
                          <TableCell>{fmtTime(f.ts)}</TableCell>
                          <TableCell>{f.error_type}</TableCell>
                          <TableCell>{f.op}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="incidents">
          <Card>
            <CardHeader>
              <CardTitle>Recent Incidents</CardTitle>
            </CardHeader>
            <CardContent>
              {(incidentsQuery.data ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">No incidents.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Provider</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Started</TableHead>
                      <TableHead>Ended</TableHead>
                      <TableHead>Affected</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(incidentsQuery.data ?? []).map((inc) => (
                      <TableRow key={inc.incident_id}>
                        <TableCell className="capitalize">{inc.provider}</TableCell>
                        <TableCell className="capitalize">{inc.status}</TableCell>
                        <TableCell>{fmtTime(inc.started_at)}</TableCell>
                        <TableCell>{inc.ended_at ? fmtTime(inc.ended_at) : "ongoing"}</TableCell>
                        <TableCell>{inc.affected_webhooks}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="uptime">
          <Card>
            <CardHeader>
              <CardTitle className="capitalize">{selectedProvider} Uptime (30d)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="text-4xl font-bold">
                {uptimeQuery.data?.uptime_pct ?? 100}%
              </div>
              <div className="text-sm text-muted-foreground">
                {uptimeQuery.data?.total_incidents ?? 0} incidents ·{" "}
                {uptimeQuery.data?.total_downtime_minutes ?? 0} min downtime
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {isRoot && (
          <TabsContent value="config">
            <Card>
              <CardHeader>
                <CardTitle>Alert Configuration</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 max-w-md">
                <div className="space-y-1">
                  <Label>Error rate threshold (bps)</Label>
                  <Input
                    type="number"
                    placeholder={String(config?.alert_error_rate_threshold ?? 500)}
                    value={errorThreshold}
                    onChange={(e) => setErrorThreshold(e.target.value)}
                    data-testid="error-threshold-input"
                  />
                </div>
                <div className="space-y-1">
                  <Label>Latency threshold (ms)</Label>
                  <Input
                    type="number"
                    placeholder={String(config?.alert_latency_threshold_ms ?? 500)}
                    value={latencyThreshold}
                    onChange={(e) => setLatencyThreshold(e.target.value)}
                    data-testid="latency-threshold-input"
                  />
                </div>
                <Button
                  onClick={() =>
                    configMut.mutate({
                      provider: selectedProvider,
                      error: errorThreshold ? Number(errorThreshold) : undefined,
                      latency: latencyThreshold ? Number(latencyThreshold) : undefined,
                    })
                  }
                  disabled={configMut.isPending}
                  data-testid="save-config"
                >
                  Save thresholds
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>

      {/* Toggle confirmation dialog */}
      <Dialog open={!!toggleTarget} onOpenChange={(o) => !o && setToggleTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="capitalize">
              {toggleTarget?.enabled ? "Disable" : "Enable"} {toggleTarget?.provider}
            </DialogTitle>
            <DialogDescription>
              {toggleTarget?.enabled
                ? "Disabling prevents new payment initiation through this provider. In-flight payments are unaffected."
                : "Re-enable this provider for new payment initiation."}
            </DialogDescription>
          </DialogHeader>
          {toggleTarget?.enabled && (
            <div className="space-y-1">
              <Label>Reason</Label>
              <Input
                value={toggleReason}
                onChange={(e) => setToggleReason(e.target.value)}
                placeholder="e.g. scheduled maintenance"
                data-testid="toggle-reason"
              />
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setToggleTarget(null)}>
              Cancel
            </Button>
            <Button
              variant={toggleTarget?.enabled ? "destructive" : "default"}
              onClick={() =>
                toggleTarget &&
                toggleMut.mutate({
                  provider: toggleTarget.provider,
                  enabled: !toggleTarget.enabled,
                  reason: toggleReason,
                })
              }
              disabled={toggleMut.isPending}
              data-testid="confirm-toggle"
            >
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
