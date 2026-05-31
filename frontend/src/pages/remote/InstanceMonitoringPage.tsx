import { useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowLeft,
  Cpu,
  HardDrive,
  MemoryStick,
  Network,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  getInstanceHealth,
  getInstanceMetricSeries,
} from "@/api/endpoints/instanceMonitoring";
import type { InstanceHealthStatus, InstanceMetricPoint } from "@/api/types";

const HEALTH_BADGE: Record<
  InstanceHealthStatus,
  { label: string; variant: "default" | "secondary" | "destructive" | "outline"; className: string }
> = {
  healthy: { label: "Healthy", variant: "default", className: "bg-green-600 hover:bg-green-600" },
  warning: { label: "Warning", variant: "secondary", className: "bg-yellow-500 text-black hover:bg-yellow-500" },
  critical: { label: "Critical", variant: "destructive", className: "" },
  unknown: { label: "Unknown", variant: "outline", className: "" },
};

function MetricGauge({
  label,
  value,
  icon,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
}) {
  return (
    <Card data-testid={`metric-${label.toLowerCase()}`}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
          {icon}
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}%</div>
        <Progress value={value} className="mt-2 h-2" />
      </CardContent>
    </Card>
  );
}

function MiniSparkline({ points }: { points: InstanceMetricPoint[] }) {
  // points come newest-first; reverse for chronological left-to-right
  const series = useMemo(() => [...points].reverse(), [points]);
  if (series.length === 0) {
    return <p className="text-sm text-muted-foreground">No datapoints yet.</p>;
  }
  const w = 600;
  const h = 120;
  const max = 100;
  const step = series.length > 1 ? w / (series.length - 1) : w;
  const line = (key: keyof InstanceMetricPoint, color: string) => {
    const d = series
      .map((p, i) => {
        const x = i * step;
        const y = h - (Number(p[key]) / max) * h;
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
    return <path d={d} fill="none" stroke={color} strokeWidth={2} />;
  };
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className="w-full"
      role="img"
      aria-label="Resource utilization time series"
      data-testid="metrics-sparkline"
    >
      {line("cpu_pct", "#2563eb")}
      {line("mem_pct", "#16a34a")}
      {line("disk_pct", "#d97706")}
    </svg>
  );
}

export default function InstanceMonitoringPage() {
  const { instanceId = "" } = useParams<{ instanceId: string }>();
  const navigate = useNavigate();

  const health = useQuery({
    queryKey: ["instance-monitoring", "health", instanceId],
    queryFn: () => getInstanceHealth(instanceId),
    refetchInterval: 10_000,
    enabled: !!instanceId,
  });

  const series = useQuery({
    queryKey: ["instance-monitoring", "series", instanceId],
    queryFn: () => getInstanceMetricSeries(instanceId, { limit: 100 }),
    refetchInterval: 10_000,
    enabled: !!instanceId,
  });

  const status: InstanceHealthStatus = health.data?.health_status ?? "unknown";
  const badge = HEALTH_BADGE[status];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/remote/k8s")}
            data-testid="monitoring-back"
          >
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Button>
          <div>
            <h1 className="flex items-center gap-2 text-xl font-semibold">
              <Activity className="h-5 w-5" /> Instance Monitoring
            </h1>
            <p className="text-sm text-muted-foreground">{instanceId}</p>
          </div>
        </div>
        <Badge
          variant={badge.variant}
          className={badge.className}
          data-testid="health-badge"
        >
          {badge.label}
        </Badge>
      </div>

      {health.data && health.data.reasons.length > 0 && (
        <Card>
          <CardContent className="pt-4">
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
              {health.data.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricGauge
          label="CPU"
          value={health.data?.cpu_pct ?? 0}
          icon={<Cpu className="h-4 w-4" />}
        />
        <MetricGauge
          label="Memory"
          value={health.data?.mem_pct ?? 0}
          icon={<MemoryStick className="h-4 w-4" />}
        />
        <MetricGauge
          label="Disk"
          value={health.data?.disk_pct ?? 0}
          icon={<HardDrive className="h-4 w-4" />}
        />
        <Card data-testid="metric-network">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <Network className="h-4 w-4" />
              Network
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            <div>&darr; {series.data?.points[0]?.net_in_kbps ?? 0} kbps</div>
            <div>&uarr; {series.data?.points[0]?.net_out_kbps ?? 0} kbps</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Resource Utilization</CardTitle>
        </CardHeader>
        <CardContent>
          <MiniSparkline points={series.data?.points ?? []} />
          <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full bg-[#2563eb]" /> CPU
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full bg-[#16a34a]" /> Memory
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full bg-[#d97706]" /> Disk
            </span>
            <span className="ml-auto" data-testid="datapoint-count">
              {health.data?.datapoints ?? 0} datapoints
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
