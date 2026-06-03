import type { TrendPoint } from "@/api/types";

export interface VolumeChartProps {
  trends: TrendPoint[];
  granularity: "daily" | "weekly" | "monthly";
}

export default function VolumeChart({ trends, granularity }: VolumeChartProps) {
  const max = trends.length > 0 ? Math.max(...trends.map((t) => t.started), 1) : 1;
  return (
    <div data-testid="volume-chart" className="space-y-1">
      <div className="text-xs text-muted-foreground capitalize">{granularity} application volume</div>
      {trends.length === 0 && (
        <div className="text-sm text-muted-foreground py-4">No data for this period.</div>
      )}
      <div className="flex items-end gap-1 h-40">
        {trends.map((t) => (
          <div
            key={t.period}
            className="flex-1 flex flex-col items-center justify-end gap-1"
            title={`${t.period}: started ${t.started}, submitted ${t.submitted}, approved ${t.approved}, rejected ${t.rejected}`}
            data-testid={`volume-bar-${t.period}`}
          >
            <div className="text-[10px] tabular-nums">{t.started}</div>
            <div
              className="w-full bg-primary/70 rounded-t"
              style={{ height: `${Math.max(2, (t.started / max) * 100)}%` }}
            />
            <div className="text-[9px] text-muted-foreground rotate-0 truncate w-full text-center">
              {t.period.slice(5)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
