import type { FunnelStep } from "@/api/types";

export interface FunnelChartProps {
  funnel: FunnelStep[];
  conversionRate: number;
}

const STEP_LABELS: Record<string, string> = {
  started: "Started",
  docs_uploaded: "Docs Uploaded",
  submitted: "Submitted",
  under_review: "Under Review",
  approved: "Approved",
};

export default function FunnelChart({ funnel, conversionRate }: FunnelChartProps) {
  const max = funnel.length > 0 ? Math.max(...funnel.map((s) => s.count), 1) : 1;
  return (
    <div data-testid="funnel-chart" className="space-y-2">
      {funnel.map((step, i) => (
        <div key={step.step} className="space-y-1">
          {i > 0 && step.drop_off_count > 0 && (
            <div className="text-xs text-red-600 pl-2" data-testid={`funnel-dropoff-${step.step}`}>
              ↓ -{step.drop_off_count} ({step.drop_off_pct}% drop-off)
            </div>
          )}
          <div className="flex items-center gap-3">
            <div className="w-32 shrink-0 text-sm font-medium" data-testid={`funnel-label-${step.step}`}>
              {STEP_LABELS[step.step] ?? step.step}
            </div>
            <div className="flex-1 bg-muted rounded h-7 overflow-hidden">
              <div
                className="h-7 bg-primary/80 rounded flex items-center px-2 text-xs text-primary-foreground"
                style={{ width: `${Math.max(2, (step.count / max) * 100)}%` }}
              >
                {step.count}
              </div>
            </div>
            <div className="w-16 shrink-0 text-right text-sm tabular-nums">
              {step.percentage}%
            </div>
          </div>
        </div>
      ))}
      <div className="pt-2 text-sm" data-testid="funnel-conversion-rate">
        Overall conversion rate:{" "}
        <span className="font-semibold">{(conversionRate * 100).toFixed(1)}%</span>
      </div>
    </div>
  );
}
