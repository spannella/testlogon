import type { HistogramBucket, Percentiles } from "@/api/types";

export interface ProcessingTimeHistogramProps {
  histogram: HistogramBucket[];
  percentiles: Percentiles;
}

export default function ProcessingTimeHistogram({
  histogram,
  percentiles,
}: ProcessingTimeHistogramProps) {
  const max = histogram.length > 0 ? Math.max(...histogram.map((b) => b.count), 1) : 1;
  return (
    <div data-testid="processing-histogram" className="space-y-2">
      <div className="flex items-end gap-1 h-40">
        {histogram.map((b) => (
          <div
            key={b.bucket_label}
            className="flex-1 flex flex-col items-center justify-end gap-1"
            title={`${b.bucket_label}: ${b.count}`}
            data-testid={`hist-bucket-${b.bucket_label}`}
          >
            <div className="text-[10px] tabular-nums">{b.count}</div>
            <div
              className="w-full bg-emerald-500/70 rounded-t"
              style={{ height: `${Math.max(2, (b.count / max) * 100)}%` }}
            />
            <div className="text-[9px] text-muted-foreground truncate w-full text-center">
              {b.bucket_label}
            </div>
          </div>
        ))}
      </div>
      <div className="flex gap-4 text-xs text-muted-foreground" data-testid="histogram-percentiles">
        <span>p50: {percentiles.p50}h</span>
        <span>p75: {percentiles.p75}h</span>
        <span>p90: {percentiles.p90}h</span>
        <span>p99: {percentiles.p99}h</span>
      </div>
    </div>
  );
}
