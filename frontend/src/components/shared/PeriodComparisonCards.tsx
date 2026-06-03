import type { AnalyticsSnapshot, Deltas } from "@/api/types";

export interface PeriodComparisonCardsProps {
  current: AnalyticsSnapshot;
  previous: AnalyticsSnapshot;
  deltas: Deltas;
}

function DeltaArrow({ value, goodWhenUp = true }: { value: number; goodWhenUp?: boolean }) {
  if (value === 0) return <span className="text-muted-foreground">→ 0</span>;
  const up = value > 0;
  const good = up === goodWhenUp;
  return (
    <span className={good ? "text-green-600" : "text-red-600"}>
      {up ? "▲" : "▼"} {Math.abs(value)}
    </span>
  );
}

export default function PeriodComparisonCards({
  current,
  previous,
  deltas,
}: PeriodComparisonCardsProps) {
  const cards = [
    {
      label: "Total Applications",
      cur: current.total_applications,
      prev: previous.total_applications,
      delta: <DeltaArrow value={deltas.volume_delta} goodWhenUp />,
      testid: "compare-volume",
    },
    {
      label: "Approved",
      cur: current.approved_count,
      prev: previous.approved_count,
      delta: <DeltaArrow value={deltas.approved_delta} goodWhenUp />,
      testid: "compare-approved",
    },
    {
      label: "Rejected",
      cur: current.rejected_count,
      prev: previous.rejected_count,
      delta: <DeltaArrow value={deltas.rejected_delta} goodWhenUp={false} />,
      testid: "compare-rejected",
    },
    {
      label: "Conversion Rate",
      cur: `${(current.conversion_rate * 100).toFixed(1)}%`,
      prev: `${(previous.conversion_rate * 100).toFixed(1)}%`,
      delta: <DeltaArrow value={Number((deltas.conversion_rate_delta * 100).toFixed(1))} goodWhenUp />,
      testid: "compare-conversion",
    },
    {
      label: "Avg Processing (h)",
      cur: current.avg_processing_hours,
      prev: previous.avg_processing_hours,
      delta: <DeltaArrow value={deltas.avg_processing_hours_delta} goodWhenUp={false} />,
      testid: "compare-processing",
    },
  ];

  return (
    <div
      data-testid="period-comparison-cards"
      className="grid grid-cols-2 md:grid-cols-5 gap-3"
    >
      {cards.map((c) => (
        <div key={c.label} className="rounded-lg border p-3" data-testid={c.testid}>
          <div className="text-xs text-muted-foreground">{c.label}</div>
          <div className="text-xl font-semibold">{c.cur}</div>
          <div className="text-xs text-muted-foreground">prev: {c.prev}</div>
          <div className="text-sm">{c.delta}</div>
        </div>
      ))}
    </div>
  );
}
