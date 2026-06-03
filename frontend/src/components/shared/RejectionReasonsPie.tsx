export interface RejectionReasonsPieProps {
  reasons: Record<string, number>;
}

const COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
  "#06b6d4",
  "#3b82f6",
  "#8b5cf6",
  "#ec4899",
  "#64748b",
  "#14b8a6",
];

export default function RejectionReasonsPie({ reasons }: RejectionReasonsPieProps) {
  const entries = Object.entries(reasons).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);

  if (total === 0) {
    return (
      <div className="text-sm text-muted-foreground py-4" data-testid="rejection-pie-empty">
        No rejections in this period.
      </div>
    );
  }

  // Build a conic-gradient donut.
  let acc = 0;
  const stops: string[] = [];
  entries.forEach(([, count], i) => {
    const start = (acc / total) * 100;
    acc += count;
    const end = (acc / total) * 100;
    const color = COLORS[i % COLORS.length];
    stops.push(`${color} ${start}% ${end}%`);
  });

  return (
    <div data-testid="rejection-pie" className="flex items-center gap-6">
      <div
        className="rounded-full shrink-0"
        style={{
          width: 120,
          height: 120,
          background: `conic-gradient(${stops.join(", ")})`,
          mask: "radial-gradient(circle 36px at center, transparent 98%, black 100%)",
          WebkitMask: "radial-gradient(circle 36px at center, transparent 98%, black 100%)",
        }}
      />
      <ul className="space-y-1 text-sm">
        {entries.map(([reason, count], i) => (
          <li key={reason} className="flex items-center gap-2" data-testid={`rejection-legend-${reason}`}>
            <span
              className="inline-block w-3 h-3 rounded-sm"
              style={{ background: COLORS[i % COLORS.length] }}
            />
            <span className="font-medium">{reason}</span>
            <span className="text-muted-foreground tabular-nums">
              {count} ({((count / total) * 100).toFixed(1)}%)
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
