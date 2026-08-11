import { useMemo } from "react";
import type { Candle } from "@/api/endpoints/marketData";

interface CandleChartProps {
  bars: Candle[];
  scaler?: number;
  height?: number;
  /** Click anywhere on the chart to prefill the ticket at that price level. */
  onPriceClick?: (price: number) => void;
}

const UP = "#059669"; // emerald-600
const DOWN = "#e11d48"; // rose-600
const PAD_TOP = 8;
const PAD_BOTTOM = 8;
const PAD_LEFT = 8;
const PAD_RIGHT = 56;

const MAS = [
  { period: 7, color: "#f59e0b" }, // amber
  { period: 25, color: "#8b5cf6" }, // violet
  { period: 99, color: "#0ea5e9" }, // sky
];

/** Simple moving average over `vals`; the first (period-1) entries are null. */
function sma(vals: number[], period: number): (number | null)[] {
  const out: (number | null)[] = [];
  let sum = 0;
  for (let i = 0; i < vals.length; i++) {
    sum += vals[i]!;
    if (i >= period) sum -= vals[i - period]!;
    out.push(i >= period - 1 ? sum / period : null);
  }
  return out;
}

/** Hand-rolled SVG candlestick chart (auto-scaled) with MA overlays + click-to-trade. */
export default function CandleChart({ bars, scaler = 1, height = 320, onPriceClick }: CandleChartProps) {
  const width = 720;
  const layout = useMemo(() => {
    if (!bars.length) return null;
    const highs = bars.map((b) => b.high);
    const lows = bars.map((b) => b.low);
    let max = Math.max(...highs);
    let min = Math.min(...lows);
    if (max === min) {
      max += 1;
      min -= 1;
    }
    const range = max - min;
    const plotW = width - PAD_LEFT - PAD_RIGHT;
    const plotH = height - PAD_TOP - PAD_BOTTOM;
    const slot = plotW / bars.length;
    const bodyW = Math.max(1, Math.min(slot * 0.7, 14));

    const yOf = (v: number) => PAD_TOP + ((max - v) / range) * plotH;
    const xOf = (i: number) => PAD_LEFT + slot * i + slot / 2;

    const candles = bars.map((b, i) => {
      const cx = xOf(i);
      const up = b.close >= b.open;
      const openY = yOf(b.open);
      const closeY = yOf(b.close);
      const top = Math.min(openY, closeY);
      const bodyH = Math.max(1, Math.abs(closeY - openY));
      return { key: i, cx, highY: yOf(b.high), lowY: yOf(b.low), bodyX: cx - bodyW / 2, bodyY: top, bodyW, bodyH, color: up ? UP : DOWN };
    });

    const closes = bars.map((b) => b.close);
    const maLines = MAS.map((m) => {
      const s = sma(closes, m.period);
      const points = s
        .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${yOf(v).toFixed(1)}`))
        .filter((p): p is string => p !== null)
        .join(" ");
      return { period: m.period, color: m.color, points };
    }).filter((m) => m.points.length > 0);

    const ticks = 4;
    const labels = Array.from({ length: ticks + 1 }, (_, i) => {
      const v = max - (range * i) / ticks;
      return { y: yOf(v), value: v / (scaler || 1) };
    });

    return { candles, labels, maLines, max, range, plotH };
  }, [bars, height, scaler]);

  if (!layout) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        No candles available.
      </div>
    );
  }

  function handleClick(e: React.MouseEvent<SVGSVGElement>) {
    if (!onPriceClick || !layout) return;
    const rect = e.currentTarget.getBoundingClientRect();
    if (!rect.height) return;
    const yView = ((e.clientY - rect.top) / rect.height) * height;
    const price = layout.max - ((yView - PAD_TOP) / layout.plotH) * layout.range;
    if (Number.isFinite(price)) onPriceClick(Math.max(0, Math.round(price)));
  }

  return (
    <div>
      {layout.maLines.length > 0 && (
        <div className="mb-1 flex gap-3 text-[10px]">
          {layout.maLines.map((m) => (
            <span key={m.period} style={{ color: m.color }}>
              MA{m.period}
            </span>
          ))}
        </div>
      )}
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className={onPriceClick ? "w-full cursor-crosshair" : "w-full"}
        style={{ height }}
        preserveAspectRatio="none"
        role="img"
        aria-label="Candlestick chart"
        onClick={handleClick}
      >
        {layout.labels.map((l, i) => (
          <g key={`g${i}`}>
            <line x1={PAD_LEFT} x2={width - PAD_RIGHT} y1={l.y} y2={l.y} stroke="currentColor" strokeOpacity={0.1} />
            <text x={width - PAD_RIGHT + 4} y={l.y + 3} fontSize={10} fill="currentColor" fillOpacity={0.6}>
              {l.value.toLocaleString(undefined, { maximumFractionDigits: 2 })}
            </text>
          </g>
        ))}
        {layout.candles.map((c) => (
          <g key={c.key}>
            <line x1={c.cx} x2={c.cx} y1={c.highY} y2={c.lowY} stroke={c.color} strokeWidth={1} />
            <rect x={c.bodyX} y={c.bodyY} width={c.bodyW} height={c.bodyH} fill={c.color} />
          </g>
        ))}
        {layout.maLines.map((m) => (
          <polyline
            key={m.period}
            points={m.points}
            fill="none"
            stroke={m.color}
            strokeWidth={1.25}
            strokeOpacity={0.9}
            vectorEffect="non-scaling-stroke"
          />
        ))}
      </svg>
    </div>
  );
}
