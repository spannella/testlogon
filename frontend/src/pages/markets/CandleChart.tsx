import { useMemo } from "react";
import type { Candle } from "@/api/endpoints/marketData";

interface CandleChartProps {
  bars: Candle[];
  scaler?: number;
  height?: number;
}

const UP = "#059669"; // emerald-600
const DOWN = "#e11d48"; // rose-600
const PAD_TOP = 8;
const PAD_BOTTOM = 8;
const PAD_LEFT = 8;
const PAD_RIGHT = 56;

/** Hand-rolled SVG candlestick chart (auto-scaled, green up / red down). */
export default function CandleChart({ bars, scaler = 1, height = 320 }: CandleChartProps) {
  const width = 720;
  const layout = useMemo(() => {
    if (!bars.length) return null;
    const highs = bars.map((b) => b.high);
    const lows = bars.map((b) => b.low);
    let max = Math.max(...highs);
    let min = Math.min(...lows);
    if (max === min) {
      // Avoid a zero-height range.
      max += 1;
      min -= 1;
    }
    const range = max - min;
    const plotW = width - PAD_LEFT - PAD_RIGHT;
    const plotH = height - PAD_TOP - PAD_BOTTOM;
    const slot = plotW / bars.length;
    const bodyW = Math.max(1, Math.min(slot * 0.7, 14));

    const yOf = (v: number) => PAD_TOP + (max - v) / range * plotH;

    const candles = bars.map((b, i) => {
      const cx = PAD_LEFT + slot * i + slot / 2;
      const up = b.close >= b.open;
      const openY = yOf(b.open);
      const closeY = yOf(b.close);
      const top = Math.min(openY, closeY);
      const bodyH = Math.max(1, Math.abs(closeY - openY));
      return {
        key: i,
        cx,
        highY: yOf(b.high),
        lowY: yOf(b.low),
        bodyX: cx - bodyW / 2,
        bodyY: top,
        bodyW,
        bodyH,
        color: up ? UP : DOWN,
      };
    });

    // A handful of price gridlines/labels on the right axis.
    const ticks = 4;
    const labels = Array.from({ length: ticks + 1 }, (_, i) => {
      const v = max - (range * i) / ticks;
      return { y: yOf(v), value: (v / (scaler || 1)) };
    });

    return { candles, labels };
  }, [bars, height, scaler]);

  if (!layout) {
    return (
      <div
        className="flex items-center justify-center text-sm text-muted-foreground"
        style={{ height }}
      >
        No candles available.
      </div>
    );
  }

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full"
      style={{ height }}
      preserveAspectRatio="none"
      role="img"
      aria-label="Candlestick chart"
    >
      {layout.labels.map((l, i) => (
        <g key={`g${i}`}>
          <line
            x1={PAD_LEFT}
            x2={width - PAD_RIGHT}
            y1={l.y}
            y2={l.y}
            stroke="currentColor"
            strokeOpacity={0.1}
          />
          <text
            x={width - PAD_RIGHT + 4}
            y={l.y + 3}
            fontSize={10}
            fill="currentColor"
            fillOpacity={0.6}
          >
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
    </svg>
  );
}
