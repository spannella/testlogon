import { useMemo, useState } from "react";
import type { Candle } from "@/api/endpoints/marketData";
import { cn } from "@/lib/utils";

interface CandleChartProps {
  bars: Candle[];
  scaler?: number;
  height?: number;
  /** Click anywhere on the chart to prefill the ticket at that price level. */
  onPriceClick?: (price: number) => void;
}

const UP = "#059669"; // emerald-600
const DOWN = "#e11d48"; // rose-600
const BB_COLOR = "#8b5cf6"; // violet-500
const VWAP_COLOR = "#0ea5e9"; // sky-500
const RSI_COLOR = "#f59e0b"; // amber-500
const MACD_COLOR = "#0ea5e9"; // sky-500
const SIGNAL_COLOR = "#f59e0b"; // amber-500
const LINE_COLOR = "#e11d48"; // rose-600 (drawing tool)
const PAD_TOP = 8;
const PAD_BOTTOM = 8;
const PAD_LEFT = 8;
const PAD_RIGHT = 56;
const SUB_GAP = 8; // gap between price pane and oscillator sub-pane

const MAS = [
  { period: 7, color: "#f59e0b" }, // amber
  { period: 25, color: "#8b5cf6" }, // violet
  { period: 99, color: "#0ea5e9" }, // sky
];

type Oscillator = "none" | "rsi" | "macd";

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

/** Rolling population standard deviation over `period`; first (period-1) entries null. */
function rollingStdDev(vals: number[], period: number, means: (number | null)[]): (number | null)[] {
  const out: (number | null)[] = [];
  for (let i = 0; i < vals.length; i++) {
    const mean = means[i];
    if (i < period - 1 || mean == null) {
      out.push(null);
      continue;
    }
    let acc = 0;
    for (let j = i - period + 1; j <= i; j++) {
      const d = vals[j]! - mean;
      acc += d * d;
    }
    out.push(Math.sqrt(acc / period));
  }
  return out;
}

/** Exponential moving average; first `period-1` entries null, seeded with an SMA. */
function ema(vals: number[], period: number): (number | null)[] {
  const out: (number | null)[] = new Array(vals.length).fill(null);
  if (vals.length < period) return out;
  const k = 2 / (period + 1);
  let seed = 0;
  for (let i = 0; i < period; i++) seed += vals[i]!;
  let prev = seed / period;
  out[period - 1] = prev;
  for (let i = period; i < vals.length; i++) {
    prev = vals[i]! * k + prev * (1 - k);
    out[i] = prev;
  }
  return out;
}

/** Wilder's RSI(period), 0..100; entries before the first computable point are null. */
function rsi(closes: number[], period: number): (number | null)[] {
  const out: (number | null)[] = new Array(closes.length).fill(null);
  if (closes.length <= period) return out;
  let gainSum = 0;
  let lossSum = 0;
  for (let i = 1; i <= period; i++) {
    const ch = closes[i]! - closes[i - 1]!;
    if (ch >= 0) gainSum += ch;
    else lossSum -= ch;
  }
  let avgGain = gainSum / period;
  let avgLoss = lossSum / period;
  out[period] = avgLoss === 0 ? 100 : 100 - 100 / (1 + avgGain / avgLoss);
  for (let i = period + 1; i < closes.length; i++) {
    const ch = closes[i]! - closes[i - 1]!;
    const gain = ch > 0 ? ch : 0;
    const loss = ch < 0 ? -ch : 0;
    avgGain = (avgGain * (period - 1) + gain) / period;
    avgLoss = (avgLoss * (period - 1) + loss) / period;
    out[i] = avgLoss === 0 ? 100 : 100 - 100 / (1 + avgGain / avgLoss);
  }
  return out;
}

/** VWAP: cumulative(sum(typical*volume)) / cumulative(volume). */
function vwap(bars: Candle[]): (number | null)[] {
  const out: (number | null)[] = [];
  let pv = 0;
  let vol = 0;
  for (const b of bars) {
    const typical = (b.high + b.low + b.close) / 3;
    const v = b.volume || 0;
    pv += typical * v;
    vol += v;
    out.push(vol > 0 ? pv / vol : null);
  }
  return out;
}

/** Chip button used for the controls row. */
function Chip({
  active,
  onClick,
  children,
  color,
  className,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  color?: string;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded border px-1.5 py-0.5 text-[10px] leading-none transition-colors",
        active ? "border-transparent bg-foreground/10 font-medium" : "border-border text-muted-foreground hover:bg-foreground/5",
        className,
      )}
      style={active && color ? { color } : undefined}
    >
      {children}
    </button>
  );
}

/** Hand-rolled SVG candlestick chart (auto-scaled) with MA/BB/VWAP overlays, an
 *  RSI/MACD sub-pane, a horizontal-line drawing tool, and click-to-trade. */
export default function CandleChart({ bars, scaler = 1, height = 320, onPriceClick }: CandleChartProps) {
  const width = 720;

  const [showBB, setShowBB] = useState(false);
  const [showVwap, setShowVwap] = useState(false);
  const [osc, setOsc] = useState<Oscillator>("none");
  const [lineTool, setLineTool] = useState(false);
  const [lines, setLines] = useState<number[]>([]); // horizontal price lines (raw integer prices)

  const oscActive = osc !== "none";

  const layout = useMemo(() => {
    if (!bars.length) return null;

    // Split the vertical space between the price pane and (optional) oscillator pane.
    const oscH = oscActive ? Math.round(height * 0.28) : 0;
    const priceAreaH = height - oscH - (oscActive ? SUB_GAP : 0);

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
    const plotH = priceAreaH - PAD_TOP - PAD_BOTTOM;
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

    const polyFrom = (series: (number | null)[]) =>
      series
        .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${yOf(v).toFixed(1)}`))
        .filter((p): p is string => p !== null)
        .join(" ");

    const maLines = MAS.map((m) => ({ period: m.period, color: m.color, points: polyFrom(sma(closes, m.period)) })).filter(
      (m) => m.points.length > 0,
    );

    // Bollinger Bands: SMA(20) +/- 2 * stdDev(20).
    let bb: { upper: string; lower: string; areaPath: string } | null = null;
    if (bars.length >= 20) {
      const basis = sma(closes, 20);
      const sd = rollingStdDev(closes, 20, basis);
      const upperPts: string[] = [];
      const lowerPts: string[] = [];
      for (let i = 0; i < bars.length; i++) {
        const m = basis[i];
        const s = sd[i];
        if (m == null || s == null) continue;
        upperPts.push(`${xOf(i).toFixed(1)},${yOf(m + 2 * s).toFixed(1)}`);
        lowerPts.push(`${xOf(i).toFixed(1)},${yOf(m - 2 * s).toFixed(1)}`);
      }
      if (upperPts.length > 1) {
        const areaPath = `M ${upperPts.join(" L ")} L ${[...lowerPts].reverse().join(" L ")} Z`;
        bb = { upper: upperPts.join(" "), lower: lowerPts.join(" "), areaPath };
      }
    }

    // VWAP.
    const vwapPoints = polyFrom(vwap(bars));

    const ticks = 4;
    const labels = Array.from({ length: ticks + 1 }, (_, i) => {
      const v = max - (range * i) / ticks;
      return { y: yOf(v), value: v / (scaler || 1) };
    });

    // Horizontal drawing lines (only those inside the visible price range render on-scale).
    const drawnLines = lines.map((p, i) => ({ key: i, y: yOf(p), price: p }));

    // ---- Oscillator sub-pane -------------------------------------------------
    const oscTop = priceAreaH + SUB_GAP;
    const oscInnerH = oscH - PAD_TOP - PAD_BOTTOM;
    let oscPane: {
      kind: "rsi" | "macd";
      lines: { points: string; color: string; width: number }[];
      hist: { x: number; y: number; w: number; h: number; color: string }[];
      guides: { y: number; label: string }[];
      zeroY: number | null;
    } | null = null;

    if (oscActive && oscInnerH > 0) {
      const oscY = (frac: number) => oscTop + PAD_TOP + (1 - frac) * oscInnerH; // frac 0..1 bottom..top

      if (osc === "rsi") {
        const series = rsi(closes, 14);
        const pts = series
          .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${oscY(v / 100).toFixed(1)}`))
          .filter((p): p is string => p !== null)
          .join(" ");
        oscPane = {
          kind: "rsi",
          lines: pts ? [{ points: pts, color: RSI_COLOR, width: 1.25 }] : [],
          hist: [],
          guides: [
            { y: oscY(0.7), label: "70" },
            { y: oscY(0.3), label: "30" },
          ],
          zeroY: null,
        };
      } else {
        // MACD(12,26,9).
        const e12 = ema(closes, 12);
        const e26 = ema(closes, 26);
        const macd: (number | null)[] = closes.map((_, i) =>
          e12[i] != null && e26[i] != null ? (e12[i] as number) - (e26[i] as number) : null,
        );
        // Signal = EMA(9) over the defined portion of the MACD line.
        const firstDef = macd.findIndex((v) => v != null);
        const signal: (number | null)[] = new Array(closes.length).fill(null);
        if (firstDef >= 0) {
          const defVals = macd.slice(firstDef).map((v) => v as number);
          const sig = ema(defVals, 9);
          for (let i = 0; i < sig.length; i++) signal[firstDef + i] = sig[i] ?? null;
        }
        let lo = Infinity;
        let hi = -Infinity;
        for (let i = 0; i < closes.length; i++) {
          for (const v of [macd[i], signal[i]]) {
            if (v == null) continue;
            if (v < lo) lo = v;
            if (v > hi) hi = v;
          }
          if (macd[i] != null && signal[i] != null) {
            const h = (macd[i] as number) - (signal[i] as number);
            if (h < lo) lo = h;
            if (h > hi) hi = h;
          }
        }
        if (!Number.isFinite(lo) || !Number.isFinite(hi)) {
          oscPane = { kind: "macd", lines: [], hist: [], guides: [], zeroY: null };
        } else {
          if (lo === hi) {
            lo -= 1;
            hi += 1;
          }
          const span = hi - lo;
          const oscVal = (v: number) => oscY((v - lo) / span);
          const macdPts = macd
            .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${oscVal(v).toFixed(1)}`))
            .filter((p): p is string => p !== null)
            .join(" ");
          const sigPts = signal
            .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${oscVal(v).toFixed(1)}`))
            .filter((p): p is string => p !== null)
            .join(" ");
          const zeroY = lo <= 0 && hi >= 0 ? oscVal(0) : null;
          const hist: { x: number; y: number; w: number; h: number; color: string }[] = [];
          for (let i = 0; i < closes.length; i++) {
            if (macd[i] == null || signal[i] == null) continue;
            const hVal = (macd[i] as number) - (signal[i] as number);
            const base = zeroY ?? oscVal(0 >= lo && 0 <= hi ? 0 : lo);
            const yTop = Math.min(base, oscVal(hVal));
            const h = Math.max(1, Math.abs(oscVal(hVal) - base));
            hist.push({ x: xOf(i) - bodyW / 2, y: yTop, w: bodyW, h, color: hVal >= 0 ? UP : DOWN });
          }
          oscPane = {
            kind: "macd",
            lines: [
              ...(macdPts ? [{ points: macdPts, color: MACD_COLOR, width: 1.25 }] : []),
              ...(sigPts ? [{ points: sigPts, color: SIGNAL_COLOR, width: 1.25 }] : []),
            ],
            hist,
            guides: [],
            zeroY,
          };
        }
      }
    }

    return { candles, labels, maLines, bb, vwapPoints, drawnLines, oscPane, max, range, priceAreaH, plotH };
  }, [bars, height, scaler, showBB, showVwap, osc, oscActive, lines]);

  if (!layout) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        No candles available.
      </div>
    );
  }

  function handleClick(e: React.MouseEvent<SVGSVGElement>) {
    if (!layout) return;
    const rect = e.currentTarget.getBoundingClientRect();
    if (!rect.height) return;
    const yView = ((e.clientY - rect.top) / rect.height) * height;
    const price = layout.max - ((yView - PAD_TOP) / layout.plotH) * layout.range;
    if (!Number.isFinite(price)) return;
    const rounded = Math.max(0, Math.round(price));
    if (lineTool) {
      setLines((prev) => [...prev, rounded]);
      return;
    }
    onPriceClick?.(rounded);
  }

  const interactive = !!onPriceClick || lineTool;

  return (
    <div>
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        {layout.maLines.map((m) => (
          <span key={m.period} className="text-[10px]" style={{ color: m.color }}>
            MA{m.period}
          </span>
        ))}
        <span className="mx-0.5 text-[10px] text-muted-foreground">|</span>
        <Chip active={showBB} onClick={() => setShowBB((v) => !v)} color={BB_COLOR}>
          BB
        </Chip>
        <Chip active={showVwap} onClick={() => setShowVwap((v) => !v)} color={VWAP_COLOR}>
          VWAP
        </Chip>
        <span className="mx-0.5 text-[10px] text-muted-foreground">|</span>
        <Chip active={osc === "none"} onClick={() => setOsc("none")}>
          None
        </Chip>
        <Chip active={osc === "rsi"} onClick={() => setOsc("rsi")} color={RSI_COLOR}>
          RSI
        </Chip>
        <Chip active={osc === "macd"} onClick={() => setOsc("macd")} color={MACD_COLOR}>
          MACD
        </Chip>
        <span className="mx-0.5 text-[10px] text-muted-foreground">|</span>
        <Chip active={lineTool} onClick={() => setLineTool((v) => !v)} color={LINE_COLOR}>
          Line
        </Chip>
        {lines.length > 0 && (
          <Chip active={false} onClick={() => setLines([])}>
            Clear
          </Chip>
        )}
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className={interactive ? "w-full cursor-crosshair" : "w-full"}
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

        {/* Bollinger Bands */}
        {showBB && layout.bb && (
          <g>
            <path d={layout.bb.areaPath} fill={BB_COLOR} fillOpacity={0.06} stroke="none" />
            <polyline
              points={layout.bb.upper}
              fill="none"
              stroke={BB_COLOR}
              strokeWidth={1}
              strokeOpacity={0.75}
              vectorEffect="non-scaling-stroke"
            />
            <polyline
              points={layout.bb.lower}
              fill="none"
              stroke={BB_COLOR}
              strokeWidth={1}
              strokeOpacity={0.75}
              vectorEffect="non-scaling-stroke"
            />
          </g>
        )}

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

        {/* VWAP */}
        {showVwap && layout.vwapPoints && (
          <polyline
            points={layout.vwapPoints}
            fill="none"
            stroke={VWAP_COLOR}
            strokeWidth={1.5}
            strokeOpacity={0.9}
            strokeDasharray="4 3"
            vectorEffect="non-scaling-stroke"
          />
        )}

        {/* Drawing tool: horizontal price lines */}
        {layout.drawnLines.map((dl) => (
          <g key={`dl${dl.key}`}>
            <line
              x1={PAD_LEFT}
              x2={width - PAD_RIGHT}
              y1={dl.y}
              y2={dl.y}
              stroke={LINE_COLOR}
              strokeWidth={1}
              strokeDasharray="3 2"
              vectorEffect="non-scaling-stroke"
            />
            <text x={PAD_LEFT + 2} y={dl.y - 2} fontSize={9} fill={LINE_COLOR} fillOpacity={0.9}>
              {(dl.price / (scaler || 1)).toLocaleString(undefined, { maximumFractionDigits: 2 })}
            </text>
          </g>
        ))}

        {/* Oscillator sub-pane */}
        {layout.oscPane && (
          <g>
            <line
              x1={PAD_LEFT}
              x2={width - PAD_RIGHT}
              y1={layout.priceAreaH + SUB_GAP / 2}
              y2={layout.priceAreaH + SUB_GAP / 2}
              stroke="currentColor"
              strokeOpacity={0.15}
            />
            {layout.oscPane.guides.map((g, i) => (
              <g key={`og${i}`}>
                <line
                  x1={PAD_LEFT}
                  x2={width - PAD_RIGHT}
                  y1={g.y}
                  y2={g.y}
                  stroke="currentColor"
                  strokeOpacity={0.12}
                  strokeDasharray="2 2"
                />
                <text x={width - PAD_RIGHT + 4} y={g.y + 3} fontSize={9} fill="currentColor" fillOpacity={0.5}>
                  {g.label}
                </text>
              </g>
            ))}
            {layout.oscPane.zeroY != null && (
              <line
                x1={PAD_LEFT}
                x2={width - PAD_RIGHT}
                y1={layout.oscPane.zeroY}
                y2={layout.oscPane.zeroY}
                stroke="currentColor"
                strokeOpacity={0.15}
              />
            )}
            {layout.oscPane.hist.map((h, i) => (
              <rect key={`oh${i}`} x={h.x} y={h.y} width={h.w} height={h.h} fill={h.color} fillOpacity={0.5} />
            ))}
            {layout.oscPane.lines.map((ln, i) => (
              <polyline
                key={`ol${i}`}
                points={ln.points}
                fill="none"
                stroke={ln.color}
                strokeWidth={ln.width}
                strokeOpacity={0.9}
                vectorEffect="non-scaling-stroke"
              />
            ))}
          </g>
        )}
      </svg>
    </div>
  );
}
