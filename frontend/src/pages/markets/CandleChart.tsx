import { useMemo, useState } from "react";
import type { Candle } from "@/api/endpoints/marketData";
import { cn } from "@/lib/utils";

interface CandleChartProps {
  bars: Candle[];
  scaler?: number;
  height?: number;
  /** Second bar interval hint (for the crosshair time readout only). */
  intervalSec?: number;
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
const SUB_GAP = 8; // gap between panes

const MAS = [
  { period: 7, color: "#f59e0b" }, // amber
  { period: 25, color: "#8b5cf6" }, // violet
  { period: 99, color: "#0ea5e9" }, // sky
];

const EMAS = [
  { period: 9, color: "#22d3ee" }, // cyan
  { period: 21, color: "#ec4899" }, // pink
  { period: 50, color: "#84cc16" }, // lime
];

const MA_CHIP_COLOR = "#f59e0b"; // amber (MA legend/chip)
const EMA_CHIP_COLOR = "#22d3ee"; // cyan (EMA legend/chip)

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

/** Wilder RSI(period), 0..100; entries before the first computable point are null. */
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

/** A stacked sub-pane definition produced by the layout memo. */
interface SubPane {
  kind: "volume" | "rsi" | "macd";
  top: number;
  height: number;
  title: string;
  lines: { points: string; color: string; width: number }[];
  hist: { x: number; y: number; w: number; h: number; color: string; opacity: number }[];
  guides: { y: number; label: string }[];
  zeroY: number | null;
}

/** Hand-rolled SVG candlestick chart (auto-scaled) with MA/EMA/BB/VWAP overlays,
 *  stacked Volume / RSI / MACD sub-panes, a crosshair readout, a horizontal-line
 *  drawing tool, and click-to-trade. */
export default function CandleChart({ bars, scaler = 1, height = 320, intervalSec, onPriceClick }: CandleChartProps) {
  const width = 720;

  const [showMa, setShowMa] = useState(true);
  const [showEma, setShowEma] = useState(false);
  const [showBB, setShowBB] = useState(false);
  const [showVwap, setShowVwap] = useState(false);
  const [showVol, setShowVol] = useState(true);
  const [showRsi, setShowRsi] = useState(false);
  const [showMacd, setShowMacd] = useState(false);
  const [lineTool, setLineTool] = useState(false);
  const [lines, setLines] = useState<number[]>([]); // horizontal price lines (raw integer prices)
  const [hover, setHover] = useState<number | null>(null); // hovered bar index

  const layout = useMemo(() => {
    if (!bars.length) return null;

    // Reserve vertical space for each active sub-pane (equal split of the extra area).
    const activePanes: ("volume" | "rsi" | "macd")[] = [];
    if (showVol) activePanes.push("volume");
    if (showRsi) activePanes.push("rsi");
    if (showMacd) activePanes.push("macd");
    const paneUnit = Math.round(height * 0.24);
    const totalSubH = activePanes.length ? activePanes.length * paneUnit + activePanes.length * SUB_GAP : 0;
    const priceAreaH = Math.max(80, height - totalSubH);

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

    const maSeries = MAS.map((m) => ({ ...m, values: sma(closes, m.period) }));
    const emaSeries = EMAS.map((m) => ({ ...m, values: ema(closes, m.period) }));
    const maLines = showMa
      ? maSeries.map((m) => ({ period: m.period, color: m.color, points: polyFrom(m.values) })).filter((m) => m.points.length > 0)
      : [];
    const emaLines = showEma
      ? emaSeries.map((m) => ({ period: m.period, color: m.color, points: polyFrom(m.values) })).filter((m) => m.points.length > 0)
      : [];

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
    const vwapValues = vwap(bars);
    const vwapPoints = polyFrom(vwapValues);

    const ticks = 4;
    const labels = Array.from({ length: ticks + 1 }, (_, i) => {
      const v = max - (range * i) / ticks;
      return { y: yOf(v), value: v / (scaler || 1) };
    });

    // Horizontal drawing lines (only those inside the visible price range render on-scale).
    const drawnLines = lines.map((p, i) => ({ key: i, y: yOf(p), price: p }));

    // ---- Stacked sub-panes ---------------------------------------------------
    const rsiValues = rsi(closes, 14);

    // MACD(12,26,9).
    const e12 = ema(closes, 12);
    const e26 = ema(closes, 26);
    const macdLine: (number | null)[] = closes.map((_, i) =>
      e12[i] != null && e26[i] != null ? (e12[i] as number) - (e26[i] as number) : null,
    );
    const firstDef = macdLine.findIndex((v) => v != null);
    const signalLine: (number | null)[] = new Array(closes.length).fill(null);
    if (firstDef >= 0) {
      const defVals = macdLine.slice(firstDef).map((v) => v as number);
      const sig = ema(defVals, 9);
      for (let i = 0; i < sig.length; i++) signalLine[firstDef + i] = sig[i] ?? null;
    }

    const subPanes: SubPane[] = [];
    let cursor = priceAreaH;
    for (const kind of activePanes) {
      const top = cursor + SUB_GAP;
      const paneH = paneUnit;
      const innerH = paneH - PAD_TOP - PAD_BOTTOM;
      const yAt = (frac: number) => top + PAD_TOP + (1 - frac) * innerH; // frac 0..1 bottom..top

      if (kind === "volume") {
        const vols = bars.map((b) => b.volume || 0);
        const maxVol = Math.max(1, ...vols);
        const hist = bars.map((b, i) => {
          const up = b.close >= b.open;
          const frac = (b.volume || 0) / maxVol;
          const yTop = yAt(frac);
          const yBase = yAt(0);
          return { x: xOf(i) - bodyW / 2, y: yTop, w: bodyW, h: Math.max(1, yBase - yTop), color: up ? UP : DOWN, opacity: 0.5 };
        });
        subPanes.push({ kind, top, height: paneH, title: "Vol", lines: [], hist, guides: [], zeroY: null });
      } else if (kind === "rsi") {
        const pts = rsiValues
          .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${yAt(v / 100).toFixed(1)}`))
          .filter((p): p is string => p !== null)
          .join(" ");
        subPanes.push({
          kind,
          top,
          height: paneH,
          title: "RSI 14",
          lines: pts ? [{ points: pts, color: RSI_COLOR, width: 1.25 }] : [],
          hist: [],
          guides: [
            { y: yAt(0.7), label: "70" },
            { y: yAt(0.3), label: "30" },
          ],
          zeroY: null,
        });
      } else {
        // MACD pane scaling.
        let lo = Infinity;
        let hi = -Infinity;
        for (let i = 0; i < closes.length; i++) {
          for (const v of [macdLine[i], signalLine[i]]) {
            if (v == null) continue;
            if (v < lo) lo = v;
            if (v > hi) hi = v;
          }
          if (macdLine[i] != null && signalLine[i] != null) {
            const h = (macdLine[i] as number) - (signalLine[i] as number);
            if (h < lo) lo = h;
            if (h > hi) hi = h;
          }
        }
        if (!Number.isFinite(lo) || !Number.isFinite(hi)) {
          subPanes.push({ kind, top, height: paneH, title: "MACD", lines: [], hist: [], guides: [], zeroY: null });
        } else {
          if (lo === hi) {
            lo -= 1;
            hi += 1;
          }
          const span = hi - lo;
          const oscVal = (v: number) => yAt((v - lo) / span);
          const macdPts = macdLine
            .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${oscVal(v).toFixed(1)}`))
            .filter((p): p is string => p !== null)
            .join(" ");
          const sigPts = signalLine
            .map((v, i) => (v == null ? null : `${xOf(i).toFixed(1)},${oscVal(v).toFixed(1)}`))
            .filter((p): p is string => p !== null)
            .join(" ");
          const zeroY = lo <= 0 && hi >= 0 ? oscVal(0) : null;
          const hist: SubPane["hist"] = [];
          for (let i = 0; i < closes.length; i++) {
            if (macdLine[i] == null || signalLine[i] == null) continue;
            const hVal = (macdLine[i] as number) - (signalLine[i] as number);
            const base = zeroY ?? oscVal(0 >= lo && 0 <= hi ? 0 : lo);
            const yTop = Math.min(base, oscVal(hVal));
            const h = Math.max(1, Math.abs(oscVal(hVal) - base));
            hist.push({ x: xOf(i) - bodyW / 2, y: yTop, w: bodyW, h, color: hVal >= 0 ? UP : DOWN, opacity: 0.5 });
          }
          subPanes.push({
            kind,
            top,
            height: paneH,
            title: "MACD",
            lines: [
              ...(macdPts ? [{ points: macdPts, color: MACD_COLOR, width: 1.25 }] : []),
              ...(sigPts ? [{ points: sigPts, color: SIGNAL_COLOR, width: 1.25 }] : []),
            ],
            hist,
            guides: [],
            zeroY,
          });
        }
      }
      cursor = top + paneH;
    }

    // Per-bar indicator readouts for the crosshair.
    const readAt = (i: number) => ({
      ma: maSeries.filter((m) => m.values[i] != null).map((m) => ({ label: `MA${m.period}`, color: m.color, value: m.values[i] as number })),
      ema: emaSeries.filter((m) => m.values[i] != null).map((m) => ({ label: `EMA${m.period}`, color: m.color, value: m.values[i] as number })),
      vwap: vwapValues[i] ?? null,
      rsi: rsiValues[i] ?? null,
    });

    return { candles, labels, maLines, emaLines, bb, vwapPoints, drawnLines, subPanes, max, min, range, priceAreaH, plotH, plotW, slot, xOf, readAt };
  }, [bars, height, scaler, showMa, showEma, showBB, showVwap, showVol, showRsi, showMacd, lines]);

  if (!layout) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        No candles available.
      </div>
    );
  }

  const fmt = (v: number) => (v / (scaler || 1)).toLocaleString(undefined, { maximumFractionDigits: 2 });

  function barIndexFromEvent(e: React.MouseEvent<SVGSVGElement>): number | null {
    const rect = e.currentTarget.getBoundingClientRect();
    if (!rect.width) return null;
    const xView = ((e.clientX - rect.left) / rect.width) * width;
    const i = Math.floor((xView - PAD_LEFT) / layout!.slot);
    if (i < 0 || i >= bars.length) return null;
    return i;
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

  const hoverBar = hover != null ? bars[hover] : null;
  const hoverRead = hover != null ? layout.readAt(hover) : null;
  const hoverX = hover != null ? layout.xOf(hover) : null;
  const hoverTime =
    hoverBar && Number.isFinite(hoverBar.ts_start_ns)
      ? new Date(Math.floor(hoverBar.ts_start_ns / 1_000_000)).toLocaleString([], {
          month: "short",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          ...(intervalSec && intervalSec < 60 ? { second: "2-digit" } : {}),
        })
      : null;

  return (
    <div>
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Chip active={showMa} onClick={() => setShowMa((v) => !v)} color={MA_CHIP_COLOR}>
          MA
        </Chip>
        <Chip active={showEma} onClick={() => setShowEma((v) => !v)} color={EMA_CHIP_COLOR}>
          EMA
        </Chip>
        <Chip active={showBB} onClick={() => setShowBB((v) => !v)} color={BB_COLOR}>
          BB
        </Chip>
        <Chip active={showVwap} onClick={() => setShowVwap((v) => !v)} color={VWAP_COLOR}>
          VWAP
        </Chip>
        <span className="mx-0.5 text-[10px] text-muted-foreground">|</span>
        <Chip active={showVol} onClick={() => setShowVol((v) => !v)}>
          Vol
        </Chip>
        <Chip active={showRsi} onClick={() => setShowRsi((v) => !v)} color={RSI_COLOR}>
          RSI
        </Chip>
        <Chip active={showMacd} onClick={() => setShowMacd((v) => !v)} color={MACD_COLOR}>
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
        {/* Active MA/EMA legend */}
        {layout.maLines.map((m) => (
          <span key={`lm${m.period}`} className="text-[10px]" style={{ color: m.color }}>
            MA{m.period}
          </span>
        ))}
        {layout.emaLines.map((m) => (
          <span key={`le${m.period}`} className="text-[10px]" style={{ color: m.color }}>
            EMA{m.period}
          </span>
        ))}
      </div>

      {/* Crosshair OHLC readout */}
      <div className="mb-1 flex h-4 flex-wrap items-center gap-2 text-[10px] tabular-nums text-muted-foreground">
        {hoverBar && (
          <>
            {hoverTime && <span className="text-foreground/80">{hoverTime}</span>}
            <span>O {fmt(hoverBar.open)}</span>
            <span>H {fmt(hoverBar.high)}</span>
            <span>L {fmt(hoverBar.low)}</span>
            <span className={hoverBar.close >= hoverBar.open ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"}>
              C {fmt(hoverBar.close)}
            </span>
            <span>V {(hoverBar.volume || 0).toLocaleString(undefined, { maximumFractionDigits: 2 })}</span>
            {hoverRead?.ma.map((r) => (
              <span key={r.label} style={{ color: r.color }}>
                {r.label} {fmt(r.value)}
              </span>
            ))}
            {hoverRead?.ema.map((r) => (
              <span key={r.label} style={{ color: r.color }}>
                {r.label} {fmt(r.value)}
              </span>
            ))}
            {showVwap && hoverRead?.vwap != null && (
              <span style={{ color: VWAP_COLOR }}>VWAP {fmt(hoverRead.vwap)}</span>
            )}
            {showRsi && hoverRead?.rsi != null && (
              <span style={{ color: RSI_COLOR }}>RSI {hoverRead.rsi.toFixed(1)}</span>
            )}
          </>
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
        onMouseMove={(e) => setHover(barIndexFromEvent(e))}
        onMouseLeave={() => setHover(null)}
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
            key={`ma${m.period}`}
            points={m.points}
            fill="none"
            stroke={m.color}
            strokeWidth={1.25}
            strokeOpacity={0.9}
            vectorEffect="non-scaling-stroke"
          />
        ))}

        {layout.emaLines.map((m) => (
          <polyline
            key={`ema${m.period}`}
            points={m.points}
            fill="none"
            stroke={m.color}
            strokeWidth={1.25}
            strokeOpacity={0.9}
            strokeDasharray="5 2"
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
              {fmt(dl.price)}
            </text>
          </g>
        ))}

        {/* Stacked sub-panes */}
        {layout.subPanes.map((pane, pi) => (
          <g key={`pane${pi}`}>
            <line
              x1={PAD_LEFT}
              x2={width - PAD_RIGHT}
              y1={pane.top - SUB_GAP / 2}
              y2={pane.top - SUB_GAP / 2}
              stroke="currentColor"
              strokeOpacity={0.15}
            />
            <text x={PAD_LEFT + 2} y={pane.top + 10} fontSize={9} fill="currentColor" fillOpacity={0.5}>
              {pane.title}
            </text>
            {pane.guides.map((g, i) => (
              <g key={`pg${pi}-${i}`}>
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
            {pane.zeroY != null && (
              <line x1={PAD_LEFT} x2={width - PAD_RIGHT} y1={pane.zeroY} y2={pane.zeroY} stroke="currentColor" strokeOpacity={0.15} />
            )}
            {pane.hist.map((h, i) => (
              <rect key={`ph${pi}-${i}`} x={h.x} y={h.y} width={h.w} height={h.h} fill={h.color} fillOpacity={h.opacity} />
            ))}
            {pane.lines.map((ln, i) => (
              <polyline
                key={`pl${pi}-${i}`}
                points={ln.points}
                fill="none"
                stroke={ln.color}
                strokeWidth={ln.width}
                strokeOpacity={0.9}
                vectorEffect="non-scaling-stroke"
              />
            ))}
          </g>
        ))}

        {/* Crosshair vertical guide */}
        {hoverX != null && (
          <line
            x1={hoverX}
            x2={hoverX}
            y1={PAD_TOP}
            y2={height - PAD_BOTTOM}
            stroke="currentColor"
            strokeOpacity={0.35}
            strokeDasharray="3 3"
            vectorEffect="non-scaling-stroke"
            pointerEvents="none"
          />
        )}
      </svg>
    </div>
  );
}
