import { useMemo, useRef, useState } from "react";
import { computeDepth, type DepthPoint, type Level } from "@/lib/depth";
import { formatPrice, formatQty } from "./format";

interface DepthChartProps {
  bids: Level[];
  asks: Level[];
  scaler?: number;
  height?: number;
}

const BID = "#059669"; // emerald-600
const ASK = "#e11d48"; // rose-600
const PAD_TOP = 10;
const PAD_BOTTOM = 22;
const PAD_LEFT = 8;
const PAD_RIGHT = 8;

interface Hover {
  x: number;
  y: number;
  price: number;
  cum: number;
  side: "bid" | "ask";
}

/**
 * Cumulative-depth (market-depth) chart. Bids are drawn as a green step-area
 * rising from the mid toward lower prices (left); asks as a red step-area
 * rising toward higher prices (right). The pure cumulative math lives in
 * `@/lib/depth`; this component is purely presentational/SVG.
 */
export default function DepthChart({
  bids,
  asks,
  scaler = 1,
  height = 260,
}: DepthChartProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [hover, setHover] = useState<Hover | null>(null);
  const [width, setWidth] = useState(640);

  const depth = useMemo(() => computeDepth(bids, asks), [bids, asks]);

  const hasData =
    depth.minPrice != null && depth.maxPrice != null && depth.maxCum > 0;

  const plotW = Math.max(1, width - PAD_LEFT - PAD_RIGHT);
  const plotH = Math.max(1, height - PAD_TOP - PAD_BOTTOM);

  // x maps price -> px across [minPrice, maxPrice]; y maps cum -> px (0 at bottom).
  const geom = useMemo(() => {
    if (!hasData) return null;
    const minP = depth.minPrice!;
    const maxP = depth.maxPrice!;
    const span = maxP - minP || 1;
    const x = (price: number) => PAD_LEFT + ((price - minP) / span) * plotW;
    const y = (cum: number) => PAD_TOP + plotH - (cum / depth.maxCum) * plotH;
    return { x, y, minP, maxP, span };
  }, [hasData, depth, plotW, plotH]);

  const anchor = depth.mid ?? depth.bestBid ?? depth.bestAsk ?? 0;
  const baseY = PAD_TOP + plotH;

  // Build an SVG step-area path for one cumulative side, anchored at the mid.
  const buildPath = (points: DepthPoint[]): string => {
    if (!geom || points.length === 0) return "";
    const { x, y } = geom;
    const ordered = [...points].sort((a, b) => a.price - b.price);
    let d = `M ${x(anchor)} ${baseY}`;
    let prevCum = 0;
    for (const p of ordered) {
      d += ` L ${x(p.price)} ${y(prevCum)}`;
      d += ` L ${x(p.price)} ${y(p.cum)}`;
      prevCum = p.cum;
    }
    const last = ordered[ordered.length - 1]!;
    d += ` L ${x(last.price)} ${baseY} Z`;
    return d;
  };

  const bidPath = useMemo(
    () => buildPath(depth.bids),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [depth.bids, geom, anchor]
  );
  const askPath = useMemo(
    () => buildPath(depth.asks),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [depth.asks, geom, anchor]
  );

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!geom) return;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const px = e.clientX - rect.left;
    const price = geom.minP + ((px - PAD_LEFT) / plotW) * geom.span;
    const side: "bid" | "ask" =
      depth.mid != null
        ? price <= depth.mid
          ? "bid"
          : "ask"
        : price <= anchor
          ? "bid"
          : "ask";
    const pts = side === "bid" ? depth.bids : depth.asks;
    if (pts.length === 0) {
      setHover(null);
      return;
    }
    let best = pts[0]!;
    let bestD = Math.abs(best.price - price);
    for (const p of pts) {
      const dd = Math.abs(p.price - price);
      if (dd < bestD) {
        bestD = dd;
        best = p;
      }
    }
    setHover({
      x: geom.x(best.price),
      y: geom.y(best.cum),
      price: best.price,
      cum: best.cum,
      side,
    });
  };

  // Track container width for responsiveness.
  const measureRef = (node: HTMLDivElement | null) => {
    if (node && node.clientWidth && node.clientWidth !== width) {
      setWidth(node.clientWidth);
    }
  };

  if (!hasData) {
    return (
      <div
        ref={measureRef}
        className="flex items-center justify-center text-sm text-muted-foreground"
        style={{ height }}
      >
        No depth data.
      </div>
    );
  }

  const midX = depth.mid != null ? geom!.x(depth.mid) : null;

  return (
    <div ref={measureRef} className="relative w-full">
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label="Cumulative market-depth chart"
      >
        <defs>
          <linearGradient id="depth-bid" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={BID} stopOpacity="0.35" />
            <stop offset="100%" stopColor={BID} stopOpacity="0.05" />
          </linearGradient>
          <linearGradient id="depth-ask" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={ASK} stopOpacity="0.35" />
            <stop offset="100%" stopColor={ASK} stopOpacity="0.05" />
          </linearGradient>
        </defs>

        <line
          x1={PAD_LEFT}
          y1={baseY}
          x2={width - PAD_RIGHT}
          y2={baseY}
          stroke="currentColor"
          strokeOpacity="0.15"
        />

        <path d={bidPath} fill="url(#depth-bid)" stroke={BID} strokeWidth={1.25} />
        <path d={askPath} fill="url(#depth-ask)" stroke={ASK} strokeWidth={1.25} />

        {midX != null && (
          <line
            x1={midX}
            y1={PAD_TOP}
            x2={midX}
            y2={baseY}
            stroke="currentColor"
            strokeOpacity="0.35"
            strokeDasharray="3 3"
          />
        )}

        {hover && (
          <g>
            <line
              x1={hover.x}
              y1={PAD_TOP}
              x2={hover.x}
              y2={baseY}
              stroke="currentColor"
              strokeOpacity="0.4"
            />
            <line
              x1={PAD_LEFT}
              y1={hover.y}
              x2={width - PAD_RIGHT}
              y2={hover.y}
              stroke="currentColor"
              strokeOpacity="0.25"
            />
            <circle cx={hover.x} cy={hover.y} r={3.5} fill={hover.side === "bid" ? BID : ASK} />
          </g>
        )}

        <text x={PAD_LEFT} y={height - 6} fontSize="10" fill="currentColor" fillOpacity="0.5">
          {formatPrice(geom!.minP, scaler)}
        </text>
        {midX != null && (
          <text
            x={midX}
            y={height - 6}
            fontSize="10"
            textAnchor="middle"
            fill="currentColor"
            fillOpacity="0.6"
          >
            {formatPrice(depth.mid!, scaler)}
          </text>
        )}
        <text
          x={width - PAD_RIGHT}
          y={height - 6}
          fontSize="10"
          textAnchor="end"
          fill="currentColor"
          fillOpacity="0.5"
        >
          {formatPrice(geom!.maxP, scaler)}
        </text>
      </svg>

      {hover && (
        <div
          className="pointer-events-none absolute z-10 rounded-md border bg-popover px-2 py-1 text-xs shadow-md tabular-nums"
          style={{
            left: Math.min(width - 130, Math.max(0, hover.x + 8)),
            top: Math.max(0, hover.y - 44),
          }}
        >
          <div
            className={
              hover.side === "bid"
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-rose-600 dark:text-rose-400"
            }
          >
            {hover.side === "bid" ? "Bid" : "Ask"} {formatPrice(hover.price, scaler)}
          </div>
          <div className="text-muted-foreground">Cum size {formatQty(hover.cum, scaler)}</div>
        </div>
      )}
    </div>
  );
}
