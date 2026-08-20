import { useEffect, useMemo, useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { LineChart as LineChartIcon, AlertTriangle, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol, Candle } from "@/api/endpoints/marketData";
import {
  getHistory,
  intervalToSeconds,
  type HistoryResponse,
} from "@/api/endpoints/marketHistory";
import {
  backtestMaCross,
  computeStats,
  normalizeTo100,
  seriesCorrelation,
  type Bar,
} from "@/lib/marketStats";
import {
  ALL_CLASS,
  CLASS_LABELS,
  CLASS_TAB_ORDER,
  symbolInClass,
  type ClassTab,
} from "@/lib/instrumentClass";
import CandleChart from "@/pages/markets/CandleChart";
import { formatPrice } from "@/pages/markets/format";

// ── Config ─────────────────────────────────────────────────────────

const INTERVALS = [
  { label: "1m", token: "1m" },
  { label: "5m", token: "5m" },
  { label: "15m", token: "15m" },
  { label: "1h", token: "1h" },
  { label: "1d", token: "1d" },
] as const;

/** Range = target number of bars to assemble (paginating history if needed). */
const RANGES = [
  { label: "200", bars: 200 },
  { label: "500", bars: 500 },
  { label: "1k", bars: 1000 },
  { label: "2k", bars: 2000 },
] as const;

const MAX_COMPARE = 4;
const MAX_PAGES = 6; // cap history pagination so we never loop unbounded

// Overlay colors for the compare chart / correlation headers.
const SERIES_COLORS = ["#0ea5e9", "#f59e0b", "#8b5cf6", "#ec4899", "#22c55e"];

// ── History assembly hook ──────────────────────────────────────────

/** Contract bar type is raw-integer priced; de-scale for display/stats. */
function toBars(res: HistoryResponse, scaler: number): Bar[] {
  const s = scaler || 1;
  return res.bars.map((b) => ({
    ts: b.ts,
    o: b.o / s,
    h: b.h / s,
    l: b.l / s,
    c: b.c / s,
    v: b.v,
  }));
}

/** Bars mapped back to the exchange `Candle` shape CandleChart expects. */
function toCandles(bars: Bar[], scaler: number): Candle[] {
  const s = scaler || 1;
  return bars.map((b) => ({
    open: b.o * s,
    high: b.h * s,
    low: b.l * s,
    close: b.c * s,
    volume: b.v,
    trades: 0,
    ts_start_ns: b.ts * 1_000_000,
  }));
}

interface AssembledHistory {
  bars: Bar[];
  stub: boolean;
}

/**
 * Fetch and assemble up to `targetBars` of history for one symbol, following
 * `next_cursor` when present (capped at {@link MAX_PAGES}). De-scales prices.
 */
function useHistory(symbolId: number | null, interval: string, targetBars: number, scaler: number) {
  return useQuery<AssembledHistory>({
    queryKey: ["md", "history", symbolId, interval, targetBars],
    enabled: symbolId != null && symbolId > 0,
    staleTime: 30_000,
    queryFn: async () => {
      const id = symbolId as number;
      const acc: Bar[] = [];
      let stub = false;
      let cursor: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const res = await getHistory(id, { interval, cursor });
        stub = stub || !!res.stub;
        acc.push(...toBars(res, scaler));
        if (res.stub || !res.next_cursor || acc.length >= targetBars) break;
        cursor = res.next_cursor;
      }
      // Keep chronological order; trim to the most recent `targetBars`.
      acc.sort((a, b) => a.ts - b.ts);
      const trimmed = acc.length > targetBars ? acc.slice(acc.length - targetBars) : acc;
      return { bars: trimmed, stub };
    },
  });
}

// ── Small presentational helpers ───────────────────────────────────

function pct(x: number | null | undefined, digits = 2): string {
  if (x == null || !Number.isFinite(x)) return "—";
  return `${(x * 100).toFixed(digits)}%`;
}

function StatRow({ label, value, tone }: { label: string; value: string; tone?: "up" | "down" }) {
  return (
    <div className="flex items-center justify-between py-1 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span
        className={cn(
          "tabular-nums font-medium",
          tone === "up" && "text-emerald-600 dark:text-emerald-400",
          tone === "down" && "text-rose-600 dark:text-rose-400",
        )}
      >
        {value}
      </span>
    </div>
  );
}

/** Overlay of several normalized-to-100 close series. */
function CompareChart({
  series,
  height = 260,
}: {
  series: { symbol: string; color: string; points: { ts: number; v: number }[] }[];
  height?: number;
}) {
  const width = 720;
  const PAD = { t: 8, r: 48, b: 8, l: 8 };
  const layout = useMemo(() => {
    const withData = series.filter((s) => s.points.length > 1);
    if (!withData.length) return null;
    let min = Infinity;
    let max = -Infinity;
    let n = 0;
    for (const s of withData) {
      n = Math.max(n, s.points.length);
      for (const p of s.points) {
        if (p.v < min) min = p.v;
        if (p.v > max) max = p.v;
      }
    }
    if (!Number.isFinite(min) || !Number.isFinite(max)) return null;
    if (min === max) {
      min -= 1;
      max += 1;
    }
    const plotW = width - PAD.l - PAD.r;
    const plotH = height - PAD.t - PAD.b;
    const yOf = (v: number) => PAD.t + ((max - v) / (max - min)) * plotH;
    const lines = withData.map((s) => {
      const step = s.points.length > 1 ? plotW / (s.points.length - 1) : 0;
      const pts = s.points
        .map((p, i) => `${(PAD.l + i * step).toFixed(1)},${yOf(p.v).toFixed(1)}`)
        .join(" ");
      const lastV = s.points[s.points.length - 1]!.v;
      return { symbol: s.symbol, color: s.color, pts, lastV };
    });
    const ticks = 4;
    const labels = Array.from({ length: ticks + 1 }, (_, i) => {
      const v = max - ((max - min) * i) / ticks;
      return { y: yOf(v), value: v };
    });
    const baseY = min <= 100 && max >= 100 ? yOf(100) : null;
    return { lines, labels, baseY };
  }, [series, height]);

  if (!layout) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        Select at least one symbol with data to compare.
      </div>
    );
  }

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height }} preserveAspectRatio="none" role="img" aria-label="Normalized compare chart">
      {layout.labels.map((l, i) => (
        <g key={`g${i}`}>
          <line x1={PAD.l} x2={width - PAD.r} y1={l.y} y2={l.y} stroke="currentColor" strokeOpacity={0.1} />
          <text x={width - PAD.r + 4} y={l.y + 3} fontSize={10} fill="currentColor" fillOpacity={0.6}>
            {l.value.toFixed(0)}
          </text>
        </g>
      ))}
      {layout.baseY != null && (
        <line x1={PAD.l} x2={width - PAD.r} y1={layout.baseY} y2={layout.baseY} stroke="currentColor" strokeOpacity={0.25} strokeDasharray="4 3" />
      )}
      {layout.lines.map((ln) => (
        <polyline key={ln.symbol} points={ln.pts} fill="none" stroke={ln.color} strokeWidth={1.4} strokeOpacity={0.95} vectorEffect="non-scaling-stroke" />
      ))}
    </svg>
  );
}

/** Equity curve line (starts at 1.0). */
function EquityChart({ equity, height = 160 }: { equity: number[]; height?: number }) {
  const width = 720;
  const PAD = { t: 8, r: 48, b: 8, l: 8 };
  const layout = useMemo(() => {
    if (equity.length < 2) return null;
    let min = Math.min(...equity);
    let max = Math.max(...equity);
    if (min === max) {
      min -= 0.01;
      max += 0.01;
    }
    const plotW = width - PAD.l - PAD.r;
    const plotH = height - PAD.t - PAD.b;
    const step = plotW / (equity.length - 1);
    const yOf = (v: number) => PAD.t + ((max - v) / (max - min)) * plotH;
    const pts = equity.map((v, i) => `${(PAD.l + i * step).toFixed(1)},${yOf(v).toFixed(1)}`).join(" ");
    const oneY = min <= 1 && max >= 1 ? yOf(1) : null;
    const labels = [max, (max + min) / 2, min].map((v) => ({ y: yOf(v), value: v }));
    return { pts, oneY, labels };
  }, [equity, height]);

  if (!layout) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        Not enough bars to backtest.
      </div>
    );
  }
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height }} preserveAspectRatio="none" role="img" aria-label="Backtest equity curve">
      {layout.labels.map((l, i) => (
        <g key={`e${i}`}>
          <line x1={PAD.l} x2={width - PAD.r} y1={l.y} y2={l.y} stroke="currentColor" strokeOpacity={0.1} />
          <text x={width - PAD.r + 4} y={l.y + 3} fontSize={10} fill="currentColor" fillOpacity={0.6}>
            {l.value.toFixed(2)}x
          </text>
        </g>
      ))}
      {layout.oneY != null && (
        <line x1={PAD.l} x2={width - PAD.r} y1={layout.oneY} y2={layout.oneY} stroke="currentColor" strokeOpacity={0.25} strokeDasharray="4 3" />
      )}
      <polyline points={layout.pts} fill="none" stroke="#0ea5e9" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// ── Page ───────────────────────────────────────────────────────────

export default function MarketAnalysisPage() {
  const symbolsQuery = useSymbols();
  const symbols = symbolsQuery.data?.symbols ?? [];

  const [classTab, setClassTab] = useState<ClassTab>(ALL_CLASS);
  const [interval, setInterval] = useState<string>("1h");
  const [rangeBars, setRangeBars] = useState<number>(500);
  const [primaryId, setPrimaryId] = useState<number | null>(null);
  const [compareIds, setCompareIds] = useState<number[]>([]);
  const [search, setSearch] = useState("");
  const [fast, setFast] = useState(10);
  const [slow, setSlow] = useState(30);

  // Default primary to the first symbol once loaded.
  useEffect(() => {
    if (primaryId == null && symbols.length > 0) setPrimaryId(symbols[0]!.symbol_id);
  }, [symbols, primaryId]);

  const symById = useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbols) m.set(s.symbol_id, s);
    return m;
  }, [symbols]);

  const filteredSymbols = useMemo(() => {
    const q = search.trim().toLowerCase();
    return symbols.filter(
      (s) => symbolInClass(s, classTab) && (!q || s.symbol.toLowerCase().includes(q)),
    );
  }, [symbols, classTab, search]);

  const primary = primaryId != null ? symById.get(primaryId) ?? null : null;
  const primaryScaler = primary?.price_scaler || 1;

  // Primary history (drives the chart + stats + backtest).
  const primaryHist = useHistory(primaryId, interval, rangeBars, primaryScaler);
  const primaryBars = primaryHist.data?.bars ?? [];
  const isStub = !!primaryHist.data?.stub;

  const stats = useMemo(
    () => computeStats(primaryBars, intervalToSeconds(interval)),
    [primaryBars, interval],
  );

  // Compare set = primary + the selected compare symbols (deduped, capped).
  const compareSet = useMemo(() => {
    const ids: number[] = [];
    if (primaryId != null) ids.push(primaryId);
    for (const id of compareIds) if (!ids.includes(id)) ids.push(id);
    return ids.slice(0, MAX_COMPARE + 1);
  }, [primaryId, compareIds]);

  // One history query per compare symbol.
  const compareQueries = useQueries({
    queries: compareSet.map((id) => {
      const sc = symById.get(id)?.price_scaler || 1;
      return {
        queryKey: ["md", "history", id, interval, rangeBars],
        enabled: id > 0,
        staleTime: 30_000,
        queryFn: async (): Promise<AssembledHistory> => {
          const acc: Bar[] = [];
          let stub = false;
          let cursor: string | undefined;
          for (let page = 0; page < MAX_PAGES; page++) {
            const res = await getHistory(id, { interval, cursor });
            stub = stub || !!res.stub;
            acc.push(...toBars(res, sc));
            if (res.stub || !res.next_cursor || acc.length >= rangeBars) break;
            cursor = res.next_cursor;
          }
          acc.sort((a, b) => a.ts - b.ts);
          const trimmed = acc.length > rangeBars ? acc.slice(acc.length - rangeBars) : acc;
          return { bars: trimmed, stub };
        },
      };
    }),
  });

  const compareData = useMemo(
    () =>
      compareSet.map((id, i) => ({
        id,
        symbol: symById.get(id)?.symbol ?? `#${id}`,
        color: SERIES_COLORS[i % SERIES_COLORS.length]!,
        bars: (compareQueries[i]?.data as AssembledHistory | undefined)?.bars ?? [],
      })),
    [compareSet, compareQueries, symById],
  );

  const compareSeries = useMemo(
    () =>
      compareData.map((d) => ({
        symbol: d.symbol,
        color: d.color,
        points: normalizeTo100(d.bars),
      })),
    [compareData],
  );

  // Correlation matrix over aligned log-returns.
  const corrMatrix = useMemo(() => {
    const n = compareData.length;
    const m: number[][] = Array.from({ length: n }, () => new Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        m[i]![j] = i === j ? 1 : seriesCorrelation(compareData[i]!.bars, compareData[j]!.bars);
      }
    }
    return m;
  }, [compareData]);

  const backtest = useMemo(() => backtestMaCross(primaryBars, fast, slow), [primaryBars, fast, slow]);

  const chartCandles = useMemo(() => toCandles(primaryBars, primaryScaler), [primaryBars, primaryScaler]);

  function toggleCompare(id: number) {
    setCompareIds((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= MAX_COMPARE) return prev;
      return [...prev, id];
    });
  }

  const cumTone = stats.cumulativeReturn > 0 ? "up" : stats.cumulativeReturn < 0 ? "down" : undefined;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <LineChartIcon className="h-6 w-6" /> Analysis
        </h1>
        <p className="text-sm text-muted-foreground">
          Historical market-data research workbench: long-range charting, statistics, multi-symbol
          compare, correlation, and a moving-average crossover backtest.
        </p>
      </div>

      {isStub && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Recent window only — long-range history pending backend (<code>/md/history</code>).
          </span>
        </div>
      )}

      {/* Controls */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Instrument &amp; range</CardTitle>
          <CardDescription>Pick a primary symbol, interval and how many bars to analyze.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1">
              <span className="mr-1 text-xs text-muted-foreground">Interval</span>
              {INTERVALS.map((iv) => (
                <Button
                  key={iv.token}
                  type="button"
                  size="sm"
                  variant={interval === iv.token ? "default" : "outline"}
                  className="h-7 px-2 text-xs"
                  onClick={() => setInterval(iv.token)}
                >
                  {iv.label}
                </Button>
              ))}
            </div>
            <div className="flex items-center gap-1">
              <span className="mr-1 text-xs text-muted-foreground">Bars</span>
              {RANGES.map((r) => (
                <Button
                  key={r.bars}
                  type="button"
                  size="sm"
                  variant={rangeBars === r.bars ? "default" : "outline"}
                  className="h-7 px-2 text-xs"
                  onClick={() => setRangeBars(r.bars)}
                >
                  {r.label}
                </Button>
              ))}
            </div>
          </div>

          <Tabs value={classTab} onValueChange={(v) => setClassTab(v as ClassTab)}>
            <TabsList className="h-8">
              {CLASS_TAB_ORDER.map((t) => (
                <TabsTrigger key={t} value={t} className="text-xs">
                  {CLASS_LABELS[t]}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>

          <Input
            placeholder="Filter symbols…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 max-w-xs"
          />

          {symbolsQuery.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : (
            <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
              {filteredSymbols.map((s) => {
                const isPrimary = s.symbol_id === primaryId;
                const isCompare = compareIds.includes(s.symbol_id);
                return (
                  <div key={s.symbol_id} className="flex items-center">
                    <button
                      type="button"
                      onClick={() => setPrimaryId(s.symbol_id)}
                      className={cn(
                        "rounded-l border px-2 py-1 text-xs transition-colors",
                        isPrimary
                          ? "border-primary bg-primary text-primary-foreground"
                          : "border-border hover:bg-foreground/5",
                      )}
                      aria-pressed={isPrimary}
                    >
                      {s.symbol}
                    </button>
                    <button
                      type="button"
                      onClick={() => toggleCompare(s.symbol_id)}
                      disabled={isPrimary}
                      title={isCompare ? "Remove from compare" : "Add to compare"}
                      className={cn(
                        "rounded-r border border-l-0 px-1.5 py-1 text-xs transition-colors",
                        isCompare
                          ? "border-sky-500 bg-sky-500/20 text-sky-700 dark:text-sky-300"
                          : "border-border text-muted-foreground hover:bg-foreground/5",
                        isPrimary && "opacity-30",
                      )}
                    >
                      {isCompare ? "✓" : "+"}
                    </button>
                  </div>
                );
              })}
              {filteredSymbols.length === 0 && (
                <span className="text-sm text-muted-foreground">No symbols match.</span>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Chart + stats */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">
              {primary?.symbol ?? "—"} · {interval} · {primaryBars.length} bars
            </CardTitle>
            <CardDescription>Long-range candles (green up / red down).</CardDescription>
          </CardHeader>
          <CardContent>
            {primaryHist.isLoading ? (
              <Skeleton className="h-[320px] w-full" />
            ) : chartCandles.length ? (
              <div className="text-muted-foreground">
                <CandleChart bars={chartCandles} scaler={primaryScaler} intervalSec={intervalToSeconds(interval)} />
              </div>
            ) : (
              <div className="flex h-[320px] items-center justify-center text-sm text-muted-foreground">
                No history available for this symbol.
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Statistics</CardTitle>
            <CardDescription>Over the selected range.</CardDescription>
          </CardHeader>
          <CardContent>
            {primaryHist.isLoading ? (
              <Skeleton className="h-48 w-full" />
            ) : (
              <div className="divide-y">
                <StatRow label="Bars" value={String(stats.bars)} />
                <StatRow label="Cumulative return" value={pct(stats.cumulativeReturn)} tone={cumTone} />
                <StatRow label="Avg per-bar return" value={pct(stats.avgReturn, 3)} />
                <StatRow label="Volatility (per bar)" value={pct(stats.volatility, 3)} />
                <StatRow label="Volatility (annualized)" value={pct(stats.annualizedVolatility)} />
                <StatRow label="Max drawdown" value={pct(stats.maxDrawdown)} tone={stats.maxDrawdown < 0 ? "down" : undefined} />
                <StatRow label="High" value={stats.hi != null ? formatPrice(stats.hi * primaryScaler, primaryScaler) : "—"} />
                <StatRow label="Low" value={stats.lo != null ? formatPrice(stats.lo * primaryScaler, primaryScaler) : "—"} />
                <StatRow label="Avg volume" value={stats.avgVolume.toLocaleString(undefined, { maximumFractionDigits: 2 })} />
                <StatRow label="Total volume" value={stats.totalVolume.toLocaleString(undefined, { maximumFractionDigits: 2 })} />
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Compare + correlation */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="text-base">Compare (normalized to 100)</CardTitle>
                <CardDescription>Relative performance of the primary + compare symbols.</CardDescription>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {compareData.map((d) => (
                  <Badge key={d.id} variant="outline" className="gap-1" style={{ borderColor: d.color, color: d.color }}>
                    {d.symbol}
                    {d.id !== primaryId && (
                      <button type="button" onClick={() => toggleCompare(d.id)} aria-label={`Remove ${d.symbol}`}>
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </Badge>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <CompareChart series={compareSeries} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Correlation</CardTitle>
            <CardDescription>Log-return correlation across the compare set.</CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            {compareData.length < 2 ? (
              <p className="text-sm text-muted-foreground">Add at least one compare symbol.</p>
            ) : (
              <table className="w-full border-collapse text-xs tabular-nums">
                <thead>
                  <tr>
                    <th className="p-1" />
                    {compareData.map((d) => (
                      <th key={d.id} className="p-1 text-center" style={{ color: d.color }}>
                        {d.symbol}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {compareData.map((row, i) => (
                    <tr key={row.id}>
                      <th className="p-1 text-left" style={{ color: row.color }}>
                        {row.symbol}
                      </th>
                      {compareData.map((col, j) => {
                        const v = corrMatrix[i]?.[j] ?? 0;
                        const bg =
                          v > 0
                            ? `rgba(16,185,129,${Math.min(0.6, Math.abs(v) * 0.6)})`
                            : `rgba(225,29,72,${Math.min(0.6, Math.abs(v) * 0.6)})`;
                        return (
                          <td key={col.id} className="p-1 text-center" style={{ backgroundColor: i === j ? undefined : bg }}>
                            {v.toFixed(2)}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Backtest */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="text-base">MA-crossover backtest</CardTitle>
              <CardDescription>
                Long when fast SMA &gt; slow SMA, flat otherwise. {primary?.symbol ?? "—"} · {interval}.
              </CardDescription>
            </div>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                Fast
                <Input
                  type="number"
                  min={1}
                  value={fast}
                  onChange={(e) => setFast(Math.max(1, Number(e.target.value) || 1))}
                  className="h-7 w-16"
                />
              </label>
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                Slow
                <Input
                  type="number"
                  min={2}
                  value={slow}
                  onChange={(e) => setSlow(Math.max(2, Number(e.target.value) || 2))}
                  className="h-7 w-16"
                />
              </label>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {fast >= slow && (
            <p className="text-sm text-amber-600 dark:text-amber-400">Fast period must be smaller than slow.</p>
          )}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div>
              <div className="text-xs text-muted-foreground">Total return</div>
              <div
                className={cn(
                  "text-lg font-semibold tabular-nums",
                  backtest.totalReturn > 0 && "text-emerald-600 dark:text-emerald-400",
                  backtest.totalReturn < 0 && "text-rose-600 dark:text-rose-400",
                )}
              >
                {pct(backtest.totalReturn)}
              </div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Trades</div>
              <div className="text-lg font-semibold tabular-nums">{backtest.numTrades}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Win rate</div>
              <div className="text-lg font-semibold tabular-nums">{pct(backtest.winRate, 1)}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Buy &amp; hold</div>
              <div className="text-lg font-semibold tabular-nums">{pct(stats.cumulativeReturn)}</div>
            </div>
          </div>
          <EquityChart equity={backtest.equity} />
        </CardContent>
      </Card>
    </div>
  );
}
