import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CandlestickChart, Star } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { useSymbols, useCandles } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice } from "./format";
import { loadDefaultSymbol } from "@/lib/tradingPrefs";
import { useWatchlist } from "@/hooks/useWatchlist";
import {
  ALL_CLASS,
  CLASS_EMPTY_COPY,
  CLASS_LABELS,
  CLASS_TAB_ORDER,
  symbolInClass,
  type ClassTab,
  type InstrumentClass,
} from "@/lib/instrumentClass";
import {
  usePredictionProbe,
  useLatestFundingRates,
  fundingIntervalOf,
} from "@/hooks/useInstrumentClasses";
import { impliedYes, type PmState } from "@/api/endpoints/trading";

// Fallback catalog if the symbols endpoint errors or returns empty.
const FALLBACK_SYMBOLS: MarketSymbol[] = [
  { symbol: "BTCUSDC", symbol_id: 1, instrument_id: 1, price_scaler: 1, lot_size: 1, reference_price: 100000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "ETHUSDC", symbol_id: 2, instrument_id: 2, price_scaler: 1, lot_size: 1, reference_price: 3000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "SOLUSDC", symbol_id: 3, instrument_id: 3, price_scaler: 1, lot_size: 1, reference_price: 150, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
];

/** Format a funding interval (seconds) as a compact human string. */
function formatInterval(seconds: number | undefined): string {
  if (!seconds || seconds <= 0) return "—";
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Tiny inline SVG sparkline of recent closes. */
function Sparkline({ closes, up }: { closes: number[]; up: boolean }) {
  const width = 88;
  const height = 28;
  if (closes.length < 2) {
    return <svg width={width} height={height} aria-hidden />;
  }
  const min = Math.min(...closes);
  const max = Math.max(...closes);
  const range = max - min || 1;
  const step = width / (closes.length - 1);
  const points = closes
    .map((c, i) => {
      const x = i * step;
      const y = height - 2 - ((c - min) / range) * (height - 4);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible" aria-hidden>
      <polyline
        points={points}
        fill="none"
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        className={up ? "stroke-emerald-500" : "stroke-rose-500"}
      />
    </svg>
  );
}

interface RowExtras {
  /** Funding tab: latest funding rate in bps (undefined -> em dash). */
  fundingRateBps?: number;
  /** Prediction tab: the live PM state, for the implied-YES column. */
  pm?: PmState;
}

function MarketRow({
  sym,
  fav,
  onToggleFav,
  activeClass,
  extras,
}: {
  sym: MarketSymbol;
  fav: boolean;
  onToggleFav: (id: number) => void;
  activeClass: ClassTab;
  extras: RowExtras;
}) {
  const navigate = useNavigate();
  const scaler = sym.price_scaler || 1;
  // 60s candles, most-recent window; bars are ordered oldest -> newest.
  const candles = useCandles(sym.symbol_id, 60, true, 60);
  const bars = candles.data?.bars ?? [];

  const closes = bars.map((b) => b.close);
  const last = closes.length ? closes[closes.length - 1]! : sym.reference_price;
  const first = closes.length ? closes[0]! : undefined;
  const changePct = first != null && first !== 0 ? ((last - first) / first) * 100 : undefined;
  const up = (changePct ?? 0) >= 0;

  const yes = activeClass === "prediction" ? impliedYes(last, extras.pm?.face_value) : null;

  return (
    <TableRow className="cursor-pointer" onClick={() => navigate(`/markets/${sym.symbol_id}`)}>
      <TableCell className="w-8 pr-0">
        <button
          type="button"
          aria-label="Toggle watchlist"
          onClick={(e) => {
            e.stopPropagation();
            onToggleFav(sym.symbol_id);
          }}
        >
          <Star className={cn("h-4 w-4", fav ? "fill-amber-400 text-amber-400" : "text-muted-foreground hover:text-amber-400")} />
        </button>
      </TableCell>
      <TableCell className="font-medium">{sym.symbol}</TableCell>
      <TableCell className="text-right tabular-nums">{formatPrice(last, scaler)}</TableCell>
      <TableCell
        className={cn(
          "text-right tabular-nums",
          changePct == null ? "text-muted-foreground" : up ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"
        )}
      >
        {changePct == null ? "—" : `${up ? "+" : ""}${changePct.toFixed(2)}%`}
      </TableCell>
      {activeClass === "funding" && (
        <>
          <TableCell className="text-right tabular-nums">{formatInterval(fundingIntervalOf(sym))}</TableCell>
          <TableCell className="text-right tabular-nums">
            {extras.fundingRateBps == null ? "—" : `${extras.fundingRateBps} bps`}
          </TableCell>
        </>
      )}
      {activeClass === "prediction" && (
        <TableCell className="text-right tabular-nums">
          {yes == null ? "—" : `${(yes * 100).toFixed(1)}%`}
        </TableCell>
      )}
      <TableCell className="hidden text-right sm:table-cell">
        <div className="flex justify-end">
          <Sparkline closes={closes} up={up} />
        </div>
      </TableCell>
    </TableRow>
  );
}

type WatchTab = "all" | "watchlist";

export default function MarketsPage() {
  const symbolsQuery = useSymbols();
  const apiSymbols = symbolsQuery.data?.symbols ?? [];
  const base = apiSymbols.length > 0 ? apiSymbols : FALLBACK_SYMBOLS;

  // One-time-per-session auto-open of the saved default market. Fires only
  // after real symbols have loaded and only if the saved id is still valid.
  const navigate = useNavigate();
  useEffect(() => {
    if (!symbolsQuery.data) return; // wait for the query to resolve
    if (sessionStorage.getItem("md.defaultOpened") === "1") return;
    const id = loadDefaultSymbol();
    if (id == null) return;
    if (!apiSymbols.some((s) => s.symbol_id === id)) return; // stale/removed
    try {
      sessionStorage.setItem("md.defaultOpened", "1");
    } catch {
      /* ignore */
    }
    navigate(`/markets/${id}`, { replace: true });
  }, [symbolsQuery.data, apiSymbols, navigate]);

  const [query, setQuery] = useState("");
  const [watchTab, setWatchTab] = useState<WatchTab>("all");
  const [classTab, setClassTab] = useState<ClassTab>(ALL_CLASS);
  // Unified cross-instrument watchlist; this page shows/toggles the SYMBOL kind.
  const { items: watchItems, has: hasWatch, toggle: toggleWatch } = useWatchlist();
  const watchlist = useMemo(
    () =>
      watchItems
        .filter((w) => w.kind === "symbol")
        .map((w) => Number(w.id))
        .filter((n) => Number.isFinite(n)),
    [watchItems],
  );

  const toggleFav = (id: number) => toggleWatch("symbol", id);

  const isFav = (id: number) => hasWatch("symbol", id);

  // Search + watchlist pre-filter (class-agnostic), shared by both the class
  // probe scope and the final rows so we only probe what could be shown.
  const preClass = useMemo(() => {
    const q = query.trim().toLowerCase();
    let filtered = q ? base.filter((s) => s.symbol.toLowerCase().includes(q)) : base.slice();
    if (watchTab === "watchlist") {
      const order = new Map(watchlist.map((id, i) => [id, i]));
      filtered = filtered
        .filter((s) => order.has(s.symbol_id))
        .sort((a, b) => order.get(a.symbol_id)! - order.get(b.symbol_id)!);
    }
    return filtered;
  }, [base, query, watchTab, watchlist]);

  // PM probe: ONLY probe the currently-visible slice, and only when the
  // Prediction tab is active (avoids a probe storm across the whole catalog).
  const predictionActive = classTab === "prediction";
  const probe = usePredictionProbe(
    predictionActive ? preClass.map((s) => s.symbol_id) : [],
    predictionActive,
  );

  // Funding rates: only needed for the Funding tab; the feed is cheap + shared.
  const fundingActive = classTab === "funding";
  const fundingRates = useLatestFundingRates(fundingActive);

  const rows = useMemo(
    () =>
      preClass.filter((s) =>
        symbolInClass(s, classTab, { isPrediction: probe.isPrediction(s.symbol_id) }),
      ),
    [preClass, classTab, probe],
  );

  const emptyWatchlist = watchTab === "watchlist" && watchlist.length === 0;

  // Column span for the "no rows" cell adapts to the extra columns.
  const colSpan = 5 + (classTab === "funding" ? 2 : 0) + (classTab === "prediction" ? 1 : 0);

  const emptyClassCopy =
    classTab !== ALL_CLASS && rows.length === 0 && !emptyWatchlist && !query
      ? CLASS_EMPTY_COPY[classTab as InstrumentClass]
      : null;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <CandlestickChart className="h-6 w-6 text-muted-foreground" />
        <div>
          <h1 className="text-2xl font-semibold">Markets</h1>
          <p className="text-sm text-muted-foreground">Live exchange market data — tap a symbol to trade.</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Instruments</CardTitle>
          <CardDescription>Prices update live. Star a market to add it to your watchlist.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex flex-col gap-3">
            <Tabs value={classTab} onValueChange={(v) => setClassTab(v as ClassTab)}>
              <TabsList>
                {CLASS_TAB_ORDER.map((t) => (
                  <TabsTrigger key={t} value={t}>
                    {CLASS_LABELS[t]}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <Tabs value={watchTab} onValueChange={(v) => setWatchTab(v as WatchTab)}>
                <TabsList>
                  <TabsTrigger value="all">All</TabsTrigger>
                  <TabsTrigger value="watchlist">
                    Watchlist{watchlist.length > 0 ? ` (${watchlist.length})` : ""}
                  </TabsTrigger>
                </TabsList>
              </Tabs>
              <Input
                placeholder="Search symbol…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="max-w-xs"
              />
            </div>
          </div>
          {symbolsQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : emptyWatchlist ? (
            <div className="flex flex-col items-center gap-2 py-10 text-center">
              <Star className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm font-medium">Your watchlist is empty</p>
              <p className="text-sm text-muted-foreground">
                Tap the star on any market in the “All” tab to add it here.
              </p>
            </div>
          ) : emptyClassCopy ? (
            <div className="flex flex-col items-center gap-2 py-10 text-center">
              <CandlestickChart className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm font-medium">{emptyClassCopy}</p>
              {predictionActive && probe.isProbing && (
                <p className="text-sm text-muted-foreground">Checking for live prediction markets…</p>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Symbol</TableHead>
                  <TableHead className="text-right">Last</TableHead>
                  <TableHead className="text-right">Chg %</TableHead>
                  {classTab === "funding" && (
                    <>
                      <TableHead className="text-right">Interval</TableHead>
                      <TableHead className="text-right">Rate (bps)</TableHead>
                    </>
                  )}
                  {classTab === "prediction" && <TableHead className="text-right">Implied YES</TableHead>}
                  <TableHead className="hidden text-right sm:table-cell">Trend</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((sym) => (
                  <MarketRow
                    key={sym.symbol_id}
                    sym={sym}
                    fav={isFav(sym.symbol_id)}
                    onToggleFav={toggleFav}
                    activeClass={classTab}
                    extras={{
                      fundingRateBps: fundingRates.get(sym.symbol_id),
                      pm: probe.pmById.get(sym.symbol_id),
                    }}
                  />
                ))}
                {rows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={colSpan} className="py-4 text-center text-sm text-muted-foreground">
                      {query ? `No symbols match “${query}”.` : "No symbols to show."}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
