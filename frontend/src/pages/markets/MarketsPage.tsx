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

// Fallback catalog if the symbols endpoint errors or returns empty.
const FALLBACK_SYMBOLS: MarketSymbol[] = [
  { symbol: "BTCUSDC", symbol_id: 1, instrument_id: 1, price_scaler: 1, lot_size: 1, reference_price: 100000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "ETHUSDC", symbol_id: 2, instrument_id: 2, price_scaler: 1, lot_size: 1, reference_price: 3000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "SOLUSDC", symbol_id: 3, instrument_id: 3, price_scaler: 1, lot_size: 1, reference_price: 150, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
];

// Client-side watchlist. Stable insertion order preserved as an id array.
const WATCHLIST_KEY = "md.watchlist.v1";

function loadWatchlist(): number[] {
  try {
    const raw = localStorage.getItem(WATCHLIST_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "number") : [];
  } catch {
    return [];
  }
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

function MarketRow({ sym, fav, onToggleFav }: { sym: MarketSymbol; fav: boolean; onToggleFav: (id: number) => void }) {
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
      <TableCell className="hidden text-right sm:table-cell">
        <div className="flex justify-end">
          <Sparkline closes={closes} up={up} />
        </div>
      </TableCell>
    </TableRow>
  );
}

type FilterTab = "all" | "watchlist";

export default function MarketsPage() {
  const symbolsQuery = useSymbols();
  const apiSymbols = symbolsQuery.data?.symbols ?? [];
  const base = apiSymbols.length > 0 ? apiSymbols : FALLBACK_SYMBOLS;

  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<FilterTab>("all");
  const [watchlist, setWatchlist] = useState<number[]>(loadWatchlist);

  useEffect(() => {
    try {
      localStorage.setItem(WATCHLIST_KEY, JSON.stringify(watchlist));
    } catch {
      /* ignore */
    }
  }, [watchlist]);

  const toggleFav = (id: number) =>
    setWatchlist((w) => (w.includes(id) ? w.filter((x) => x !== id) : [...w, id]));

  const isFav = (id: number) => watchlist.includes(id);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    let filtered = q ? base.filter((s) => s.symbol.toLowerCase().includes(q)) : base.slice();
    if (tab === "watchlist") {
      // Preserve stable starred order (order in which they were added).
      const order = new Map(watchlist.map((id, i) => [id, i]));
      filtered = filtered
        .filter((s) => order.has(s.symbol_id))
        .sort((a, b) => order.get(a.symbol_id)! - order.get(b.symbol_id)!);
    }
    return filtered;
  }, [base, query, tab, watchlist]);

  const emptyWatchlist = tab === "watchlist" && watchlist.length === 0;

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
          <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <Tabs value={tab} onValueChange={(v) => setTab(v as FilterTab)}>
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
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Symbol</TableHead>
                  <TableHead className="text-right">Last</TableHead>
                  <TableHead className="text-right">Chg %</TableHead>
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
                  />
                ))}
                {rows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="py-4 text-center text-sm text-muted-foreground">
                      No symbols match “{query}”.
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
