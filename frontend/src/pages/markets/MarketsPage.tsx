import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CandlestickChart, Star } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { useSymbols, useOrderBook, useTrades } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice } from "./format";

// Fallback catalog if the symbols endpoint errors or returns empty.
const FALLBACK_SYMBOLS: MarketSymbol[] = [
  { symbol: "BTCUSDC", symbol_id: 1, instrument_id: 1, price_scaler: 1, lot_size: 1, reference_price: 100000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "ETHUSDC", symbol_id: 2, instrument_id: 2, price_scaler: 1, lot_size: 1, reference_price: 3000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "SOLUSDC", symbol_id: 3, instrument_id: 3, price_scaler: 1, lot_size: 1, reference_price: 150, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
];

const FAV_KEY = "markets_favorites";

function MarketRow({ sym, fav, onToggleFav }: { sym: MarketSymbol; fav: boolean; onToggleFav: (id: number) => void }) {
  const navigate = useNavigate();
  const scaler = sym.price_scaler || 1;
  const book = useOrderBook(sym.symbol_id);
  const trades = useTrades(sym.symbol_id);

  const bestBid = book.data?.bid_px ?? book.data?.bids?.[0]?.[0];
  const bestAsk = book.data?.ask_px ?? book.data?.asks?.[0]?.[0];
  const lastTrade = trades.data?.trades?.[0]?.price;
  const mid = bestBid != null && bestAsk != null ? (bestBid + bestAsk) / 2 : undefined;
  const last = lastTrade ?? mid ?? sym.reference_price;
  const spread = bestBid != null && bestAsk != null ? bestAsk - bestBid : undefined;

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
      <TableCell className="text-right tabular-nums text-emerald-600 dark:text-emerald-400">
        {bestBid != null ? formatPrice(bestBid, scaler) : "—"}
      </TableCell>
      <TableCell className="text-right tabular-nums text-rose-600 dark:text-rose-400">
        {bestAsk != null ? formatPrice(bestAsk, scaler) : "—"}
      </TableCell>
      <TableCell className="text-right tabular-nums text-muted-foreground">
        {spread != null ? formatPrice(spread, scaler) : "—"}
      </TableCell>
    </TableRow>
  );
}

export default function MarketsPage() {
  const symbolsQuery = useSymbols();
  const apiSymbols = symbolsQuery.data?.symbols ?? [];
  const base = apiSymbols.length > 0 ? apiSymbols : FALLBACK_SYMBOLS;

  const [query, setQuery] = useState("");
  const [favorites, setFavorites] = useState<number[]>(() => {
    try {
      const raw = localStorage.getItem(FAV_KEY);
      return raw ? (JSON.parse(raw) as number[]) : [];
    } catch {
      return [];
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(FAV_KEY, JSON.stringify(favorites));
    } catch {
      /* ignore */
    }
  }, [favorites]);
  const toggleFav = (id: number) =>
    setFavorites((f) => (f.includes(id) ? f.filter((x) => x !== id) : [...f, id]));

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q ? base.filter((s) => s.symbol.toLowerCase().includes(q)) : base;
    return [...filtered].sort(
      (a, b) => (favorites.includes(a.symbol_id) ? 0 : 1) - (favorites.includes(b.symbol_id) ? 0 : 1)
    );
  }, [base, query, favorites]);

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
          <CardDescription>Prices update every 2 seconds. Star a market to pin it.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-3">
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
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Symbol</TableHead>
                  <TableHead className="text-right">Last</TableHead>
                  <TableHead className="text-right">Bid</TableHead>
                  <TableHead className="text-right">Ask</TableHead>
                  <TableHead className="text-right">Spread</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((sym) => (
                  <MarketRow
                    key={sym.symbol_id}
                    sym={sym}
                    fav={favorites.includes(sym.symbol_id)}
                    onToggleFav={toggleFav}
                  />
                ))}
                {rows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-4 text-center text-sm text-muted-foreground">
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
