import { useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useSymbols, useOrderBook, useCandles, useTrades } from "@/hooks/useMarketData";
import type { BookLevel } from "@/api/endpoints/marketData";
import CandleChart from "./CandleChart";
import { formatPrice, formatQty, formatTimeNs } from "./format";

function DepthRow({
  level,
  side,
  maxQty,
  scaler,
}: {
  level: BookLevel;
  side: "bid" | "ask";
  maxQty: number;
  scaler: number;
}) {
  const [price, qty] = level;
  const pct = maxQty > 0 ? Math.min(100, (qty / maxQty) * 100) : 0;
  const isBid = side === "bid";
  return (
    <div className="relative flex items-center justify-between px-2 py-0.5 text-sm tabular-nums">
      <div
        className={cn(
          "absolute inset-y-0 right-0",
          isBid ? "bg-emerald-500/10" : "bg-rose-500/10"
        )}
        style={{ width: pct + "%" }}
      />
      <span
        className={cn(
          "relative z-10 font-medium",
          isBid ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"
        )}
      >
        {formatPrice(price, scaler)}
      </span>
      <span className="relative z-10 text-muted-foreground">{formatQty(qty, scaler)}</span>
    </div>
  );
}

export default function SymbolDetailPage() {
  const { symbolId } = useParams<{ symbolId: string }>();
  const id = Number(symbolId);

  const symbolsQuery = useSymbols();
  const book = useOrderBook(id);
  const candles = useCandles(id, 60);
  const trades = useTrades(id);

  const meta = useMemo(
    () => symbolsQuery.data?.symbols.find((s) => s.symbol_id === id),
    [symbolsQuery.data, id]
  );
  const scaler = meta?.price_scaler || 1;
  const label = meta?.symbol ?? ("Symbol " + id);

  const asks = useMemo(() => {
    const rows = [...(book.data?.asks ?? [])].sort((a, b) => a[0] - b[0]);
    return rows.slice(0, 12);
  }, [book.data]);
  const bids = useMemo(() => {
    const rows = [...(book.data?.bids ?? [])].sort((a, b) => b[0] - a[0]);
    return rows.slice(0, 12);
  }, [book.data]);
  const maxQty = useMemo(() => {
    const all = [...asks, ...bids].map((l) => l[1]);
    return all.length ? Math.max(...all) : 0;
  }, [asks, bids]);

  const bestBid = book.data?.bid_px ?? bids[0]?.[0];
  const bestAsk = book.data?.ask_px ?? asks[0]?.[0];
  const spread = bestBid != null && bestAsk != null ? bestAsk - bestBid : undefined;

  const bars = candles.data?.bars ?? [];
  const recentTrades = trades.data?.trades ?? [];

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/markets"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Markets
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold">{label}</h1>
          {meta?.is_perpetual && <Badge variant="secondary">Perpetual</Badge>}
          {meta && <Badge variant="outline">{meta.matching_algo}</Badge>}
          {spread != null && (
            <span className="text-sm text-muted-foreground">
              Spread {formatPrice(spread, scaler)}
            </span>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Price (1m candles)</CardTitle>
          <CardDescription>Green = up, red = down. Updates every 2 seconds.</CardDescription>
        </CardHeader>
        <CardContent>
          {candles.isLoading ? (
            <Skeleton className="h-[320px] w-full" />
          ) : (
            <div className="text-muted-foreground">
              <CandleChart bars={bars} scaler={scaler} />
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Order Book</CardTitle>
            <CardDescription>Best bid/ask ladder with depth.</CardDescription>
          </CardHeader>
          <CardContent>
            {book.isLoading ? (
              <Skeleton className="h-64 w-full" />
            ) : (
              <div>
                <div className="flex justify-between px-2 pb-1 text-xs uppercase text-muted-foreground">
                  <span>Price</span>
                  <span>Qty</span>
                </div>
                <div className="flex flex-col-reverse">
                  {asks.map((l, i) => (
                    <DepthRow key={"a" + i} level={l} side="ask" maxQty={maxQty} scaler={scaler} />
                  ))}
                </div>
                <div className="my-1 flex items-center justify-between border-y px-2 py-1 text-sm font-medium">
                  <span className="text-muted-foreground">Spread</span>
                  <span className="tabular-nums">
                    {spread != null ? formatPrice(spread, scaler) : "-"}
                  </span>
                </div>
                <div>
                  {bids.map((l, i) => (
                    <DepthRow key={"b" + i} level={l} side="bid" maxQty={maxQty} scaler={scaler} />
                  ))}
                </div>
                {asks.length === 0 && bids.length === 0 && (
                  <p className="py-4 text-center text-sm text-muted-foreground">
                    No book data.
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Trades</CardTitle>
            <CardDescription>Latest prints, newest first.</CardDescription>
          </CardHeader>
          <CardContent>
            {trades.isLoading ? (
              <Skeleton className="h-64 w-full" />
            ) : recentTrades.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">No trades.</p>
            ) : (
              <div>
                <div className="flex justify-between px-2 pb-1 text-xs uppercase text-muted-foreground">
                  <span>Price</span>
                  <span>Qty</span>
                  <span>Time</span>
                </div>
                <div className="max-h-72 overflow-y-auto">
                  {recentTrades.map((t, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between px-2 py-0.5 text-sm tabular-nums"
                    >
                      <span
                        className={cn(
                          "font-medium",
                          t.aggressor === "buy"
                            ? "text-emerald-600 dark:text-emerald-400"
                            : "text-rose-600 dark:text-rose-400"
                        )}
                      >
                        {formatPrice(t.price, scaler)}
                      </span>
                      <span className="text-muted-foreground">{formatQty(t.qty, scaler)}</span>
                      <span className="text-muted-foreground">{formatTimeNs(t.ts_ns)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
