import { useNavigate } from "react-router-dom";
import { TrendingUp } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useCandles, useSymbols } from "@/hooks/useMarketData";
import { formatPrice } from "@/pages/markets/format";
import { changePctFromCloses } from "@/lib/tradingCards";

/** Tiny inline SVG sparkline of recent closes (mirrors MarketsPage). */
function Sparkline({ closes, up }: { closes: number[]; up: boolean }) {
  const width = 96;
  const height = 30;
  if (closes.length < 2) {
    return <svg width={width} height={height} aria-hidden data-testid="market-card-sparkline" />;
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
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="overflow-visible"
      aria-hidden
      data-testid="market-card-sparkline"
    >
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

export interface MarketCardProps {
  symbolId: number;
  symbol: string;
}

/**
 * FE-101: an in-chat market card. Ticker + live price + change% + mini
 * sparkline + a Trade button that opens the order ticket pre-filled. Live data
 * reuses the same md hooks (useCandles / useSymbols) the markets surfaces poll.
 */
export function MarketCard({ symbolId, symbol }: MarketCardProps) {
  const navigate = useNavigate();
  const symbolsQ = useSymbols();
  const scaler =
    symbolsQ.data?.symbols?.find((s) => s.symbol_id === symbolId)?.price_scaler || 1;

  // 60s candles, most-recent window; oldest -> newest. Same feed as MarketsPage.
  const candles = useCandles(symbolId, 60, symbolId > 0, 60);
  const bars = candles.data?.bars ?? [];
  const closes = bars.map((b) => b.close);
  const last = closes.length ? closes[closes.length - 1]! : undefined;
  const changePct = changePctFromCloses(closes);
  const up = (changePct ?? 0) >= 0;

  return (
    <Card className="w-72 max-w-full" data-testid="market-card">
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 text-sm font-semibold">
              <TrendingUp className="h-4 w-4 shrink-0 text-muted-foreground" />
              <span className="truncate" data-testid="market-card-ticker">
                {symbol}
              </span>
            </div>
            <div className="mt-1 text-xl font-bold tabular-nums" data-testid="market-card-price">
              {last != null ? formatPrice(last, scaler) : "—"}
            </div>
            <div
              className={
                "text-xs font-medium tabular-nums " +
                (changePct == null
                  ? "text-muted-foreground"
                  : up
                    ? "text-emerald-600 dark:text-emerald-400"
                    : "text-rose-600 dark:text-rose-400")
              }
              data-testid="market-card-change"
            >
              {changePct == null ? "—" : `${up ? "+" : ""}${changePct.toFixed(2)}%`}
            </div>
          </div>
          <Sparkline closes={closes} up={up} />
        </div>
        <Button
          size="sm"
          className="mt-3 w-full"
          onClick={() => navigate(`/markets/${symbolId}`)}
          data-testid="market-card-trade"
        >
          Trade
        </Button>
      </CardContent>
    </Card>
  );
}

export default MarketCard;
