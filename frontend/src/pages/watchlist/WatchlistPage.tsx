import { useMemo } from "react";
import { Link } from "react-router-dom";
import { Star, Coins, Landmark, Boxes, CandlestickChart } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { useWatchlist } from "@/hooks/useWatchlist";
import { useSymbols, useCandles } from "@/hooks/useMarketData";
import { useTokenMarket } from "@/hooks/useTokens";
import { useStrategyMarket } from "@/hooks/useStrategies";
import { formatPrice } from "@/pages/markets/format";
import { formatCents, formatBps } from "@/lib/tokens";
import { sortWatchItems, kindLabel, type WatchItem } from "@/lib/watchlist";

const KIND_ICON = {
  symbol: <CandlestickChart className="h-4 w-4 text-muted-foreground" />,
  token: <Coins className="h-4 w-4 text-muted-foreground" />,
  strategy: <Boxes className="h-4 w-4 text-muted-foreground" />,
} as const;

const KIND_VARIANT = {
  symbol: "default",
  token: "secondary",
  strategy: "outline",
} as const;

function UnwatchButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      aria-label="Remove from watchlist"
      onClick={(e) => {
        e.stopPropagation();
        e.preventDefault();
        onClick();
      }}
    >
      <Star className="h-4 w-4 fill-amber-400 text-amber-400" />
    </button>
  );
}

/** A watched exchange symbol row — live last/change from 60s candles. */
function SymbolRow({
  symbolId,
  onRemove,
}: {
  symbolId: number;
  onRemove: () => void;
}) {
  const symbolsQ = useSymbols();
  const sym = (symbolsQ.data?.symbols ?? []).find((s) => s.symbol_id === symbolId);
  const scaler = sym?.price_scaler || 1;
  const candles = useCandles(symbolId, 60, true, 60);
  const bars = candles.data?.bars ?? [];
  const closes = bars.map((b) => b.close);
  const last = closes.length ? closes[closes.length - 1]! : sym?.reference_price;
  const first = closes.length ? closes[0]! : undefined;
  const changePct =
    first != null && first !== 0 && last != null ? ((last - first) / first) * 100 : undefined;
  const up = (changePct ?? 0) >= 0;

  const label = sym?.symbol ?? `Symbol ${symbolId}`;
  const to = `/markets/${symbolId}`;

  return (
    <WatchRow
      to={to}
      kind="symbol"
      title={label}
      subtitle="Exchange symbol"
      value={last != null ? formatPrice(last, scaler) : "—"}
      change={changePct == null ? "—" : `${up ? "+" : ""}${changePct.toFixed(2)}%`}
      changeUp={changePct == null ? undefined : up}
      onRemove={onRemove}
    />
  );
}

/** A watched creator token row — clearing price from the token market feed. */
function TokenRow({ tokenId, onRemove }: { tokenId: string; onRemove: () => void }) {
  const marketQ = useTokenMarket();
  const tok = (marketQ.data?.tokens ?? []).find((t) => t.token_id === tokenId);
  const title = tok ? `${tok.ticker}` : `Token ${tokenId}`;
  const subtitle = tok?.name ?? "Creator token";
  return (
    <WatchRow
      to={`/tokens/${encodeURIComponent(tokenId)}`}
      kind="token"
      title={title}
      subtitle={subtitle}
      value={tok?.clearing_price != null ? formatCents(tok.clearing_price) : "—"}
      change={tok ? tok.status : "—"}
      onRemove={onRemove}
    />
  );
}

/** A watched strategy fund row — NAV per unit + inception return. */
function StrategyRow({ strategyId, onRemove }: { strategyId: string; onRemove: () => void }) {
  const marketQ = useStrategyMarket();
  const st = (marketQ.data?.strategies ?? []).find((s) => s.strategy_id === strategyId);
  const title = st?.name ?? `Strategy ${strategyId}`;
  const ret = st?.inception_return_bps;
  const up = ret == null ? undefined : ret >= 0;
  return (
    <WatchRow
      to={`/strategies/${encodeURIComponent(strategyId)}`}
      kind="strategy"
      title={title}
      subtitle="Strategy fund"
      value={st?.nav_per_unit != null ? formatCents(st.nav_per_unit) : "—"}
      change={ret == null ? "—" : `${up ? "+" : ""}${formatBps(ret)}`}
      changeUp={up}
      onRemove={onRemove}
    />
  );
}

/** Shared presentational row (deep-links to the item's detail page). */
function WatchRow({
  to,
  kind,
  title,
  subtitle,
  value,
  change,
  changeUp,
  onRemove,
}: {
  to: string;
  kind: WatchItem["kind"];
  title: string;
  subtitle: string;
  value: string;
  change: string;
  changeUp?: boolean;
  onRemove: () => void;
}) {
  return (
    <TableRow className="cursor-pointer">
      <TableCell className="w-8 pr-0">
        <UnwatchButton onClick={onRemove} />
      </TableCell>
      <TableCell>
        <Link to={to} className="flex items-center gap-2">
          {KIND_ICON[kind]}
          <div className="min-w-0">
            <div className="truncate font-medium">{title}</div>
            <div className="truncate text-xs text-muted-foreground">{subtitle}</div>
          </div>
        </Link>
      </TableCell>
      <TableCell>
        <Badge variant={KIND_VARIANT[kind]}>{kindLabel(kind)}</Badge>
      </TableCell>
      <TableCell className="text-right tabular-nums">{value}</TableCell>
      <TableCell
        className={cn(
          "text-right tabular-nums",
          changeUp == null
            ? "text-muted-foreground"
            : changeUp
              ? "text-emerald-600 dark:text-emerald-400"
              : "text-rose-600 dark:text-rose-400",
        )}
      >
        {change}
      </TableCell>
    </TableRow>
  );
}

export default function WatchlistPage() {
  const { items, remove } = useWatchlist();
  const ordered = useMemo(() => sortWatchItems(items), [items]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Star className="h-6 w-6 text-amber-400" />
        <div>
          <h1 className="text-2xl font-semibold">Watchlist</h1>
          <p className="text-sm text-muted-foreground">
            Everything you are following — symbols, creator tokens, and strategy funds — in one place.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Watched instruments</CardTitle>
          <CardDescription>
            Prices, clearing prices, and NAVs update live where available. Tap a row to open its detail page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {ordered.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <Star className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm font-medium">Your watchlist is empty</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                Star a market, creator token, or strategy fund and it will show up here.
              </p>
              <div className="mt-2 flex flex-wrap justify-center gap-2">
                <Button asChild variant="outline" size="sm">
                  <Link to="/markets">
                    <CandlestickChart className="mr-1 h-4 w-4" /> Markets
                  </Link>
                </Button>
                <Button asChild variant="outline" size="sm">
                  <Link to="/tokens">
                    <Landmark className="mr-1 h-4 w-4" /> Creator Tokens
                  </Link>
                </Button>
                <Button asChild variant="outline" size="sm">
                  <Link to="/strategies">
                    <Boxes className="mr-1 h-4 w-4" /> Strategies
                  </Link>
                </Button>
              </div>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Instrument</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead className="text-right">Price / NAV</TableHead>
                  <TableHead className="text-right">Change</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ordered.map((it) => {
                  if (it.kind === "symbol") {
                    return (
                      <SymbolRow
                        key={`symbol:${it.id}`}
                        symbolId={Number(it.id)}
                        onRemove={() => remove("symbol", it.id)}
                      />
                    );
                  }
                  if (it.kind === "token") {
                    return (
                      <TokenRow
                        key={`token:${it.id}`}
                        tokenId={it.id}
                        onRemove={() => remove("token", it.id)}
                      />
                    );
                  }
                  return (
                    <StrategyRow
                      key={`strategy:${it.id}`}
                      strategyId={it.id}
                      onRemove={() => remove("strategy", it.id)}
                    />
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
