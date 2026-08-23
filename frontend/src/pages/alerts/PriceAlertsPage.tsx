import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { BellRing, Plus, Trash2, RotateCcw, ArrowUp, ArrowDown } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useSymbols, useCandles } from "@/hooks/useMarketData";
import { useTokenMarket, useMyTokens } from "@/hooks/useTokens";
import { useStrategyMarket, useMyStrategies, useStrategyNav } from "@/hooks/useStrategies";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import type { Token } from "@/api/endpoints/tokens";
import type { Strategy } from "@/api/endpoints/strategies";
import { formatPrice } from "@/pages/markets/format";
import { formatCents } from "@/lib/tokens";
import { relativeTime } from "@/hooks/useTradingAlerts";
import {
  addPriceAlert,
  loadPriceAlerts,
  parseCentsToInt,
  parsePriceToTicks,
  rearmPriceAlert,
  removePriceAlert,
  subjectKindLabel,
  PRICE_ALERTS_EVENT,
  PRICE_ALERTS_KEY,
  type AlertSubjectKind,
  type PriceAlert,
  type PriceAlertDirection,
} from "@/lib/priceAlerts";

/** Subscribe to the stored price-alert list (re-reads on same/cross-tab change). */
function usePriceAlerts(): PriceAlert[] {
  const [alerts, setAlerts] = React.useState<PriceAlert[]>(() => loadPriceAlerts());
  React.useEffect(() => {
    const reload = () => setAlerts(loadPriceAlerts());
    const onStorage = (e: StorageEvent) => {
      if (e.key === PRICE_ALERTS_KEY || e.key === null) reload();
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener(PRICE_ALERTS_EVENT, reload);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(PRICE_ALERTS_EVENT, reload);
    };
  }, []);
  return alerts;
}

/** Small live current-price readout for a SYMBOL (candle close). */
function SymbolCurrentPrice({ symbolId, scaler }: { symbolId: number; scaler: number }) {
  const { data } = useCandles(symbolId, 60, symbolId > 0, 1);
  const bars = data?.bars;
  const lastBar = bars && bars.length ? bars[bars.length - 1] : undefined;
  const last = lastBar?.close;
  return <span className="tabular-nums">{formatPrice(last, scaler)}</span>;
}

/** Live NAV readout for a STRATEGY (polled). */
function StrategyCurrentNav({ strategyId }: { strategyId: string }) {
  const { data } = useStrategyNav(strategyId);
  return <span className="tabular-nums">{formatCents(data?.nav_per_unit)}</span>;
}

function AlertRow({
  alert,
  symbol,
  tokensById,
  strategiesById,
  now,
}: {
  alert: PriceAlert;
  symbol: MarketSymbol | undefined;
  tokensById: Map<string, Token>;
  strategiesById: Map<string, Strategy>;
  now: number;
}) {
  const fired = !!alert.triggeredTs;
  const DirIcon = alert.direction === "above" ? ArrowUp : ArrowDown;

  // Resolve display name + threshold rendering per subject kind.
  let name: string;
  let thresholdLabel: string;
  let current: React.ReactNode;
  if (alert.subjectKind === "token") {
    const t = tokensById.get(alert.subjectId);
    name = t?.ticker ?? t?.name ?? alert.subjectId;
    thresholdLabel = formatCents(alert.price);
    current = <span className="tabular-nums">{formatCents(t?.clearing_price)}</span>;
  } else if (alert.subjectKind === "strategy") {
    const s = strategiesById.get(alert.subjectId);
    name = s?.name ?? alert.subjectId;
    thresholdLabel = formatCents(alert.price);
    current = <StrategyCurrentNav strategyId={alert.subjectId} />;
  } else {
    const scaler = symbol?.price_scaler ?? 1;
    name = symbol?.symbol ?? `#${alert.symbolId}`;
    thresholdLabel = formatPrice(alert.price, scaler);
    current = <SymbolCurrentPrice symbolId={alert.symbolId} scaler={scaler} />;
  }
  const fieldWord = alert.field === "nav" ? "NAV" : "price";

  return (
    <div
      className={cn(
        "flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between",
        fired && "bg-muted/40",
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="text-muted-foreground">
            {subjectKindLabel(alert.subjectKind)}
          </Badge>
          <span className="font-medium">{name}</span>
          <Badge
            variant={alert.direction === "above" ? "default" : "secondary"}
            className="gap-1"
          >
            <DirIcon className="h-3 w-3" />
            {fieldWord} {alert.direction} {thresholdLabel}
          </Badge>
          {fired ? (
            <Badge variant="outline" className="text-muted-foreground">
              Triggered {relativeTime(alert.triggeredTs as number, now)}
            </Badge>
          ) : (
            <Badge variant="outline" className="border-emerald-500/40 text-emerald-600 dark:text-emerald-400">
              Armed
            </Badge>
          )}
        </div>
        {alert.note && (
          <p className="mt-1 truncate text-sm text-muted-foreground">{alert.note}</p>
        )}
        <p className="mt-1 text-xs text-muted-foreground">Current: {current}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {fired && (
          <Button
            variant="outline"
            size="sm"
            className="gap-1"
            onClick={() => rearmPriceAlert(alert.id)}
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Re-arm
          </Button>
        )}
        <Button
          variant="ghost"
          size="icon"
          aria-label="Delete alert"
          onClick={() => removePriceAlert(alert.id)}
        >
          <Trash2 className="h-4 w-4 text-destructive" />
        </Button>
      </div>
    </div>
  );
}

/** De-dupe two token/strategy lists (mine + market) into one id-keyed map. */
function mergeById<T>(lists: (T[] | undefined)[], keyOf: (x: T) => string): Map<string, T> {
  const m = new Map<string, T>();
  for (const list of lists) {
    for (const item of list ?? []) {
      const k = keyOf(item);
      if (k && !m.has(k)) m.set(k, item);
    }
  }
  return m;
}

export default function PriceAlertsPage() {
  const alerts = usePriceAlerts();

  // -- Subject data sources -------------------------------------------
  const { data: symbolsData } = useSymbols();
  const symbols = React.useMemo(() => symbolsData?.symbols ?? [], [symbolsData]);
  const symbolsById = React.useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbols) m.set(s.symbol_id, s);
    return m;
  }, [symbols]);

  const tokenMarketQ = useTokenMarket();
  const myTokensQ = useMyTokens();
  const tokensById = React.useMemo(
    () => mergeById<Token>([tokenMarketQ.data?.tokens, myTokensQ.data?.tokens], (t) => t.token_id),
    [tokenMarketQ.data, myTokensQ.data],
  );
  const tokens = React.useMemo(() => [...tokensById.values()], [tokensById]);

  const strategyMarketQ = useStrategyMarket();
  const myStrategiesQ = useMyStrategies();
  const strategiesById = React.useMemo(
    () =>
      mergeById<Strategy>(
        [strategyMarketQ.data?.strategies, myStrategiesQ.data?.strategies],
        (s) => s.strategy_id,
      ),
    [strategyMarketQ.data, myStrategiesQ.data],
  );
  const strategies = React.useMemo(() => [...strategiesById.values()], [strategiesById]);

  // -- Deep-link prefill (e.g. from a token / strategy "Set alert" button) ----
  // ?kind=token&id=<token_id> | ?kind=strategy&id=<strategy_id> | ?kind=symbol&id=<symbol_id>
  const [searchParams] = useSearchParams();
  const prefillKind = ((): AlertSubjectKind => {
    const k = searchParams.get("kind");
    return k === "token" || k === "strategy" || k === "symbol" ? k : "symbol";
  })();
  const prefillId = searchParams.get("id") ?? "";

  // -- Add-form state -------------------------------------------------
  const [subjectKind, setSubjectKind] = React.useState<AlertSubjectKind>(prefillKind);
  const [symbolId, setSymbolId] = React.useState<string>(
    prefillKind === "symbol" ? prefillId : "",
  );
  const [tokenId, setTokenId] = React.useState<string>(
    prefillKind === "token" ? prefillId : "",
  );
  const [strategyId, setStrategyId] = React.useState<string>(
    prefillKind === "strategy" ? prefillId : "",
  );
  const [direction, setDirection] = React.useState<PriceAlertDirection>("above");
  const [priceStr, setPriceStr] = React.useState("");
  const [note, setNote] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  // Default each selector to its first option once loaded.
  React.useEffect(() => {
    if (!symbolId && symbols[0]) setSymbolId(String(symbols[0].symbol_id));
  }, [symbols, symbolId]);
  React.useEffect(() => {
    if (!tokenId && tokens[0]) setTokenId(tokens[0].token_id);
  }, [tokens, tokenId]);
  React.useEffect(() => {
    if (!strategyId && strategies[0]) setStrategyId(strategies[0].strategy_id);
  }, [strategies, strategyId]);

  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const selectedSymbol = symbolId ? symbolsById.get(Number(symbolId)) : undefined;
  const isCents = subjectKind !== "symbol"; // token / strategy targets are dollars->cents

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (subjectKind === "symbol") {
      const sid = Number(symbolId);
      if (!Number.isFinite(sid) || sid <= 0) {
        setError("Choose a symbol.");
        return;
      }
      const scaler = selectedSymbol?.price_scaler ?? 1;
      const ticks = parsePriceToTicks(priceStr, scaler);
      if (ticks == null) {
        setError("Enter a valid price.");
        return;
      }
      addPriceAlert({ subjectKind: "symbol", symbolId: sid, direction, price: ticks, note });
    } else if (subjectKind === "token") {
      if (!tokenId) {
        setError("Choose a creator token.");
        return;
      }
      const cents = parseCentsToInt(priceStr);
      if (cents == null) {
        setError("Enter a valid price ($).");
        return;
      }
      addPriceAlert({
        subjectKind: "token",
        subjectId: tokenId,
        field: "price",
        direction,
        price: cents,
        note,
      });
    } else {
      if (!strategyId) {
        setError("Choose a strategy.");
        return;
      }
      const cents = parseCentsToInt(priceStr);
      if (cents == null) {
        setError("Enter a valid NAV ($).");
        return;
      }
      addPriceAlert({
        subjectKind: "strategy",
        subjectId: strategyId,
        field: "nav",
        direction,
        price: cents,
        note,
      });
    }
    setPriceStr("");
    setNote("");
  };

  const active = alerts.filter((a) => a.armed);
  const triggered = alerts.filter((a) => !a.armed);

  const fieldNoun = subjectKind === "strategy" ? "NAV" : "price";

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center gap-3">
        <BellRing className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-xl font-semibold">Price alerts</h1>
          <p className="text-sm text-muted-foreground">
            Get notified when a market, creator token, or strategy fund crosses your target.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">New alert</CardTitle>
          <CardDescription>
            Alerts fire once when the {fieldNoun} crosses your threshold, then pause
            so you can re-arm them.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="pa-kind">Watch</Label>
              <Select
                value={subjectKind}
                onValueChange={(v) => {
                  setSubjectKind(v as AlertSubjectKind);
                  setError(null);
                }}
              >
                <SelectTrigger id="pa-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="symbol">Symbol</SelectItem>
                  <SelectItem value="token">Creator token</SelectItem>
                  <SelectItem value="strategy">Strategy</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {subjectKind === "symbol" && (
              <div className="space-y-1.5">
                <Label htmlFor="pa-symbol">Symbol</Label>
                <Select value={symbolId} onValueChange={setSymbolId}>
                  <SelectTrigger id="pa-symbol">
                    <SelectValue placeholder="Select symbol" />
                  </SelectTrigger>
                  <SelectContent>
                    {symbols.map((s) => (
                      <SelectItem key={s.symbol_id} value={String(s.symbol_id)}>
                        {s.symbol}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {subjectKind === "token" && (
              <div className="space-y-1.5">
                <Label htmlFor="pa-token">Creator token</Label>
                <Select value={tokenId} onValueChange={setTokenId}>
                  <SelectTrigger id="pa-token">
                    <SelectValue placeholder="Select token" />
                  </SelectTrigger>
                  <SelectContent>
                    {tokens.length === 0 ? (
                      <SelectItem value="__none" disabled>
                        No tokens available
                      </SelectItem>
                    ) : (
                      tokens.map((t) => (
                        <SelectItem key={t.token_id} value={t.token_id}>
                          {t.ticker} — {t.name}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
            )}

            {subjectKind === "strategy" && (
              <div className="space-y-1.5">
                <Label htmlFor="pa-strategy">Strategy</Label>
                <Select value={strategyId} onValueChange={setStrategyId}>
                  <SelectTrigger id="pa-strategy">
                    <SelectValue placeholder="Select strategy" />
                  </SelectTrigger>
                  <SelectContent>
                    {strategies.length === 0 ? (
                      <SelectItem value="__none" disabled>
                        No strategies available
                      </SelectItem>
                    ) : (
                      strategies.map((s) => (
                        <SelectItem key={s.strategy_id} value={s.strategy_id}>
                          {s.name}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="pa-dir">Condition</Label>
              <Select
                value={direction}
                onValueChange={(v) => setDirection(v as PriceAlertDirection)}
              >
                <SelectTrigger id="pa-dir">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="above">{fieldNoun} rises above</SelectItem>
                  <SelectItem value="below">{fieldNoun} falls below</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="pa-price">
                {subjectKind === "strategy" ? "Target NAV" : "Target price"}
                {isCents ? " ($)" : ""}
              </Label>
              <Input
                id="pa-price"
                inputMode="decimal"
                placeholder={isCents ? "e.g. 12.50" : "e.g. 65000"}
                value={priceStr}
                onChange={(e) => setPriceStr(e.target.value)}
              />
              {subjectKind === "symbol" && selectedSymbol && (
                <p className="text-xs text-muted-foreground">
                  Current:{" "}
                  <SymbolCurrentPrice
                    symbolId={selectedSymbol.symbol_id}
                    scaler={selectedSymbol.price_scaler}
                  />
                </p>
              )}
              {subjectKind === "token" && tokenId && (
                <p className="text-xs text-muted-foreground">
                  Current: {formatCents(tokensById.get(tokenId)?.clearing_price)}
                </p>
              )}
              {subjectKind === "strategy" && strategyId && (
                <p className="text-xs text-muted-foreground">
                  Current: <StrategyCurrentNav strategyId={strategyId} />
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="pa-note">Note (optional)</Label>
              <Input
                id="pa-note"
                placeholder="Why this matters"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>

            <div className="sm:col-span-2 flex items-center gap-3">
              <Button type="submit" className="gap-1">
                <Plus className="h-4 w-4" />
                Add alert
              </Button>
              {error && <span className="text-sm text-destructive">{error}</span>}
            </div>
          </form>
        </CardContent>
      </Card>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-muted-foreground">
          Active ({active.length})
        </h2>
        {active.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed py-10 text-center">
            <BellRing className="h-6 w-6 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No active alerts</p>
            <p className="text-xs text-muted-foreground">
              Add one above to get notified on a price or NAV move.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {active.map((a) => (
              <AlertRow
                key={a.id}
                alert={a}
                symbol={symbolsById.get(a.symbolId)}
                tokensById={tokensById}
                strategiesById={strategiesById}
                now={now}
              />
            ))}
          </div>
        )}
      </section>

      {triggered.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-muted-foreground">
            Triggered ({triggered.length})
          </h2>
          <div className="space-y-2">
            {triggered.map((a) => (
              <AlertRow
                key={a.id}
                alert={a}
                symbol={symbolsById.get(a.symbolId)}
                tokensById={tokensById}
                strategiesById={strategiesById}
                now={now}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
