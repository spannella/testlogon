import * as React from "react";
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
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice } from "@/pages/markets/format";
import { relativeTime } from "@/hooks/useTradingAlerts";
import {
  addPriceAlert,
  loadPriceAlerts,
  parsePriceToTicks,
  rearmPriceAlert,
  removePriceAlert,
  PRICE_ALERTS_EVENT,
  PRICE_ALERTS_KEY,
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

/** Small live current-price readout for a symbol (candle close). */
function CurrentPrice({ symbolId, scaler }: { symbolId: number; scaler: number }) {
  const { data } = useCandles(symbolId, 60, symbolId > 0, 1);
  const bars = data?.bars;
  const lastBar = bars && bars.length ? bars[bars.length - 1] : undefined;
  const last = lastBar?.close;
  return <span className="tabular-nums">{formatPrice(last, scaler)}</span>;
}

function AlertRow({
  alert,
  symbol,
  now,
}: {
  alert: PriceAlert;
  symbol: MarketSymbol | undefined;
  now: number;
}) {
  const scaler = symbol?.price_scaler ?? 1;
  const name = symbol?.symbol ?? `#${alert.symbolId}`;
  const fired = !!alert.triggeredTs;
  const DirIcon = alert.direction === "above" ? ArrowUp : ArrowDown;
  return (
    <div
      className={cn(
        "flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between",
        fired && "bg-muted/40",
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{name}</span>
          <Badge
            variant={alert.direction === "above" ? "default" : "secondary"}
            className="gap-1"
          >
            <DirIcon className="h-3 w-3" />
            {alert.direction} {formatPrice(alert.price, scaler)}
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
        <p className="mt-1 text-xs text-muted-foreground">
          Current: <CurrentPrice symbolId={alert.symbolId} scaler={scaler} />
        </p>
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

export default function PriceAlertsPage() {
  const alerts = usePriceAlerts();
  const { data: symbolsData } = useSymbols();
  const symbols = React.useMemo(() => symbolsData?.symbols ?? [], [symbolsData]);
  const byId = React.useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbols) m.set(s.symbol_id, s);
    return m;
  }, [symbols]);

  // Add-form state.
  const [symbolId, setSymbolId] = React.useState<string>("");
  const [direction, setDirection] = React.useState<PriceAlertDirection>("above");
  const [priceStr, setPriceStr] = React.useState("");
  const [note, setNote] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  // Default the symbol select to the first symbol once loaded.
  React.useEffect(() => {
    const first = symbols[0];
    if (!symbolId && first) setSymbolId(String(first.symbol_id));
  }, [symbols, symbolId]);

  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const selectedSymbol = symbolId ? byId.get(Number(symbolId)) : undefined;

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
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
    addPriceAlert({ symbolId: sid, direction, price: ticks, note });
    setPriceStr("");
    setNote("");
  };

  const active = alerts.filter((a) => a.armed);
  const triggered = alerts.filter((a) => !a.armed);

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center gap-3">
        <BellRing className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-xl font-semibold">Price alerts</h1>
          <p className="text-sm text-muted-foreground">
            Get notified when a market crosses your target price.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">New alert</CardTitle>
          <CardDescription>
            Alerts fire once when the last price crosses your threshold, then pause
            so you can re-arm them.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="grid gap-4 sm:grid-cols-2">
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
                  <SelectItem value="above">Price rises above</SelectItem>
                  <SelectItem value="below">Price falls below</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="pa-price">Target price</Label>
              <Input
                id="pa-price"
                inputMode="decimal"
                placeholder="e.g. 65000"
                value={priceStr}
                onChange={(e) => setPriceStr(e.target.value)}
              />
              {selectedSymbol && (
                <p className="text-xs text-muted-foreground">
                  Current:{" "}
                  <CurrentPrice
                    symbolId={selectedSymbol.symbol_id}
                    scaler={selectedSymbol.price_scaler}
                  />
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
            <p className="text-sm text-muted-foreground">No active price alerts</p>
            <p className="text-xs text-muted-foreground">
              Add one above to get notified on a price move.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {active.map((a) => (
              <AlertRow key={a.id} alert={a} symbol={byId.get(a.symbolId)} now={now} />
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
              <AlertRow key={a.id} alert={a} symbol={byId.get(a.symbolId)} now={now} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
