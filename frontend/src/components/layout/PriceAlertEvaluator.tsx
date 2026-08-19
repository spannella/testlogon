import * as React from "react";

import { useCandles, useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice } from "@/pages/markets/format";
import {
  pushExternalTradingAlert,
  type ExternalTradingAlert,
} from "@/hooks/useTradingAlerts";
import {
  evaluate,
  loadPriceAlerts,
  markPriceAlertTriggered,
  PRICE_ALERTS_EVENT,
  PRICE_ALERTS_KEY,
  type PriceAlert,
} from "@/lib/priceAlerts";

/** Subscribe to the current price-alert list (re-reads on same/cross-tab change). */
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

/**
 * Watches ONE symbol's last price (candle close) and evaluates every armed
 * alert on that symbol. On a fire it pushes a `price` alert into the trading
 * bell (toast + OS notification) and marks the alert triggered (one-shot).
 * Renders nothing.
 */
function SymbolPriceWatcher({
  symbolId,
  symbol,
  alerts,
}: {
  symbolId: number;
  symbol: MarketSymbol | undefined;
  alerts: PriceAlert[];
}) {
  const { data } = useCandles(symbolId, 60, true, 1);
  const bars = data?.bars;
  const lastBar = bars && bars.length ? bars[bars.length - 1] : undefined;
  const lastClose = lastBar?.close;
  const scaler = symbol?.price_scaler ?? 1;
  const name = symbol?.symbol ?? `#${symbolId}`;

  React.useEffect(() => {
    if (lastClose == null || !Number.isFinite(lastClose)) return;
    for (const alert of alerts) {
      if (!alert.armed) continue;
      if (!evaluate(alert, lastClose)) continue;
      const dir = alert.direction === "above" ? "above" : "below";
      const priceLabel = formatPrice(alert.price, scaler);
      const detail: ExternalTradingAlert = {
        id: `price:${alert.id}:${alert.triggeredTs ?? "armed"}`,
        kind: "price",
        title: `${name} crossed ${dir} ${priceLabel}`,
        message: alert.note
          ? alert.note
          : `Last ${formatPrice(lastClose, scaler)} · target ${priceLabel}`,
        ts: Date.now(),
      };
      // One-shot: stamp + disarm BEFORE pushing so a fast re-render can't double-fire.
      markPriceAlertTriggered(alert.id, detail.ts);
      pushExternalTradingAlert(detail);
    }
    // Re-run when the price or the alert set for this symbol changes.
  }, [lastClose, alerts, scaler, name]);

  return null;
}

/**
 * App-chrome-level evaluator: for each distinct symbol that has an ARMED price
 * alert, mount a hidden watcher that polls its last price and fires crossings
 * through the trading-alerts bell. Mount this next to <TradingAlertsBell/> so it
 * runs whenever the user is logged in.
 */
export default function PriceAlertEvaluator({ enabled = true }: { enabled?: boolean }) {
  const alerts = usePriceAlerts();
  const { data: symbolsData } = useSymbols();

  const byId = React.useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbolsData?.symbols ?? []) m.set(s.symbol_id, s);
    return m;
  }, [symbolsData]);

  // Group armed alerts by symbol; only distinct armed symbols get a watcher.
  const grouped = React.useMemo(() => {
    const m = new Map<number, PriceAlert[]>();
    if (!enabled) return m;
    for (const a of alerts) {
      if (!a.armed) continue;
      const list = m.get(a.symbolId) ?? [];
      list.push(a);
      m.set(a.symbolId, list);
    }
    return m;
  }, [alerts, enabled]);

  if (!enabled) return null;

  return (
    <>
      {[...grouped.entries()].map(([symbolId, symAlerts]) => (
        <SymbolPriceWatcher
          key={symbolId}
          symbolId={symbolId}
          symbol={byId.get(symbolId)}
          alerts={symAlerts}
        />
      ))}
    </>
  );
}
