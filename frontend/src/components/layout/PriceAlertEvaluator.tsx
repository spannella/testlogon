import * as React from "react";

import { useCandles, useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { formatPrice } from "@/pages/markets/format";
import { formatCents } from "@/lib/tokens";
import { useToken } from "@/hooks/useTokens";
import { useStrategy, useStrategyNav } from "@/hooks/useStrategies";
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
 * Shared fire path: for each armed alert whose current value MEETS its
 * condition, push a `price` alert into the trading bell and mark it triggered
 * (one-shot). `value` is in the subject's native integer units; `render`
 * formats it for display. `subjectName` is the resolved display label.
 */
function fireCrossings(
  alerts: PriceAlert[],
  value: number,
  subjectName: string,
  render: (v: number) => string,
) {
  if (value == null || !Number.isFinite(value)) return;
  for (const alert of alerts) {
    if (!alert.armed) continue;
    if (!evaluate(alert, value)) continue;
    const dir = alert.direction === "above" ? "above" : "below";
    const fieldWord = alert.field === "nav" ? "NAV" : "price";
    const targetLabel = render(alert.price);
    const detail: ExternalTradingAlert = {
      id: `price:${alert.id}:${alert.triggeredTs ?? "armed"}`,
      kind: "price",
      title: `${subjectName} ${fieldWord} crossed ${dir} ${targetLabel}`,
      message: alert.note
        ? alert.note
        : `Now ${render(value)} · target ${targetLabel}`,
      ts: Date.now(),
    };
    // One-shot: stamp + disarm BEFORE pushing so a fast re-render can't double-fire.
    markPriceAlertTriggered(alert.id, detail.ts);
    pushExternalTradingAlert(detail);
  }
}

/**
 * Watches ONE symbol's last price (candle close) and evaluates every armed
 * alert on that symbol. Renders nothing.
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
    fireCrossings(alerts, lastClose, name, (v) => formatPrice(v, scaler));
  }, [lastClose, alerts, scaler, name]);

  return null;
}

/**
 * Watches ONE creator token's last / clearing price (integer cents). Degrades
 * silently on 404 (token backend not shipped) — no read, no fire. Renders nothing.
 */
function TokenPriceWatcher({
  tokenId,
  alerts,
}: {
  tokenId: string;
  alerts: PriceAlert[];
}) {
  const { data } = useToken(tokenId);
  const last = data?.clearing_price;
  const name = data?.ticker ?? data?.name ?? tokenId;

  React.useEffect(() => {
    if (last == null || !Number.isFinite(last)) return;
    fireCrossings(alerts, last, name, (v) => formatCents(v));
  }, [last, alerts, name]);

  return null;
}

/**
 * Watches ONE strategy fund's NAV per unit (integer cents), polled by
 * useStrategyNav. Falls back to the strategy detail's nav_per_unit when the NAV
 * snapshot endpoint 404s. Degrades silently when neither is available. Renders
 * nothing.
 */
function StrategyNavWatcher({
  strategyId,
  alerts,
}: {
  strategyId: string;
  alerts: PriceAlert[];
}) {
  const navQ = useStrategyNav(strategyId);
  const stratQ = useStrategy(strategyId);
  const nav = navQ.data?.nav_per_unit ?? stratQ.data?.nav_per_unit;
  const name = stratQ.data?.name ?? strategyId;

  React.useEffect(() => {
    if (nav == null || !Number.isFinite(nav)) return;
    fireCrossings(alerts, nav, name, (v) => formatCents(v));
  }, [nav, alerts, name]);

  return null;
}

/**
 * App-chrome-level evaluator: for each distinct SUBJECT (symbol / token /
 * strategy) that has an ARMED alert, mount a hidden watcher that polls its
 * current value and fires crossings through the trading-alerts bell. Mount this
 * next to <TradingAlertsBell/> so it runs whenever the user is logged in.
 */
export default function PriceAlertEvaluator({ enabled = true }: { enabled?: boolean }) {
  const alerts = usePriceAlerts();
  const { data: symbolsData } = useSymbols();

  const byId = React.useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbolsData?.symbols ?? []) m.set(s.symbol_id, s);
    return m;
  }, [symbolsData]);

  // Group armed alerts by subject; only distinct armed subjects get a watcher.
  const grouped = React.useMemo(() => {
    const symbols = new Map<number, PriceAlert[]>();
    const tokens = new Map<string, PriceAlert[]>();
    const strategies = new Map<string, PriceAlert[]>();
    if (!enabled) return { symbols, tokens, strategies };
    for (const a of alerts) {
      if (!a.armed) continue;
      if (a.subjectKind === "token") {
        const list = tokens.get(a.subjectId) ?? [];
        list.push(a);
        tokens.set(a.subjectId, list);
      } else if (a.subjectKind === "strategy") {
        const list = strategies.get(a.subjectId) ?? [];
        list.push(a);
        strategies.set(a.subjectId, list);
      } else {
        const list = symbols.get(a.symbolId) ?? [];
        list.push(a);
        symbols.set(a.symbolId, list);
      }
    }
    return { symbols, tokens, strategies };
  }, [alerts, enabled]);

  if (!enabled) return null;

  return (
    <>
      {[...grouped.symbols.entries()].map(([symbolId, symAlerts]) => (
        <SymbolPriceWatcher
          key={`sym:${symbolId}`}
          symbolId={symbolId}
          symbol={byId.get(symbolId)}
          alerts={symAlerts}
        />
      ))}
      {[...grouped.tokens.entries()].map(([tokenId, tokAlerts]) => (
        <TokenPriceWatcher key={`tok:${tokenId}`} tokenId={tokenId} alerts={tokAlerts} />
      ))}
      {[...grouped.strategies.entries()].map(([strategyId, stratAlerts]) => (
        <StrategyNavWatcher
          key={`strat:${strategyId}`}
          strategyId={strategyId}
          alerts={stratAlerts}
        />
      ))}
    </>
  );
}
