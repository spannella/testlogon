import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, RotateCcw, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { cn } from "@/lib/utils";
import { useSymbols, useOrderBook, useTrades } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import {
  placeOrder,
  onTick,
  cancelOrder,
  unrealized as calcUnrealized,
  equity as calcEquity,
  DEFAULT_STARTING_CASH,
  type PaperAccount,
  type PaperSide,
  type PaperOrderType,
} from "@/lib/paperEngine";
import { loadAccount, saveAccount, resetAndSave } from "@/lib/paperStore";
import { notional as calcNotional } from "@/lib/orderMath";
import { formatPrice, formatQty } from "@/pages/markets/format";

// Fallback catalog mirrors MarketsPage so the page still works if /md/symbols errors.
const FALLBACK_SYMBOLS: MarketSymbol[] = [
  { symbol: "BTCUSDC", symbol_id: 1, instrument_id: 1, price_scaler: 1, lot_size: 1, reference_price: 100000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "ETHUSDC", symbol_id: 2, instrument_id: 2, price_scaler: 1, lot_size: 1, reference_price: 3000, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
  { symbol: "SOLUSDC", symbol_id: 3, instrument_id: 3, price_scaler: 1, lot_size: 1, reference_price: 150, matching_algo: "price_time", is_perpetual: false, funding_interval_s: 0 },
];

/** A signed +/- coloured amount, scaled for display. */
function Pnl({ value, scaler }: { value: number; scaler: number }) {
  const positive = value >= 0;
  return (
    <span
      className={cn(
        "font-medium tabular-nums",
        positive ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400",
      )}
    >
      {positive ? "+" : "−"}
      {formatPrice(Math.abs(value), scaler)}
    </span>
  );
}

function Stat({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-lg font-semibold tabular-nums">{children}</span>
    </div>
  );
}

export default function PaperTradingPage() {
  const symbolsQuery = useSymbols();
  const symbols = symbolsQuery.data?.symbols?.length ? symbolsQuery.data.symbols : FALLBACK_SYMBOLS;

  const DEFAULT_SYMBOL = FALLBACK_SYMBOLS[0]!;
  const [symbolId, setSymbolId] = useState<number>(DEFAULT_SYMBOL.symbol_id);
  const activeSymbol: MarketSymbol =
    symbols.find((s) => s.symbol_id === symbolId) ?? symbols[0] ?? DEFAULT_SYMBOL;
  const scaler = activeSymbol.price_scaler || 1;

  // ── Account (loaded once, persisted after every mutation) ────────────
  const [account, setAccount] = useState<PaperAccount>(() =>
    loadAccount(DEFAULT_STARTING_CASH),
  );

  // ── Live market price for the selected symbol ────────────────────────
  const book = useOrderBook(symbolId, 5);
  const trades = useTrades(symbolId, true, 4000);
  const bestBid = book.data?.bid_px ?? book.data?.bids?.[0]?.[0];
  const bestAsk = book.data?.ask_px ?? book.data?.asks?.[0]?.[0];
  const lastTrade = trades.data?.trades?.[0]?.price;
  const mid =
    bestBid != null && bestAsk != null ? Math.round((bestBid + bestAsk) / 2) : undefined;
  // "Market price" = last trade, else book mid, else a best-side, else reference.
  const marketPrice =
    lastTrade ?? mid ?? bestAsk ?? bestBid ?? activeSymbol.reference_price ?? undefined;

  // ── Fill-simulator: feed the live price into onTick + persist ────────
  const acctRef = useRef(account);
  acctRef.current = account;
  useEffect(() => {
    if (marketPrice == null || !(marketPrice > 0)) return;
    const next = onTick(acctRef.current, symbolId, marketPrice);
    if (next !== acctRef.current) {
      setAccount(next);
      saveAccount(next);
    }
  }, [marketPrice, symbolId]);

  // Mark map for MTM: mark the selected symbol at its live price. Positions in
  // other symbols keep marking at their avg entry (0 unrealized) until selected.
  const marks = useMemo<Record<number, number | undefined>>(() => {
    const m: Record<number, number | undefined> = {};
    for (const [k, pos] of Object.entries(account.positions)) {
      const id = Number(k);
      m[id] = id === symbolId ? marketPrice : pos.avgEntry;
    }
    return m;
  }, [account.positions, symbolId, marketPrice]);

  const unreal = calcUnrealized(account, marks);
  const equity = calcEquity(account, marks);
  const returnPct =
    account.startingCash > 0 ? ((equity - account.startingCash) / account.startingCash) * 100 : 0;

  // ── Order form state ─────────────────────────────────────────────────
  const [side, setSide] = useState<PaperSide>("buy");
  const [orderType, setOrderType] = useState<PaperOrderType>("market");
  const [priceStr, setPriceStr] = useState("");
  const [qtyStr, setQtyStr] = useState("");

  const qtyNum = Number(qtyStr);
  const priceNum = Number(priceStr);
  // Limit price is entered in display units; convert to ticks to match qty/market.
  const previewPriceTicks =
    orderType === "limit" ? Math.round(priceNum * scaler) : marketPrice ?? 0;
  const previewNotional = calcNotional(previewPriceTicks, qtyNum);

  const canSubmit =
    Number.isFinite(qtyNum) &&
    qtyNum > 0 &&
    (orderType === "market"
      ? marketPrice != null && marketPrice > 0
      : Number.isFinite(priceNum) && priceNum > 0);

  function submitOrder() {
    if (!canSubmit) return;
    const { account: next } = placeOrder(
      account,
      {
        symbolId,
        side,
        type: orderType,
        price: orderType === "limit" ? Math.round(priceNum * scaler) : undefined,
        qty: Math.floor(qtyNum),
      },
      marketPrice,
    );
    setAccount(next);
    saveAccount(next);
    setQtyStr("");
  }

  function cancel(id: string) {
    const next = cancelOrder(account, id);
    setAccount(next);
    saveAccount(next);
  }

  function doReset() {
    const fresh = resetAndSave(DEFAULT_STARTING_CASH);
    setAccount(fresh);
  }

  const workingOrders = account.orders.filter((o) => o.status === "working");
  const positions = Object.entries(account.positions);
  const recentFills = account.fills.slice().reverse().slice(0, 40);
  const symLabel = (id: number) => symbols.find((s) => s.symbol_id === id)?.symbol ?? `#${id}`;

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex items-start gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" />
        <div>
          <p className="font-semibold text-amber-700 dark:text-amber-300">
            Paper — simulated, not real funds
          </p>
          <p className="text-sm text-muted-foreground">
            This is an isolated client-side simulator. It uses live market data but never
            places real orders. Your paper account is stored only in this browser.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <TrendingUp className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-semibold">Paper Trading</h1>
          <Badge variant="secondary">PAPER</Badge>
        </div>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="outline" size="sm">
              <RotateCcw className="mr-2 h-4 w-4" /> Reset account
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Reset paper account?</AlertDialogTitle>
              <AlertDialogDescription>
                This clears all positions, working orders, and fill history, and restores the
                starting balance of {formatPrice(DEFAULT_STARTING_CASH, scaler)}. This cannot be
                undone.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={doReset}>Reset</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>

      {/* Account panel */}
      <Card>
        <CardContent className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3 lg:grid-cols-6">
          <Stat label="Equity">{formatPrice(equity, scaler)}</Stat>
          <Stat label="Cash">{formatPrice(account.cash, scaler)}</Stat>
          <Stat label="Realized PnL">
            <Pnl value={account.realizedPnl} scaler={scaler} />
          </Stat>
          <Stat label="Unrealized PnL">
            <Pnl value={unreal} scaler={scaler} />
          </Stat>
          <Stat label="Starting balance">{formatPrice(account.startingCash, scaler)}</Stat>
          <Stat label="Return">
            <span
              className={cn(
                "tabular-nums",
                returnPct >= 0
                  ? "text-emerald-600 dark:text-emerald-400"
                  : "text-rose-600 dark:text-rose-400",
              )}
            >
              {returnPct >= 0 ? "+" : ""}
              {returnPct.toFixed(2)}%
            </span>
          </Stat>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        {/* Order form */}
        <Card className="h-fit">
          <CardHeader>
            <CardTitle className="text-base">Paper order</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground">Symbol</label>
              <Select value={String(symbolId)} onValueChange={(v) => setSymbolId(Number(v))}>
                <SelectTrigger className="mt-1">
                  <SelectValue />
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

            <div className="rounded-md border bg-muted/30 p-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Market price</span>
                <span className="text-lg font-semibold tabular-nums">
                  {marketPrice != null ? formatPrice(marketPrice, scaler) : "—"}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between text-xs text-muted-foreground">
                <span>Bid {bestBid != null ? formatPrice(bestBid, scaler) : "—"}</span>
                <span>Ask {bestAsk != null ? formatPrice(bestAsk, scaler) : "—"}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <Button
                type="button"
                variant={side === "buy" ? "default" : "outline"}
                className={cn(side === "buy" && "bg-emerald-600 hover:bg-emerald-700")}
                onClick={() => setSide("buy")}
              >
                Buy
              </Button>
              <Button
                type="button"
                variant={side === "sell" ? "default" : "outline"}
                className={cn(side === "sell" && "bg-rose-600 hover:bg-rose-700")}
                onClick={() => setSide("sell")}
              >
                Sell
              </Button>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <Button
                type="button"
                size="sm"
                variant={orderType === "market" ? "secondary" : "outline"}
                onClick={() => setOrderType("market")}
              >
                Market
              </Button>
              <Button
                type="button"
                size="sm"
                variant={orderType === "limit" ? "secondary" : "outline"}
                onClick={() => setOrderType("limit")}
              >
                Limit
              </Button>
            </div>

            {orderType === "limit" && (
              <div>
                <label className="text-xs text-muted-foreground">Limit price</label>
                <Input
                  className="mt-1"
                  inputMode="decimal"
                  placeholder={marketPrice != null ? formatPrice(marketPrice, scaler) : "0"}
                  value={priceStr}
                  onChange={(e) => setPriceStr(e.target.value)}
                />
              </div>
            )}

            <div>
              <label className="text-xs text-muted-foreground">Quantity</label>
              <Input
                className="mt-1"
                inputMode="numeric"
                placeholder="0"
                value={qtyStr}
                onChange={(e) => setQtyStr(e.target.value)}
              />
            </div>

            <div className="flex items-center justify-between rounded-md bg-muted/30 px-3 py-2 text-sm">
              <span className="text-muted-foreground">Order notional</span>
              <span className="font-medium tabular-nums">
                {previewNotional > 0 ? formatPrice(previewNotional, scaler) : "—"}
              </span>
            </div>

            <Button
              type="button"
              className={cn(
                "w-full",
                side === "buy" ? "bg-emerald-600 hover:bg-emerald-700" : "bg-rose-600 hover:bg-rose-700",
              )}
              disabled={!canSubmit}
              onClick={submitOrder}
            >
              {side === "buy" ? "Buy" : "Sell"} {activeSymbol.symbol} ({orderType})
            </Button>
            {orderType === "limit" && (
              <p className="text-xs text-muted-foreground">
                Limit orders rest until the live market crosses your price, then fill
                automatically.
              </p>
            )}
          </CardContent>
        </Card>

        {/* Positions / orders / fills */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Positions</CardTitle>
            </CardHeader>
            <CardContent>
              {positions.length === 0 ? (
                <p className="text-sm text-muted-foreground">No open positions.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-muted-foreground">
                        <th className="pb-2">Symbol</th>
                        <th className="pb-2">Side</th>
                        <th className="pb-2 text-right">Qty</th>
                        <th className="pb-2 text-right">Avg entry</th>
                        <th className="pb-2 text-right">Mark</th>
                        <th className="pb-2 text-right">Unrealized</th>
                      </tr>
                    </thead>
                    <tbody>
                      {positions.map(([k, pos]) => {
                        const id = Number(k);
                        const mark = marks[id];
                        const u = mark != null ? (mark - pos.avgEntry) * pos.qty : 0;
                        const isLong = pos.qty > 0;
                        return (
                          <tr key={k} className="border-t">
                            <td className="py-2 font-medium">{symLabel(id)}</td>
                            <td className="py-2">
                              <Badge variant={isLong ? "default" : "destructive"}>
                                {isLong ? "Long" : "Short"}
                              </Badge>
                            </td>
                            <td className="py-2 text-right tabular-nums">
                              {formatQty(Math.abs(pos.qty), scaler)}
                            </td>
                            <td className="py-2 text-right tabular-nums">
                              {formatPrice(pos.avgEntry, scaler)}
                            </td>
                            <td className="py-2 text-right tabular-nums">
                              {mark != null ? formatPrice(mark, scaler) : "—"}
                            </td>
                            <td className="py-2 text-right">
                              <Pnl value={u} scaler={scaler} />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                Working orders {workingOrders.length > 0 && `(${workingOrders.length})`}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {workingOrders.length === 0 ? (
                <p className="text-sm text-muted-foreground">No working orders.</p>
              ) : (
                <div className="space-y-2">
                  {workingOrders.map((o) => (
                    <div
                      key={o.id}
                      className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
                    >
                      <div className="flex items-center gap-2">
                        <Badge variant={o.side === "buy" ? "default" : "destructive"}>
                          {o.side.toUpperCase()}
                        </Badge>
                        <span className="font-medium">{symLabel(o.symbolId)}</span>
                        <span className="text-muted-foreground">
                          {formatQty(o.qty, scaler)} @ {formatPrice(o.price, scaler)} (limit)
                        </span>
                      </div>
                      <Button variant="ghost" size="sm" onClick={() => cancel(o.id)}>
                        Cancel
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Fill history</CardTitle>
            </CardHeader>
            <CardContent>
              {recentFills.length === 0 ? (
                <p className="text-sm text-muted-foreground">No fills yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-muted-foreground">
                        <th className="pb-2">Time</th>
                        <th className="pb-2">Symbol</th>
                        <th className="pb-2">Side</th>
                        <th className="pb-2 text-right">Qty</th>
                        <th className="pb-2 text-right">Price</th>
                        <th className="pb-2 text-right">Realized</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentFills.map((f) => (
                        <tr key={f.id} className="border-t">
                          <td className="py-1.5 text-muted-foreground">
                            {new Date(f.ts).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                              second: "2-digit",
                            })}
                          </td>
                          <td className="py-1.5 font-medium">{symLabel(f.symbolId)}</td>
                          <td
                            className={cn(
                              "py-1.5 font-medium",
                              f.side === "buy"
                                ? "text-emerald-600 dark:text-emerald-400"
                                : "text-rose-600 dark:text-rose-400",
                            )}
                          >
                            {f.side.toUpperCase()}
                          </td>
                          <td className="py-1.5 text-right tabular-nums">
                            {formatQty(f.qty, scaler)}
                          </td>
                          <td className="py-1.5 text-right tabular-nums">
                            {formatPrice(f.price, scaler)}
                          </td>
                          <td className="py-1.5 text-right">
                            {f.realized !== 0 ? (
                              <Pnl value={f.realized} scaler={scaler} />
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <Separator />
      <p className="text-center text-xs text-muted-foreground">
        Paper Trading is fully isolated from live trading. No order here ever reaches the exchange.
      </p>
    </div>
  );
}
