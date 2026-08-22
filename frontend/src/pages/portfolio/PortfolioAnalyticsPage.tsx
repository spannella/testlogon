// Portfolio Risk — a client-computed "how am I positioned / what's my risk"
// view spanning EVERY venue the account touches: custody vault, trading spot,
// margin (incl. its open position), creator revenue-share tokens, strategy /
// basket funds, and staking. It builds a single NORMALIZED position list from
// the SAME reads the consolidated Portfolio page uses, values every leg in
// indicative USD cents (via /me/prices marks, degrade-labelled), and runs the
// pure `portfolioAnalytics` math over it: allocation, concentration (HHI),
// exposure/leverage, and risk (portfolio volatility + parametric & historical
// VaR from per-asset getHistory returns + a diversification score).
//
// EVERYTHING degrades independently: any source that 404s/403s is excluded and
// its contribution simply drops out; thin/absent history flips the risk section
// to a "recent window only / limited history" banner. All reads, no mutations.
import { useMemo, useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import {
  PieChart,
  ShieldAlert,
  RefreshCw,
  Layers,
  Scale,
  Activity,
  Info,
  Loader2,
  TrendingUp,
} from "lucide-react";

import { cn } from "@/lib/utils";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

import { getBalance, getStakingPositions, mergeBalances } from "@/api/endpoints/custody";
import { getSpotBalance, getMarginAccount, getPrices } from "@/api/endpoints/trading";
import { getSymbols, type MarketSymbol } from "@/api/endpoints/marketData";
import { getMyTokens, getCapTable } from "@/api/endpoints/tokens";
import { getMyStrategies, getStrategyPosition } from "@/api/endpoints/strategies";
import { getHistory } from "@/api/endpoints/marketHistory";
import { logReturns, stdev, seriesCorrelation, barsPerYear, type Bar } from "@/lib/marketStats";
import {
  allocation,
  concentration,
  exposure,
  portfolioVolatilityBps,
  parametricVarCents,
  historicalVarCents,
  diversificationScore,
  zForConfidence,
  type NormalizedPosition,
  type AllocationBy,
} from "@/lib/portfolioAnalytics";

// ── small helpers ────────────────────────────────────────────────────

function num(v: string | number | undefined | null): number {
  if (v == null) return 0;
  const n = typeof v === "number" ? v : parseFloat(v);
  return Number.isFinite(n) ? n : 0;
}

/** Format integer cents as a USD string. */
function usdCents(cents: number): string {
  return `$${(cents / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

/** bps -> "12.34%". */
function bpsPct(bps: number, digits = 2): string {
  return `${(bps / 100).toFixed(digits)}%`;
}

/** bps leverage -> "2.00x". */
function bpsX(bps: number): string {
  return `${(bps / 10_000).toFixed(2)}x`;
}

const HISTORY_INTERVAL = "1h";
const HISTORY_SECS = 3600;

/** Fetch + de-scale up to a recent window of bars for one market symbol. */
async function fetchBars(symbolId: number, scaler: number): Promise<{ bars: Bar[]; stub: boolean }> {
  const res = await getHistory(symbolId, { interval: HISTORY_INTERVAL });
  const s = scaler || 1;
  const bars: Bar[] = (res.bars ?? []).map((b) => ({
    ts: b.ts,
    o: b.o / s,
    h: b.h / s,
    l: b.l / s,
    c: b.c / s,
    v: b.v,
  }));
  bars.sort((a, b) => a.ts - b.ts);
  return { bars, stub: !!res.stub };
}

// ── presentational bits ──────────────────────────────────────────────

function SectionCard({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function WeightBar({ label, valueCents, weightBps }: { label: string; valueCents: number; weightBps: number }) {
  return (
    <div className="space-y-1 py-1.5">
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="truncate">{label}</span>
        <span className="tabular-nums text-muted-foreground">
          {bpsPct(weightBps)} · {usdCents(valueCents)}
        </span>
      </div>
      <Progress value={weightBps} max={10_000} />
    </div>
  );
}

function Stat({ label, value, tone, sub }: { label: string; value: string; tone?: string; sub?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="num text-lg font-semibold tabular-nums" style={tone ? { color: tone } : undefined}>
        {value}
      </span>
      {sub && <span className="text-[11px] text-muted-foreground">{sub}</span>}
    </div>
  );
}

const RED = "rgb(239 68 68)";
const GREEN = "rgb(16 185 129)";

// ── page ─────────────────────────────────────────────────────────────

export default function PortfolioAnalyticsPage() {
  // Cross-venue reads (mirror the Portfolio page; each degrades independently).
  const custodyQ = useQuery({ queryKey: ["pa", "custody"], queryFn: getBalance, retry: false });
  const stakingQ = useQuery({ queryKey: ["pa", "staking"], queryFn: getStakingPositions, retry: false });
  const spotQ = useQuery({ queryKey: ["pa", "spot"], queryFn: getSpotBalance, retry: false });
  const marginQ = useQuery({ queryKey: ["pa", "margin"], queryFn: getMarginAccount, retry: false });
  const symbolsQ = useQuery({ queryKey: ["pa", "symbols"], queryFn: getSymbols, retry: false });
  const pricesQ = useQuery({ queryKey: ["pa", "prices"], queryFn: getPrices, retry: false });
  const tokensQ = useQuery({ queryKey: ["pa", "tokens"], queryFn: getMyTokens, retry: false });
  const strategiesQ = useQuery({ queryKey: ["pa", "strategies"], queryFn: getMyStrategies, retry: false });

  const myTokens = tokensQ.data?.tokens ?? [];
  const myStrategies = strategiesQ.data?.strategies ?? [];

  // Per-token cap table (my qty) and per-strategy investor position.
  const capTableQs = useQueries({
    queries: myTokens.map((t) => ({
      queryKey: ["pa", "captable", t.token_id],
      queryFn: () => getCapTable(t.token_id),
      retry: false,
    })),
  });
  const strategyPosQs = useQueries({
    queries: myStrategies.map((s) => ({
      queryKey: ["pa", "stratpos", s.strategy_id],
      queryFn: () => getStrategyPosition(s.strategy_id),
      retry: false,
    })),
  });

  const refetchAll = () => {
    [custodyQ, stakingQ, spotQ, marginQ, symbolsQ, pricesQ, tokensQ, strategiesQ].forEach((q) => q.refetch());
    capTableQs.forEach((q) => q.refetch());
    strategyPosQs.forEach((q) => q.refetch());
  };

  const anyFetching =
    custodyQ.isFetching ||
    stakingQ.isFetching ||
    spotQ.isFetching ||
    marginQ.isFetching ||
    symbolsQ.isFetching ||
    pricesQ.isFetching ||
    tokensQ.isFetching ||
    strategiesQ.isFetching;

  const pricesStub = pricesQ.isSuccess && (pricesQ.data?.stub === true || pricesQ.data?.source === "stub");
  const pricesUnavailable = pricesQ.isError;

  // asset-symbol (upper) -> USD price (number). Empty when /me/prices 404s.
  const priceOf = useMemo(() => {
    const map = new Map<string, number>();
    for (const [sym, px] of Object.entries(pricesQ.data?.prices ?? {})) {
      const n = num(px);
      if (n > 0) map.set(sym.toUpperCase(), n);
    }
    return (symbol: string | undefined | null): number | undefined =>
      symbol ? map.get(String(symbol).toUpperCase()) : undefined;
  }, [pricesQ.data]);

  // Map an asset ticker to a tradeable market symbol (for history/vol/corr).
  const symLookup = useMemo(() => {
    const byId = new Map<number, MarketSymbol>();
    const list = symbolsQ.data?.symbols ?? [];
    for (const s of list) byId.set(s.symbol_id, s);
    const findByAsset = (asset: string | undefined | null): MarketSymbol | undefined => {
      if (!asset) return undefined;
      const up = String(asset).toUpperCase();
      // Prefer an exact base match ("BTC" -> "BTC-USD"/"BTCUSD"/"BTC"), else contains.
      return (
        list.find((s) => s.symbol.toUpperCase() === up) ||
        list.find((s) => s.symbol.toUpperCase().startsWith(up + "-") || s.symbol.toUpperCase().startsWith(up + "/")) ||
        list.find((s) => s.symbol.toUpperCase().startsWith(up)) ||
        list.find((s) => s.symbol.toUpperCase().includes(up))
      );
    };
    return { byId, findByAsset };
  }, [symbolsQ.data]);

  const marginSymName = (id: number | undefined): string => {
    const s = id != null ? symLookup.byId.get(id) : undefined;
    return s?.symbol ?? (id != null ? `#${id}` : "Margin position");
  };

  // ── build the normalized position list (USD cents, indicative) ──────
  // Only assets with a USD mark are valued; unpriced balances are counted so we
  // can honestly report how much of the book we could not value.
  const { positions, valuedCount, unpricedCount, sourcesOk } = useMemo(() => {
    const out: NormalizedPosition[] = [];
    let valued = 0;
    let unpriced = 0;
    let sources = 0;

    const push = (
      key: string,
      label: string,
      group: string,
      assetClass: string,
      amount: number,
      symbol: string | undefined,
      side: "long" | "short" = "long",
      qty?: number,
    ) => {
      if (amount === 0) return;
      const px = priceOf(symbol);
      if (px == null) {
        unpriced++;
        return;
      }
      const valueCents = Math.round(Math.abs(amount) * px * 100);
      if (valueCents <= 0) return;
      out.push({ key, label, group, assetClass, valueCents, side, qty });
      valued++;
    };

    const classOf = (sym: string | undefined): string => {
      const up = (sym ?? "").toUpperCase();
      if (up === "USDC" || up === "USDT" || up === "DAI" || up === "USD") return "Stablecoin";
      return "Crypto";
    };

    if (custodyQ.isSuccess) {
      sources++;
      for (const r of mergeBalances(custodyQ.data?.balances)) {
        const bal = num(r.balance);
        if (bal !== 0) push(`custody:${r.symbol}`, r.symbol, "Custody", classOf(r.symbol), bal, r.symbol, "long", bal);
      }
    }
    if (spotQ.isSuccess) {
      sources++;
      for (const b of spotQ.data?.balances ?? []) {
        const bal = num(b.balance);
        const sym = b.symbol;
        if (bal !== 0 && sym) push(`spot:${sym}`, sym, "Spot", classOf(sym), bal, sym, "long", bal);
      }
    }
    if (marginQ.isSuccess) {
      sources++;
      const m = marginQ.data;
      // Margin collateral balance is USD-denominated (quote currency).
      const bal = num(m?.balance);
      if (bal !== 0) {
        out.push({ key: "margin:cash", label: "Margin cash", group: "Margin", assetClass: "Cash", valueCents: Math.round(Math.abs(bal) * 100), side: "long" });
        valued++;
      }
      // The open leveraged position (valued via its notional at entry).
      const hasPos = num(m?.num_positions) > 0 && num(m?.pos_qty) !== 0;
      if (hasPos) {
        const symId = m?.pos_symbol_idx;
        const sym = symId != null ? symLookup.byId.get(symId) : undefined;
        const scaler = sym?.price_scaler || 1;
        const qtyRaw = num(m?.pos_qty);
        const entryRaw = num(m?.pos_entry_price);
        const notional = Math.abs((qtyRaw / scaler) * (entryRaw / scaler));
        if (notional > 0) {
          out.push({
            key: "margin:pos",
            label: marginSymName(symId),
            group: "Margin",
            assetClass: "Derivative",
            valueCents: Math.round(notional * 100),
            side: qtyRaw < 0 ? "short" : "long",
            qty: qtyRaw / scaler,
          });
          valued++;
        }
      }
    }
    if (stakingQ.isSuccess) {
      sources++;
      for (const p of stakingQ.data?.positions ?? []) {
        const tot = num(p.total);
        if (tot !== 0) push(`stake:${p.position_id}`, `${p.asset} (staked)`, "Staking", classOf(p.asset), tot, p.asset, "long", tot);
      }
    }
    // Creator tokens — value my holding at the token's clearing price (cents).
    if (tokensQ.isSuccess && myTokens.length > 0) {
      sources++;
      myTokens.forEach((t, i) => {
        const cap = capTableQs[i]?.data;
        const priceCents = num(t.clearing_price);
        // my qty: creator retains its slice; find my row by pct if present.
        const holders = cap?.holders ?? [];
        const myQty = holders.reduce((a, h) => a + num(h.qty), 0); // best-effort: sum (single-holder self view)
        const qty = myQty > 0 ? myQty : t.total_supply; // pre-IPO: hold full supply
        if (priceCents > 0 && qty > 0) {
          out.push({ key: `token:${t.token_id}`, label: `${t.ticker}`, group: "Tokens", assetClass: "Token", valueCents: Math.round(qty * priceCents), side: "long", qty });
          valued++;
        }
      });
    }
    // Strategy funds — value at my investor current_value.
    if (strategiesQ.isSuccess && myStrategies.length > 0) {
      sources++;
      myStrategies.forEach((s, i) => {
        const posn = strategyPosQs[i]?.data;
        const cv = num(posn?.current_value_cents);
        if (cv > 0) {
          out.push({ key: `strat:${s.strategy_id}`, label: s.name, group: "Strategies", assetClass: "Fund", valueCents: cv, side: "long", qty: num(posn?.units) });
          valued++;
        }
      });
    }

    return { positions: out, valuedCount: valued, unpricedCount: unpriced, sourcesOk: sources };
  }, [
    custodyQ.isSuccess, custodyQ.data, spotQ.isSuccess, spotQ.data, marginQ.isSuccess, marginQ.data,
    stakingQ.isSuccess, stakingQ.data, tokensQ.isSuccess, strategiesQ.isSuccess,
    myTokens, myStrategies, capTableQs, strategyPosQs, priceOf, symLookup,
  ]);

  const totalCents = useMemo(() => positions.reduce((a, p) => a + p.valueCents, 0), [positions]);
  const marginEquityCents = useMemo(() => {
    // Prefer the margin cash balance as the equity to lever gross exposure by;
    // fall back to total portfolio value when no margin balance is readable.
    const cash = positions.find((p) => p.key === "margin:cash");
    return cash ? cash.valueCents : totalCents;
  }, [positions, totalCents]);

  // ── derived analytics ──────────────────────────────────────────────
  const [allocBy, setAllocBy] = useState<AllocationBy>("asset");

  const byAsset = useMemo(() => allocation(positions, "asset"), [positions]);
  const alloc = useMemo(() => allocation(positions, allocBy), [positions, allocBy]);
  const conc = useMemo(() => concentration(byAsset, 5), [byAsset]);
  const expo = useMemo(() => exposure(positions, marginEquityCents), [positions, marginEquityCents]);

  // Per-asset return series for the RISK section — one history fetch per priced
  // asset that maps to a tradeable market symbol. Degrades on 404 to the recent
  // window (getHistory) and to an "empty" contribution when a symbol is missing.
  const riskAssets = useMemo(() => {
    // De-dupe by market symbol id; carry each asset's weight (bps) from byAsset.
    const seen = new Map<number, { symbolId: number; scaler: number; label: string; weightBps: number }>();
    for (const slice of byAsset) {
      const sym = symLookup.findByAsset(slice.label);
      if (!sym) continue;
      if (!seen.has(sym.symbol_id)) {
        seen.set(sym.symbol_id, { symbolId: sym.symbol_id, scaler: sym.price_scaler || 1, label: slice.label, weightBps: slice.weightBps });
      }
    }
    return [...seen.values()];
  }, [byAsset, symLookup]);

  const historyQs = useQueries({
    queries: riskAssets.map((a) => ({
      queryKey: ["pa", "hist", a.symbolId],
      queryFn: () => fetchBars(a.symbolId, a.scaler),
      retry: false,
      staleTime: 60_000,
      enabled: symbolsQ.isSuccess,
    })),
  });

  const risk = useMemo(() => {
    const n = riskAssets.length;
    const returnsByAsset: number[][] = [];
    const volsBps: number[] = [];
    const weights: number[] = [];
    const labels: string[] = [];
    let anyStub = false;
    let loadedCount = 0;
    let thin = false;

    const annFactor = Math.sqrt(barsPerYear(HISTORY_SECS));

    for (let i = 0; i < n; i++) {
      const q = historyQs[i];
      const bars = q?.data?.bars ?? [];
      anyStub = anyStub || !!q?.data?.stub;
      if (bars.length >= 2) loadedCount++;
      if (bars.length < 10) thin = true;
      const rets = logReturns(bars);
      const perBarVol = stdev(rets);
      const annVolBps = Math.round(perBarVol * annFactor * 10_000);
      returnsByAsset.push(rets);
      volsBps.push(annVolBps);
      weights.push(riskAssets[i]!.weightBps);
      labels.push(riskAssets[i]!.label);
    }

    // Correlation matrix over aligned bar series.
    const corr: number[][] = Array.from({ length: n }, () => new Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      corr[i]![i] = 1;
      for (let j = i + 1; j < n; j++) {
        const bi = historyQs[i]?.data?.bars ?? [];
        const bj = historyQs[j]?.data?.bars ?? [];
        const c = seriesCorrelation(bi, bj);
        corr[i]![j] = c;
        corr[j]![i] = c;
      }
    }

    const portVolBps = portfolioVolatilityBps(weights, volsBps, corr);

    // Historical portfolio return series: weighted sum of per-asset returns over
    // the shortest common length (equal weights fallback handled by normalize).
    let minLen = Infinity;
    for (const r of returnsByAsset) minLen = Math.min(minLen, r.length);
    const portReturns: number[] = [];
    if (Number.isFinite(minLen) && minLen > 0 && n > 0) {
      const wSum = weights.reduce((a, w) => a + Math.max(0, w), 0) || 1;
      for (let t = 0; t < minLen; t++) {
        let r = 0;
        for (let i = 0; i < n; i++) r += (Math.max(0, weights[i]!) / wSum) * (returnsByAsset[i]![t] ?? 0);
        portReturns.push(r);
      }
    }

    const z = zForConfidence(0.95);
    const paramVar = parametricVarCents(totalCents, portVolBps, z);
    const histVar = historicalVarCents(totalCents, portReturns, 0.95);
    const divScore = diversificationScore(byAsset, corr);

    const loading = historyQs.some((q) => q.isLoading);
    return { n, portVolBps, paramVar, histVar, divScore, anyStub, thin, loadedCount, portReturnsLen: portReturns.length, loading };
  }, [riskAssets, historyQs, totalCents, byAsset]);

  // ── render ─────────────────────────────────────────────────────────
  const anyLoading =
    custodyQ.isLoading || spotQ.isLoading || marginQ.isLoading || stakingQ.isLoading ||
    tokensQ.isLoading || strategiesQ.isLoading || symbolsQ.isLoading;

  const bookEmpty = !anyLoading && positions.length === 0;
  const concentratedLabel = conc.hhi >= 2500 ? "Concentrated" : conc.hhi >= 1500 ? "Moderately concentrated" : "Diversified";
  const concentratedTone = conc.hhi >= 2500 ? "destructive" : conc.hhi >= 1500 ? "warning" : "success";
  const leverageBps = expo.leverageBps;
  const levTone = leverageBps > 30_000 ? "destructive" : leverageBps > 15_000 ? "warning" : "secondary";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-xl font-semibold leading-tight">Portfolio Risk</h1>
            <p className="text-xs text-muted-foreground">
              Client-computed allocation, concentration, exposure & risk across custody, spot, margin, tokens, funds & staking.
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="gap-2 self-start sm:self-auto" onClick={refetchAll}>
          <RefreshCw className={cn("h-4 w-4", anyFetching && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* Valuation banner */}
      <Card>
        <CardContent className="flex flex-col gap-1 py-5">
          <span className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
            Total valued (indicative USD)
            {pricesStub && (
              <Badge variant="outline" className="gap-1 text-[10px] font-normal normal-case">
                <Info className="h-3 w-3" /> indicative (stub prices)
              </Badge>
            )}
          </span>
          {anyLoading ? (
            <Skeleton className="h-9 w-48" />
          ) : (
            <div className="flex items-baseline gap-2">
              <span className="num text-3xl font-bold tabular-nums">{usdCents(totalCents)}</span>
              {anyFetching && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
            </div>
          )}
          <span className="text-[11px] text-muted-foreground">
            {pricesUnavailable
              ? "USD valuation marks unavailable on this backend — risk analytics cannot value the book here."
              : `Valued ${valuedCount} position${valuedCount === 1 ? "" : "s"} across ${sourcesOk} source${sourcesOk === 1 ? "" : "s"}`}
            {unpricedCount > 0 ? `, ${unpricedCount} unpriced balance${unpricedCount === 1 ? "" : "s"} excluded` : ""}
            {pricesStub ? " — indicative marks, not a live valuation." : "."}
          </span>
        </CardContent>
      </Card>

      {bookEmpty ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No valuable positions to analyze. Once custody / spot / margin / token / fund / staking
            holdings with a USD price mark are readable, allocation and risk analytics appear here.
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Allocation */}
          <SectionCard title="Allocation" icon={<PieChart className="h-4 w-4 text-muted-foreground" />}>
            <Tabs value={allocBy} onValueChange={(v) => setAllocBy(v as AllocationBy)}>
              <TabsList className="mb-3">
                <TabsTrigger value="asset">By asset</TabsTrigger>
                <TabsTrigger value="class">By class</TabsTrigger>
                <TabsTrigger value="product">By product</TabsTrigger>
              </TabsList>
              <TabsContent value={allocBy} className="mt-0">
                {anyLoading ? (
                  <div className="space-y-3 py-2">
                    {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-6 w-full" />)}
                  </div>
                ) : alloc.length === 0 ? (
                  <p className="py-4 text-sm text-muted-foreground">Nothing to allocate.</p>
                ) : (
                  <div className="divide-y divide-border/40">
                    {alloc.map((s) => (
                      <WeightBar key={s.label} label={s.label} valueCents={s.valueCents} weightBps={s.weightBps} />
                    ))}
                    <div className="flex items-center justify-between pt-3 text-sm font-medium">
                      <span>Total</span>
                      <span className="tabular-nums">{usdCents(totalCents)}</span>
                    </div>
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </SectionCard>

          {/* Concentration */}
          <SectionCard title="Concentration" icon={<Layers className="h-4 w-4 text-muted-foreground" />}>
            {anyLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex flex-col gap-0.5">
                    <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Herfindahl (HHI)</span>
                    <span className="num text-2xl font-semibold tabular-nums">{conc.hhi.toLocaleString()}</span>
                    <span className="text-[11px] text-muted-foreground">0 = perfectly even · 10,000 = single position</span>
                  </div>
                  <Badge variant={concentratedTone as never}>{concentratedLabel}</Badge>
                </div>
                <Progress value={conc.hhi} max={10_000} />
                <Separator />
                <div>
                  <p className="mb-2 text-xs font-medium text-muted-foreground">Top positions</p>
                  <div className="divide-y divide-border/40">
                    {conc.top.map((t) => (
                      <div key={t.label} className="flex items-center justify-between py-1.5 text-sm">
                        <span className="truncate">{t.label}</span>
                        <span className="tabular-nums text-muted-foreground">{bpsPct(t.weightBps)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </SectionCard>

          {/* Exposure */}
          <SectionCard title="Exposure" icon={<Scale className="h-4 w-4 text-muted-foreground" />}>
            {anyLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <Stat label="Gross" value={usdCents(expo.grossCents)} />
                  <Stat label="Net" value={usdCents(expo.netCents)} tone={expo.netCents < 0 ? RED : GREEN} />
                  <Stat label="Long" value={usdCents(expo.longCents)} tone={GREEN} />
                  <Stat label="Short" value={usdCents(expo.shortCents)} tone={expo.shortCents > 0 ? RED : undefined} />
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div className="flex flex-col gap-0.5">
                    <span className="text-[11px] uppercase tracking-wide text-muted-foreground">Leverage (gross / margin equity)</span>
                    <span className="num text-2xl font-semibold tabular-nums">{bpsX(leverageBps)}</span>
                  </div>
                  <Badge variant={levTone as never}>
                    {leverageBps > 30_000 ? "High leverage" : leverageBps > 15_000 ? "Elevated" : leverageBps > 10_000 ? "Levered" : "Unlevered"}
                  </Badge>
                </div>
                {expo.shortCents === 0 && (
                  <p className="text-[11px] text-muted-foreground">
                    No short exposure detected — gross equals net. Margin shorts surface here when the open position is a short.
                  </p>
                )}
              </div>
            )}
          </SectionCard>

          {/* Risk */}
          <SectionCard title="Risk" icon={<Activity className="h-4 w-4 text-muted-foreground" />}>
            {pricesUnavailable ? (
              <div className="flex flex-col items-start gap-2 py-4">
                <p className="text-sm text-muted-foreground">Cannot value the book — risk analytics are unavailable on this backend.</p>
                <Badge variant="outline" className="gap-1.5"><Info className="h-3 w-3" /> Valuation marks unavailable</Badge>
              </div>
            ) : risk.loading ? (
              <Skeleton className="h-28 w-full" />
            ) : risk.n === 0 ? (
              <p className="py-4 text-sm text-muted-foreground">
                No priced asset maps to a tradeable market symbol, so volatility & VaR cannot be computed. Cash / fund / token
                legs still count toward allocation and exposure above.
              </p>
            ) : (
              <div className="space-y-4">
                {(risk.anyStub || risk.thin) && (
                  <Badge variant="outline" className="gap-1.5 text-[11px] font-normal">
                    <Info className="h-3 w-3" />
                    {risk.anyStub ? "Recent window only — real history endpoint not deployed" : "Limited history — estimates use a thin window"}
                  </Badge>
                )}
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                  <Stat label="Ann. volatility" value={bpsPct(risk.portVolBps, 1)} sub={`${risk.n} priced asset${risk.n === 1 ? "" : "s"}`} />
                  <Stat label="Parametric VaR (95%)" value={usdCents(risk.paramVar)} tone={RED} sub="1-period, z=1.645" />
                  <Stat
                    label="Historical VaR (95%)"
                    value={risk.portReturnsLen > 0 ? usdCents(risk.histVar) : "—"}
                    tone={risk.histVar > 0 ? RED : undefined}
                    sub={risk.portReturnsLen > 0 ? `${risk.portReturnsLen} periods` : "no return series"}
                  />
                </div>
                <Separator />
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="flex items-center gap-1.5 text-muted-foreground">
                      <TrendingUp className="h-3.5 w-3.5" /> Diversification score
                    </span>
                    <span className="num font-semibold tabular-nums">{risk.divScore} / 100</span>
                  </div>
                  <Progress value={risk.divScore} max={100} />
                  <p className="text-[11px] text-muted-foreground">
                    Higher = lower average pairwise correlation and more even weights. VaR is the indicative 1-period loss not
                    expected to be exceeded at 95% confidence, on indicative marks.
                  </p>
                </div>
              </div>
            )}
          </SectionCard>
        </div>
      )}
    </div>
  );
}
