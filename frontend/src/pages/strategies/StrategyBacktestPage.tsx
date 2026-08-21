import { useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQueries } from "@tanstack/react-query";
import { ArrowLeft, FlaskConical, Play, TrendingUp, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useStrategy } from "@/hooks/useStrategies";
import { useSymbols } from "@/hooks/useMarketData";
import { getHistory, intervalToSeconds } from "@/api/endpoints/marketHistory";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { basketBacktest, formatBps, type LegSeries } from "@/lib/strategies";
import type { Bar } from "@/lib/marketStats";
import { newAccount, placeOrder, equity as paperEquity, type PaperAccount } from "@/lib/paperEngine";
import { PendingBackend, PooledNavNote } from "./PendingBackend";

const INTERVAL = "1d";
const PAPER_SEED_CENTS = 100_000_00; // $100k paper capital

/** Sparkline-style SVG equity curve (base 1.0). */
function EquityCurve({ equity }: { equity: number[] }) {
  if (equity.length < 2) return null;
  const w = 640;
  const h = 160;
  const min = Math.min(...equity);
  const max = Math.max(...equity);
  const span = max - min || 1;
  const pts = equity
    .map((v, i) => {
      const x = (i / (equity.length - 1)) * w;
      const y = h - ((v - min) / span) * h;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const up = equity[equity.length - 1]! >= equity[0]!;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-40 w-full" preserveAspectRatio="none" role="img" aria-label="Backtest equity curve">
      <polyline
        fill="none"
        stroke={up ? "hsl(142 71% 45%)" : "hsl(0 72% 51%)"}
        strokeWidth={2}
        points={pts}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  const cls =
    tone === "pos"
      ? "text-emerald-600 dark:text-emerald-400"
      : tone === "neg"
        ? "text-rose-600 dark:text-rose-400"
        : "";
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-0.5 font-semibold tabular-nums ${cls}`}>{value}</p>
    </div>
  );
}

export default function StrategyBacktestPage() {
  const { id } = useParams<{ id: string }>();
  const strategyQ = useStrategy(id);
  const symbolsQ = useSymbols();
  const strategy = strategyQ.data;

  const legs = strategy?.legs ?? [];
  const symById = useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbolsQ.data?.symbols ?? []) m.set(s.symbol_id, s);
    return m;
  }, [symbolsQ.data]);

  // Fetch each leg's history (degrades to the recent candle window on 404).
  const historyQueries = useQueries({
    queries: legs.map((leg) => ({
      queryKey: ["strategy-backtest-history", leg.symbol_id, INTERVAL],
      queryFn: () => getHistory(leg.symbol_id, { interval: INTERVAL }),
      enabled: !!strategy && leg.symbol_id > 0,
      retry: false,
      staleTime: 60_000,
    })),
  });

  const anyLoading = historyQueries.some((q) => q.isLoading);
  const anyStub = historyQueries.some((q) => q.data?.stub);
  const anyError = historyQueries.some((q) => q.isError);

  // De-scale each leg's bars by its symbol price_scaler into Bar[].
  const legSeries: LegSeries[] = useMemo(() => {
    return legs.map((leg, i) => {
      const res = historyQueries[i]?.data;
      const sym = symById.get(leg.symbol_id);
      const scaler = sym?.price_scaler && sym.price_scaler > 0 ? sym.price_scaler : 1;
      const bars: Bar[] = (res?.bars ?? []).map((b) => ({
        ts: b.ts,
        o: b.o / scaler,
        h: b.h / scaler,
        l: b.l / scaler,
        c: b.c / scaler,
        v: b.v,
      }));
      return { symbol_id: leg.symbol_id, weight_bps: leg.weight_bps, bars };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [legs, symById, historyQueries.map((q) => q.dataUpdatedAt).join(",")]);

  const backtest = useMemo(
    () => basketBacktest(legSeries, intervalToSeconds(INTERVAL)),
    [legSeries],
  );

  // -- Paper run -------------------------------------------------------
  const [paper, setPaper] = useState<PaperAccount | null>(null);

  const runPaper = () => {
    if (!strategy) return;
    // Seed a paper account and place a market buy per leg sized by its target
    // weight against the latest de-scaled close (the fund following the basket).
    let acct = newAccount(PAPER_SEED_CENTS);
    const marks: Record<number, number> = {};
    let placed = 0;
    for (const ls of legSeries) {
      const last = ls.bars[ls.bars.length - 1]?.c;
      if (!(last && last > 0) || !(ls.weight_bps > 0)) continue;
      const allocCents = PAPER_SEED_CENTS * (ls.weight_bps / 10_000);
      // Paper engine works in ticks/quote units; use cents as the quote unit and
      // price in cents so cash accounting stays integer-cents consistent.
      const priceCents = Math.max(1, Math.round(last * 100));
      const qty = Math.floor(allocCents / priceCents);
      if (qty <= 0) continue;
      marks[ls.symbol_id] = priceCents;
      const res = placeOrder(acct, { symbolId: ls.symbol_id, side: "buy", type: "market", qty }, priceCents);
      acct = res.account;
      placed += 1;
    }
    setPaper(acct);
    if (placed === 0) {
      toast.error("No leg had a usable price to paper-trade yet.");
    } else {
      toast.success(`Paper account seeded — bought ${placed} leg${placed === 1 ? "" : "s"} by weight.`);
    }
  };

  const paperEquityCents = useMemo(() => {
    if (!paper) return 0;
    const marks: Record<number, number> = {};
    for (const ls of legSeries) {
      const last = ls.bars[ls.bars.length - 1]?.c;
      if (last && last > 0) marks[ls.symbol_id] = Math.max(1, Math.round(last * 100));
    }
    return paperEquity(paper, marks);
  }, [paper, legSeries]);

  if (strategyQ.isError) {
    return (
      <Shell id={id}>
        <PendingBackend label="This strategy" />
      </Shell>
    );
  }

  const s = backtest.stats;

  return (
    <Shell id={id} name={strategy?.name}>
      <PooledNavNote />

      {(anyStub || anyError) && (
        <p className="flex items-start gap-2 rounded-md border border-amber-300/50 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-300">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Long-range history is unavailable — the backtest uses the most recent candle window
            for {anyError ? "some legs" : "one or more legs"}. Results are indicative only.
          </span>
        </p>
      )}

      {/* Backtest */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-base">
            <FlaskConical className="h-4 w-4" /> Basket backtest ({INTERVAL})
          </CardTitle>
          {backtest.aligned ? (
            <Badge variant="secondary">{backtest.steps} bars</Badge>
          ) : (
            <Badge variant="outline">single-leg</Badge>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          {strategyQ.isLoading || anyLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : backtest.equity.length < 2 ? (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              Not enough overlapping history across the legs to backtest yet.
            </div>
          ) : (
            <>
              <EquityCurve equity={backtest.equity} />
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <Stat
                  label="Total return"
                  value={`${s.cumulativeReturn >= 0 ? "+" : ""}${(s.cumulativeReturn * 100).toFixed(2)}%`}
                  tone={s.cumulativeReturn >= 0 ? "pos" : "neg"}
                />
                <Stat label="Ann. volatility" value={`${(s.annualizedVolatility * 100).toFixed(1)}%`} />
                <Stat label="Max drawdown" value={`${(s.maxDrawdown * 100).toFixed(1)}%`} tone="neg" />
                <Stat label="Bars" value={String(s.bars)} />
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Composition */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Composition</CardTitle>
        </CardHeader>
        <CardContent>
          {legs.length === 0 ? (
            <p className="text-sm text-muted-foreground">This strategy has no legs.</p>
          ) : (
            <div className="space-y-2">
              {legSeries.map((ls) => (
                <div key={ls.symbol_id} className="flex items-center justify-between text-sm">
                  <span className="font-medium">{symById.get(ls.symbol_id)?.symbol ?? `#${ls.symbol_id}`}</span>
                  <span className="tabular-nums text-muted-foreground">
                    {formatBps(ls.weight_bps)} · {ls.bars.length} bars
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Paper run */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-base">
            <TrendingUp className="h-4 w-4" /> Paper-trade the basket
          </CardTitle>
          <Button size="sm" onClick={runPaper} disabled={!strategy || anyLoading} data-testid="run-paper">
            <Play className="mr-1 h-4 w-4" /> {paper ? "Re-run" : "Run paper"}
          </Button>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-xs text-muted-foreground">
            Seeds a paper account with $100,000 and buys each leg by its target weight at the
            latest price — no real capital. This is the &ldquo;paper-trade before you invest&rdquo; step.
          </p>
          {!paper ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              Run the paper account to preview how the basket would hold.
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label="Seed" value={`$${(PAPER_SEED_CENTS / 100).toLocaleString()}`} />
              <Stat label="Cash left" value={`$${(paper.cash / 100).toLocaleString(undefined, { maximumFractionDigits: 0 })}`} />
              <Stat label="Positions" value={String(Object.values(paper.positions).filter((p) => p.qty !== 0).length)} />
              <Stat label="Mark value" value={`$${(paperEquityCents / 100).toLocaleString(undefined, { maximumFractionDigits: 0 })}`} />
            </div>
          )}
        </CardContent>
      </Card>
    </Shell>
  );
}

function Shell({ id, name, children }: { id?: string; name?: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="icon">
          <Link to={id ? `/strategies/${encodeURIComponent(id)}` : "/strategies"} aria-label="Back">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div className="flex items-center gap-2">
          <FlaskConical className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">
            Paper-run &amp; backtest{name ? <span className="text-muted-foreground"> — {name}</span> : null}
          </h1>
        </div>
      </div>
      {children}
    </div>
  );
}
