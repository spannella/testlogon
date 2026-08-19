import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Bell,
  CandlestickChart,
  CheckCircle2,
  Circle,
  Home as HomeIcon,
  Info,
  LineChart,
  PieChart,
  Plus,
  Wallet,
  X,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/client";

import { useMarginAccount, useSpotBalance } from "@/hooks/useTrading";
import { useSymbols, useCandles } from "@/hooks/useMarketData";
import { useTradingAlerts, relativeTime } from "@/hooks/useTradingAlerts";
import { getBalance } from "@/api/endpoints/custody";
import { getFillsFees, type FillFee } from "@/api/endpoints/trading";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { loadDefaultSymbol } from "@/lib/tradingPrefs";
import { formatPrice, formatQty } from "@/pages/markets/format";

// local helpers

const WATCHLIST_KEY = "md.watchlist.v1";
const ONBOARDING_DISMISSED_KEY = "home.onboardingDismissed";

function loadWatchlist(): number[] {
  try {
    const raw = localStorage.getItem(WATCHLIST_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "number") : [];
  } catch {
    return [];
  }
}

function num(v: string | number | undefined | null): number {
  if (v == null) return 0;
  const n = typeof v === "number" ? v : parseFloat(v);
  return Number.isFinite(n) ? n : 0;
}

// 404/403 = "not available on this backend" -> treated as UNKNOWN, not "no".
function isUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 404 || err.status === 403;
  const msg = (err as Error)?.message ?? "";
  return /\b40[34]\b/.test(msg);
}

// nanosecond / second / ms epoch -> ms.
function toMs(ts: number | undefined): number {
  if (ts == null || !Number.isFinite(ts)) return 0;
  if (ts > 1e17) return Math.floor(ts / 1_000_000);
  if (ts < 1e12) return Math.floor(ts * 1000);
  return Math.floor(ts);
}

function CardError({ line }: { line: string }) {
  return (
    <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
      <Info className="h-3.5 w-3.5 shrink-0" />
      <span>{line}</span>
    </div>
  );
}

function EmptyLine({ children }: { children: React.ReactNode }) {
  return <p className="py-2 text-xs text-muted-foreground">{children}</p>;
}

// 1. Portfolio summary

function PortfolioSummaryCard() {
  const marginQ = useMarginAccount();
  const custodyQ = useQuery({
    queryKey: ["home", "custody", "balance"],
    queryFn: getBalance,
    retry: false,
    refetchInterval: 30_000,
  });
  const spotQ = useSpotBalance();

  const margin = marginQ.data;
  const available = num(margin?.available_balance);
  const unrealized = num(margin?.pos_unrealized_pnl);

  const equity = useMemo(() => {
    let sum = 0;
    let anySource = false;
    if (marginQ.isSuccess) {
      sum += num(margin?.balance);
      anySource = true;
    }
    if (spotQ.isSuccess) {
      sum += (spotQ.data?.balances ?? []).reduce((a, b) => a + num(b.balance), 0);
      anySource = true;
    }
    if (custodyQ.isSuccess) {
      for (const v of Object.values(custodyQ.data?.balances ?? {})) sum += num(v);
      anySource = true;
    }
    return { sum, anySource };
  }, [
    marginQ.isSuccess,
    spotQ.isSuccess,
    custodyQ.isSuccess,
    margin,
    spotQ.data,
    custodyQ.data,
  ]);

  const loading = marginQ.isLoading && spotQ.isLoading && custodyQ.isLoading;
  const allFailed = marginQ.isError && spotQ.isError && custodyQ.isError;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <div className="flex items-center gap-2">
          <PieChart className="h-4 w-4 text-primary" />
          <CardTitle className="text-sm">Portfolio</CardTitle>
        </div>
        <Link
          to="/portfolio"
          className="flex items-center gap-1 text-xs text-primary hover:underline"
        >
          View portfolio <ArrowUpRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent className="space-y-3">
        {loading ? (
          <Skeleton className="h-8 w-40" />
        ) : allFailed ? (
          <CardError line="Portfolio sources are unavailable right now." />
        ) : (
          <>
            <div>
              <span className="text-xs uppercase tracking-wide text-muted-foreground">
                Snapshot equity
              </span>
              <div className="num text-2xl font-bold tabular-nums">
                {equity.anySource
                  ? equity.sum.toLocaleString(undefined, {
                      maximumFractionDigits: 2,
                    })
                  : "—"}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <span className="text-[11px] uppercase tracking-wide text-muted-foreground">
                  Available
                </span>
                <div className="num text-sm font-semibold tabular-nums">
                  {marginQ.isSuccess
                    ? available.toLocaleString(undefined, { maximumFractionDigits: 2 })
                    : "—"}
                </div>
              </div>
              <div>
                <span className="text-[11px] uppercase tracking-wide text-muted-foreground">
                  Unrealized PnL
                </span>
                <div
                  className={cn(
                    "num text-sm font-semibold tabular-nums",
                    marginQ.isSuccess && unrealized > 0 && "text-emerald-600 dark:text-emerald-400",
                    marginQ.isSuccess && unrealized < 0 && "text-rose-600 dark:text-rose-400",
                  )}
                >
                  {marginQ.isSuccess
                    ? `${unrealized > 0 ? "+" : ""}${unrealized.toLocaleString(undefined, { maximumFractionDigits: 2 })}`
                    : "—"}
                </div>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// 2. Watchlist snapshot

function WatchRow({ sym }: { sym: MarketSymbol }) {
  const scaler = sym.price_scaler || 1;
  const candles = useCandles(sym.symbol_id, 60, true, 60);
  const bars = candles.data?.bars ?? [];
  const closes = bars.map((b) => b.close);
  const last = closes.length ? closes[closes.length - 1]! : sym.reference_price;
  const first = closes.length ? closes[0]! : undefined;
  const changePct =
    first != null && first !== 0 ? ((last - first) / first) * 100 : undefined;
  const up = (changePct ?? 0) >= 0;

  return (
    <Link
      to={`/markets/${sym.symbol_id}`}
      className="flex items-center justify-between rounded-md px-2 py-1.5 hover:bg-muted/60"
    >
      <span className="text-sm font-medium">{sym.symbol}</span>
      <span className="flex items-center gap-3">
        <span className="num text-sm tabular-nums">{formatPrice(last, scaler)}</span>
        <span
          className={cn(
            "num w-16 text-right text-xs tabular-nums",
            changePct == null
              ? "text-muted-foreground"
              : up
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-rose-600 dark:text-rose-400",
          )}
        >
          {changePct == null ? "—" : `${up ? "+" : ""}${changePct.toFixed(2)}%`}
        </span>
      </span>
    </Link>
  );
}

function WatchlistCard() {
  const [watchlist] = useState<number[]>(loadWatchlist);
  const symbolsQ = useSymbols();

  const rows = useMemo(() => {
    const all = symbolsQ.data?.symbols ?? [];
    const byId = new Map(all.map((s) => [s.symbol_id, s]));
    return watchlist
      .map((id) => byId.get(id))
      .filter((s): s is MarketSymbol => Boolean(s))
      .slice(0, 6);
  }, [symbolsQ.data, watchlist]);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <div className="flex items-center gap-2">
          <CandlestickChart className="h-4 w-4 text-primary" />
          <CardTitle className="text-sm">Watchlist</CardTitle>
        </div>
        <Link
          to="/markets"
          className="flex items-center gap-1 text-xs text-primary hover:underline"
        >
          Markets <ArrowUpRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent>
        {symbolsQ.isLoading && watchlist.length > 0 ? (
          <div className="space-y-2">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full" />
          </div>
        ) : watchlist.length === 0 ? (
          <div className="flex flex-col items-start gap-2 py-2">
            <EmptyLine>No markets starred yet.</EmptyLine>
            <Button asChild size="sm" variant="outline" className="gap-1">
              <Link to="/markets">
                <Plus className="h-3.5 w-3.5" /> Add markets
              </Link>
            </Button>
          </div>
        ) : rows.length === 0 ? (
          <CardError line="Could not resolve your starred markets." />
        ) : (
          <div className="-mx-2">
            {rows.map((s) => (
              <WatchRow key={s.symbol_id} sym={s} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// 3. Recent activity

function symbolNameFrom(symbols: MarketSymbol[] | undefined, id: number | undefined): string {
  if (id == null) return "—";
  const s = symbols?.find((x) => x.symbol_id === id);
  return s?.symbol ?? `#${id}`;
}

function RecentActivityCard() {
  const fillsQ = useQuery({
    queryKey: ["home", "fills", "fees"],
    queryFn: getFillsFees,
    retry: false,
    refetchInterval: 15_000,
  });
  const symbolsQ = useSymbols();
  const { alerts } = useTradingAlerts();

  const fills: FillFee[] = useMemo(
    () => (fillsQ.data?.fills ?? []).slice(0, 5),
    [fillsQ.data],
  );
  const recentAlerts = useMemo(() => alerts.slice(0, 4), [alerts]);

  const fillsFailed = fillsQ.isError && !isUnavailable(fillsQ.error);
  const fillsUnavailable = fillsQ.isError && isUnavailable(fillsQ.error);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm">Recent activity</CardTitle>
        <span className="flex items-center gap-3 text-xs">
          <Link to="/pnl" className="text-primary hover:underline">
            PnL
          </Link>
          <Link to="/blotter" className="text-primary hover:underline">
            History
          </Link>
        </span>
      </CardHeader>
      <CardContent className="space-y-3">
        <div>
          <div className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">
            Recent fills
          </div>
          {fillsQ.isLoading ? (
            <Skeleton className="h-5 w-full" />
          ) : fillsUnavailable ? (
            <EmptyLine>Fills feed not available on this backend.</EmptyLine>
          ) : fillsFailed ? (
            <CardError line="Could not load recent fills." />
          ) : fills.length === 0 ? (
            <EmptyLine>No fills yet.</EmptyLine>
          ) : (
            <div className="space-y-0.5">
              {fills.map((f, i) => {
                const scaler =
                  symbolsQ.data?.symbols?.find((s) => s.symbol_id === f.symbolid)?.price_scaler || 1;
                const buy = String(f.side).toLowerCase().includes("b");
                return (
                  <div
                    key={`${f.symbolid}-${f.ts}-${i}`}
                    className="flex items-center justify-between text-xs"
                  >
                    <span className="flex items-center gap-2">
                      <Badge
                        variant={buy ? "success" : "destructive"}
                        className="px-1.5 py-0 text-[10px]"
                      >
                        {buy ? "BUY" : "SELL"}
                      </Badge>
                      <span className="font-medium">
                        {symbolNameFrom(symbolsQ.data?.symbols, f.symbolid)}
                      </span>
                    </span>
                    <span className="num tabular-nums text-muted-foreground">
                      {formatQty(f.qty, scaler)} @ {formatPrice(f.price, scaler)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {recentAlerts.length > 0 && (
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">
              Trading alerts
            </div>
            <div className="space-y-1">
              {recentAlerts.map((a) => (
                <div key={a.id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate">{a.title}</span>
                  <span className="shrink-0 text-[11px] text-muted-foreground">
                    {relativeTime(toMs(a.ts))}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// 4. Quick actions

function QuickActionsCard() {
  const navigate = useNavigate();
  const goTrade = () => {
    const id = loadDefaultSymbol();
    navigate(id ? `/markets/${id}` : "/markets");
  };
  const actions: { label: string; icon: React.ReactNode; onClick: () => void }[] = [
    { label: "Trade", icon: <CandlestickChart className="h-4 w-4" />, onClick: goTrade },
    { label: "Deposit", icon: <Wallet className="h-4 w-4" />, onClick: () => navigate("/custody") },
    { label: "Portfolio", icon: <PieChart className="h-4 w-4" />, onClick: () => navigate("/portfolio") },
    { label: "PnL", icon: <LineChart className="h-4 w-4" />, onClick: () => navigate("/pnl") },
    { label: "Price alerts", icon: <Bell className="h-4 w-4" />, onClick: () => navigate("/markets/price-alerts") },
  ];
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Quick actions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {actions.map((a) => (
            <Button
              key={a.label}
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={a.onClick}
            >
              {a.icon}
              {a.label}
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// 5. Getting-started / onboarding

type StepState = "done" | "todo" | "unknown";

function StepRow({
  state,
  label,
  to,
}: {
  state: StepState;
  label: string;
  to: string;
}) {
  return (
    <Link
      to={to}
      className="flex items-center gap-3 rounded-md px-2 py-2 hover:bg-muted/60"
    >
      {state === "done" ? (
        <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-500" />
      ) : (
        <Circle
          className={cn(
            "h-5 w-5 shrink-0",
            state === "unknown" ? "text-muted-foreground/50" : "text-muted-foreground",
          )}
        />
      )}
      <span
        className={cn(
          "flex-1 text-sm",
          state === "done" && "text-muted-foreground line-through",
        )}
      >
        {label}
      </span>
      {state === "unknown" && (
        <Badge variant="outline" className="text-[10px] font-normal">
          unknown
        </Badge>
      )}
      <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground" />
    </Link>
  );
}

function OnboardingCard() {
  const custodyQ = useQuery({
    queryKey: ["home", "onboarding", "custody"],
    queryFn: getBalance,
    retry: false,
    refetchInterval: 30_000,
  });
  const marginQ = useMarginAccount();
  const spotQ = useSpotBalance();
  const fillsQ = useQuery({
    queryKey: ["home", "fills", "fees"],
    queryFn: getFillsFees,
    retry: false,
    refetchInterval: 15_000,
  });

  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(ONBOARDING_DISMISSED_KEY) === "1";
    } catch {
      return false;
    }
  });

  const custodyStep: StepState = custodyQ.isSuccess
    ? Object.values(custodyQ.data?.balances ?? {}).some((v) => num(v as number | string) > 0)
      ? "done"
      : "todo"
    : "unknown";

  const spotFunded = spotQ.isSuccess
    ? (spotQ.data?.balances ?? []).some((b) => num(b.available) > 0 || num(b.balance) > 0)
    : undefined;
  const marginFunded = marginQ.isSuccess
    ? num(marginQ.data?.available_balance) > 0 || num(marginQ.data?.balance) > 0
    : undefined;
  const tradingStep: StepState =
    spotFunded || marginFunded
      ? "done"
      : spotQ.isSuccess || marginQ.isSuccess
        ? "todo"
        : "unknown";

  const tradeStep: StepState = fillsQ.isSuccess
    ? (fillsQ.data?.fills ?? []).length > 0
      ? "done"
      : "todo"
    : "unknown";

  const steps: { state: StepState; label: string; to: string }[] = [
    { state: custodyStep, label: "Fund your custody vault", to: "/custody" },
    { state: tradingStep, label: "Fund your trading account", to: "/portfolio" },
    { state: tradeStep, label: "Place your first trade", to: "/markets" },
  ];

  const anyLoading =
    custodyQ.isLoading || marginQ.isLoading || spotQ.isLoading || fillsQ.isLoading;
  const allDone = steps.every((s) => s.state === "done");
  const anyTodo = steps.some((s) => s.state === "todo");

  const dismiss = () => {
    try {
      localStorage.setItem(ONBOARDING_DISMISSED_KEY, "1");
    } catch {
      /* ignore */
    }
    setDismissed(true);
  };

  if (allDone && dismissed) return null;

  if (allDone) {
    return (
      <Card>
        <CardContent className="flex items-center justify-between gap-2 py-3">
          <span className="flex items-center gap-2 text-sm">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            You&apos;re all set &mdash; happy trading.
          </span>
          <Button variant="ghost" size="sm" className="h-7 gap-1 px-2" onClick={dismiss}>
            <X className="h-3.5 w-3.5" /> Dismiss
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn(anyTodo && "border-primary/40")}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Getting started</CardTitle>
        <CardDescription className="text-xs">
          Finish setting up your trading account.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {anyLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : (
          <div className="-mx-2">
            {steps.map((s) => (
              <StepRow key={s.label} state={s.state} label={s.label} to={s.to} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Page

export default function HomePage() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <HomeIcon className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-xl font-semibold leading-tight">Home</h1>
          <p className="text-xs text-muted-foreground">
            Your trading overview at a glance.
          </p>
        </div>
      </div>

      <OnboardingCard />

      <QuickActionsCard />

      <div className="grid gap-4 lg:grid-cols-2">
        <PortfolioSummaryCard />
        <WatchlistCard />
      </div>

      <RecentActivityCard />
    </div>
  );
}
