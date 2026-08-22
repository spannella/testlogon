import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Sparkles,
  TrendingUp,
  Landmark,
  Boxes,
  Coins,
  Rocket,
  ChevronRight,
  Search,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

import { useSymbols, useCandles } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import { useTokenMarket } from "@/hooks/useTokens";
import { useStrategyMarket } from "@/hooks/useStrategies";
import { getOpenTokenAuctions } from "@/api/endpoints/tokens";
import { getStakingProviders, type StakingProvider } from "@/api/endpoints/custody";
import { getBailouts, type BailoutAuction } from "@/api/endpoints/bailouts";
import { getStakeRequests, getOpenAuctions } from "@/api/endpoints/trading";
import {
  ALL_CLASS,
  CLASS_TAB_ORDER,
  CLASS_LABELS,
  symbolInClass,
  type ClassTab,
} from "@/lib/instrumentClass";
import {
  searchSymbols,
  searchTokens,
  searchStrategies,
  topMovers,
  changeBpsFromPrices,
  sortStrategies,
  sortTokens,
  capacityRemainingFraction,
  bpsToSignedPct,
  centsToUsd,
  type DiscoverItem,
  type SymbolChange,
} from "@/lib/discover";

/** How many cards to render per row. */
const ROW_LIMIT = 12;

// -- Shared row scaffolding -------------------------------------------

function SectionHeader({
  icon,
  title,
  description,
  seeAllHref,
  seeAllLabel,
}: {
  icon: React.ReactNode;
  title: string;
  description?: string;
  seeAllHref: string;
  seeAllLabel?: string;
}) {
  return (
    <div className="mb-3 flex items-end justify-between gap-3">
      <div className="flex items-center gap-2">
        <span className="text-primary">{icon}</span>
        <div>
          <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
          {description && <p className="text-xs text-muted-foreground">{description}</p>}
        </div>
      </div>
      <Link
        to={seeAllHref}
        className="flex shrink-0 items-center gap-0.5 text-sm font-medium text-primary hover:underline"
      >
        {seeAllLabel ?? "See all"} <ChevronRight className="h-4 w-4" />
      </Link>
    </div>
  );
}

/** A horizontally-scrollable strip that holds the section's cards. */
function CardRow({ children }: { children: React.ReactNode }) {
  return (
    <div className="-mx-1 flex gap-3 overflow-x-auto px-1 pb-2">{children}</div>
  );
}

function SectionShell({
  header,
  children,
}: {
  header: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      {header}
      {children}
    </section>
  );
}

function RowSkeleton() {
  return (
    <CardRow>
      {Array.from({ length: 5 }).map((_, i) => (
        <Skeleton key={i} className="h-28 w-44 shrink-0 rounded-lg" />
      ))}
    </CardRow>
  );
}

function EmptyRow({ note }: { note: string }) {
  return (
    <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
      {note}
    </div>
  );
}

/** A uniform card for any normalized {@link DiscoverItem}. */
function ItemCard({ item }: { item: DiscoverItem }) {
  const up = item.changeBps != null ? item.changeBps >= 0 : undefined;
  return (
    <Link
      to={item.href}
      data-testid={`discover-item-${item.kind}`}
      className="flex w-44 shrink-0 flex-col justify-between rounded-lg border bg-card p-3 transition-colors hover:border-primary/50 hover:bg-accent/40"
    >
      <div className="min-w-0">
        <div className="truncate font-semibold">{item.title}</div>
        {item.subtitle && (
          <div className="truncate text-xs text-muted-foreground">{item.subtitle}</div>
        )}
      </div>
      {item.metric != null && (
        <div
          className={cn(
            "mt-3 text-sm font-medium tabular-nums",
            up == null
              ? "text-foreground"
              : up
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-rose-600 dark:text-rose-400",
          )}
        >
          {item.metric}
        </div>
      )}
    </Link>
  );
}

// -- Markets (top movers + class tab) ---------------------------------

/**
 * Fetches recent candles for ONE symbol to compute its intraday change, then
 * reports it up to the parent so the parent can rank the movers. Renders
 * nothing itself.
 */
function SymbolChangeProbe({
  sym,
  onChange,
}: {
  sym: MarketSymbol;
  onChange: (id: number, change: number) => void;
}) {
  const candles = useCandles(sym.symbol_id, 60, true, 60);
  const bars = candles.data?.bars ?? [];
  const first = bars.length ? bars[0]!.close : undefined;
  const last = bars.length ? bars[bars.length - 1]!.close : undefined;
  const change = changeBpsFromPrices(first, last);
  // Report up whenever we have a finite value; react-query dedupes the fetch.
  useEffect(() => {
    if (Number.isFinite(change)) onChange(sym.symbol_id, change);
  }, [change, sym.symbol_id, onChange]);
  return null;
}

function MarketsSection({ query }: { query: string }) {
  const symbols = useSymbols();
  const [classTab, setClassTab] = useState<ClassTab>(ALL_CLASS);
  const [changes, setChanges] = useState<Record<number, number>>({});

  const all = symbols.data?.symbols ?? [];
  const filtered = useMemo(() => {
    const bySearch = searchSymbols(all, query);
    return bySearch.filter((s) => symbolInClass(s, classTab));
  }, [all, query, classTab]);

  const onChange = useMemo(
    () => (id: number, change: number) =>
      setChanges((prev) => (prev[id] === change ? prev : { ...prev, [id]: change })),
    [],
  );

  const ranked: SymbolChange[] = useMemo(() => {
    const withChange = filtered.map((s) => ({
      symbol: s,
      changeBps: changes[s.symbol_id] ?? NaN,
    }));
    return topMovers(withChange, ROW_LIMIT);
  }, [filtered, changes]);

  const items: DiscoverItem[] = ranked.map(({ symbol, changeBps }) => ({
    kind: "market",
    id: String(symbol.symbol_id),
    title: symbol.symbol,
    subtitle: symbol.is_perpetual ? "Perpetual" : "Spot",
    metric: Number.isFinite(changeBps) ? bpsToSignedPct(changeBps) : "—",
    changeBps: Number.isFinite(changeBps) ? changeBps : undefined,
    href: `/markets/${symbol.symbol_id}`,
  }));

  return (
    <SectionShell
      header={
        <SectionHeader
          icon={<TrendingUp className="h-5 w-5" />}
          title="Markets"
          description="Top movers across spot, perps, prediction & funding books."
          seeAllHref="/markets"
        />
      }
    >
      {/* Probes: one lightweight candle read per filtered symbol. */}
      {filtered.map((s) => (
        <SymbolChangeProbe key={s.symbol_id} sym={s} onChange={onChange} />
      ))}

      <Tabs value={classTab} onValueChange={(v) => setClassTab(v as ClassTab)} className="mb-3">
        <TabsList>
          {CLASS_TAB_ORDER.map((t) => (
            <TabsTrigger key={t} value={t}>
              {CLASS_LABELS[t]}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {symbols.isLoading ? (
        <RowSkeleton />
      ) : items.length === 0 ? (
        <EmptyRow note={query ? "No markets match your search." : "No markets listed yet."} />
      ) : (
        <CardRow>
          {items.map((it) => (
            <ItemCard key={it.id} item={it} />
          ))}
        </CardRow>
      )}
    </SectionShell>
  );
}

// -- Creator tokens ---------------------------------------------------

function TokensSection({ query }: { query: string }) {
  const market = useTokenMarket();
  const tokens = market.data?.tokens ?? [];
  const items = useMemo(
    () =>
      sortTokens(searchTokens(tokens, query), ROW_LIMIT).map((t) => ({
        kind: "token" as const,
        id: t.token_id,
        title: t.ticker || t.name,
        subtitle: t.name,
        metric: t.clearing_price != null ? centsToUsd(t.clearing_price) ?? t.status : t.status,
        href: `/tokens/${encodeURIComponent(t.token_id)}`,
      })),
    [tokens, query],
  );

  return (
    <SectionShell
      header={
        <SectionHeader
          icon={<Landmark className="h-5 w-5" />}
          title="Creator Tokens"
          description="Tradeable creator revenue-share tokens."
          seeAllHref="/tokens"
        />
      }
    >
      {market.isLoading ? (
        <RowSkeleton />
      ) : items.length === 0 ? (
        <EmptyRow
          note={
            market.isError
              ? "Creator tokens are pending backend — nothing to browse yet."
              : query
                ? "No tokens match your search."
                : "No creator tokens listed yet."
          }
        />
      ) : (
        <CardRow>
          {items.map((it) => (
            <ItemCard key={it.id} item={it} />
          ))}
        </CardRow>
      )}
    </SectionShell>
  );
}

// -- Strategy funds ---------------------------------------------------

function StrategiesSection({ query }: { query: string }) {
  const market = useStrategyMarket();
  const strategies = market.data?.strategies ?? [];
  const items = useMemo(
    () =>
      sortStrategies(searchStrategies(strategies, query), "inception", ROW_LIMIT).map((s) => {
        const capFrac = capacityRemainingFraction(s.aum_cents, s.max_aum_cents);
        const capLabel =
          s.max_aum_cents > 0 ? `${Math.round(capFrac * 100)}% capacity left` : "Uncapped";
        const fees = `${(s.mgmt_fee_bps / 100).toLocaleString()}% mgmt / ${(s.perf_fee_bps / 100).toLocaleString()}% perf`;
        const hasReturn = s.inception_return_bps != null && Number.isFinite(s.inception_return_bps);
        return {
          kind: "strategy" as const,
          id: s.strategy_id,
          title: s.name,
          subtitle: `${fees} · ${capLabel}`,
          metric: hasReturn ? bpsToSignedPct(s.inception_return_bps!) : centsToUsd(s.nav_per_unit) ?? "—",
          changeBps: hasReturn ? s.inception_return_bps! : undefined,
          href: `/strategies/${encodeURIComponent(s.strategy_id)}`,
        };
      }),
    [strategies, query],
  );

  return (
    <SectionShell
      header={
        <SectionHeader
          icon={<Boxes className="h-5 w-5" />}
          title="Strategy Funds"
          description="Pooled NAV funds — top by since-inception return, with fees & capacity."
          seeAllHref="/strategies"
        />
      }
    >
      {market.isLoading ? (
        <RowSkeleton />
      ) : items.length === 0 ? (
        <EmptyRow
          note={
            market.isError
              ? "Strategy funds are pending backend — nothing to browse yet."
              : query
                ? "No strategies match your search."
                : "No published strategy funds yet."
          }
        />
      ) : (
        <CardRow>
          {items.map((it) => (
            <Card key={it.id} className="w-56 shrink-0">
              <CardContent className="p-0">
                <ItemCard item={{ ...it, subtitle: undefined }} />
                <div className="px-3 pb-3 text-xs text-muted-foreground">{it.subtitle}</div>
              </CardContent>
            </Card>
          ))}
        </CardRow>
      )}
    </SectionShell>
  );
}

// -- Staking ----------------------------------------------------------

function StakingSection({ query }: { query: string }) {
  const providers = useQuery({
    queryKey: ["me", "staking", "providers", "discover"],
    queryFn: getStakingProviders,
    retry: false,
  });

  const list: StakingProvider[] = providers.data?.providers ?? [];
  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return list
      .filter((p) =>
        !q ? true : `${p.asset} ${p.kind} ${p.chain} ${p.id}`.toLowerCase().includes(q),
      )
      .slice(0, ROW_LIMIT)
      .map((p) => ({
        kind: "staking" as const,
        id: p.id,
        title: p.asset,
        subtitle: `${p.kind} · ${p.chain}`,
        metric: undefined,
        href: "/custody",
      }));
  }, [list, query]);

  return (
    <SectionShell
      header={
        <SectionHeader
          icon={<Coins className="h-5 w-5" />}
          title="Staking"
          description="Gateway-backed yield vaults & validators."
          seeAllHref="/custody"
        />
      }
    >
      {providers.isLoading ? (
        <RowSkeleton />
      ) : items.length === 0 ? (
        <EmptyRow
          note={
            providers.isError
              ? "Staking is not available on this account / pending backend."
              : query
                ? "No staking providers match your search."
                : "No staking providers offered yet."
          }
        />
      ) : (
        <CardRow>
          {items.map((it) => (
            <ItemCard key={it.id} item={it} />
          ))}
        </CardRow>
      )}
    </SectionShell>
  );
}

// -- Opportunities (IPO auctions + bailouts + peer discovery) ---------

function OpportunitiesSection({ query }: { query: string }) {
  const q = query.trim().toLowerCase();

  const tokenAuctions = useQuery({
    queryKey: ["me", "tokens", "auctions", "discover"],
    queryFn: getOpenTokenAuctions,
    retry: false,
  });
  const bailouts = useQuery({
    queryKey: ["me", "bailouts", "discover"],
    queryFn: getBailouts,
    retry: false,
  });
  const stakeRequests = useQuery({
    queryKey: ["me", "stake_requests", "discover"],
    queryFn: getStakeRequests,
    retry: false,
  });
  const peerAuctions = useQuery({
    queryKey: ["me", "auctions", "discover"],
    queryFn: getOpenAuctions,
    retry: false,
  });

  const loading =
    tokenAuctions.isLoading ||
    bailouts.isLoading ||
    stakeRequests.isLoading ||
    peerAuctions.isLoading;

  const items: DiscoverItem[] = useMemo(() => {
    const out: DiscoverItem[] = [];

    for (const a of tokenAuctions.data?.auctions ?? []) {
      out.push({
        kind: "opportunity",
        id: `tokipo-${a.auction_id}`,
        title: `IPO · ${a.token_id}`,
        subtitle: `Reserve ${centsToUsd(a.reserve_price) ?? "—"} · ${(a.offered_pct_bps / 100).toLocaleString()}% offered`,
        metric: "Bid",
        href: `/tokens/${encodeURIComponent(a.token_id)}`,
      });
    }

    for (const b of (bailouts.data?.auctions ?? []) as BailoutAuction[]) {
      out.push({
        kind: "opportunity",
        id: `bailout-${b.auction_id}`,
        title: `Bailout · ${b.side}`,
        subtitle: `Needs ${centsToUsd(b.capital_needed_cents) ?? "—"} · up to ${(b.max_share_bps / 100).toLocaleString()}% share`,
        metric: "Rescue",
        href: "/bailouts",
      });
    }

    for (const r of stakeRequests.data?.stake_requests ?? []) {
      out.push({
        kind: "opportunity",
        id: `stakereq-${r.request_id ?? Math.random()}`,
        title: `Stake request${r.symbolid != null ? ` · #${r.symbolid}` : ""}`,
        subtitle:
          r.max_stake_pct != null ? `up to ${r.max_stake_pct}% stake` : "peer collateral market",
        metric: "Offer",
        href: "/bailouts",
      });
    }

    for (const a of peerAuctions.data?.auctions ?? []) {
      out.push({
        kind: "opportunity",
        id: `peerauc-${a.auction_id ?? Math.random()}`,
        title: `Position auction${a.symbolid != null ? ` · #${a.symbolid}` : ""}`,
        subtitle: a.qty != null ? `qty ${a.qty}` : "peer position auction",
        metric: "Bid",
        href: "/bailouts",
      });
    }

    return out
      .filter((it) => (!q ? true : `${it.title} ${it.subtitle ?? ""}`.toLowerCase().includes(q)))
      .slice(0, ROW_LIMIT);
  }, [tokenAuctions.data, bailouts.data, stakeRequests.data, peerAuctions.data, q]);

  // Honest note when every source degraded / returned nothing.
  const allErrored =
    tokenAuctions.isError && bailouts.isError && stakeRequests.isError && peerAuctions.isError;

  return (
    <SectionShell
      header={
        <SectionHeader
          icon={<Rocket className="h-5 w-5" />}
          title="Opportunities"
          description="Open IPO auctions, position bailouts & peer staking/auction markets."
          seeAllHref="/bailouts"
          seeAllLabel="Bailouts board"
        />
      }
    >
      {loading ? (
        <RowSkeleton />
      ) : items.length === 0 ? (
        <EmptyRow
          note={
            allErrored
              ? "Opportunity feeds are pending backend — check back once they ship."
              : query
                ? "No open opportunities match your search."
                : "No open opportunities right now."
          }
        />
      ) : (
        <CardRow>
          {items.map((it) => (
            <div key={it.id} className="w-56 shrink-0">
              <ItemCard item={it} />
            </div>
          ))}
        </CardRow>
      )}
    </SectionShell>
  );
}

// -- Page -------------------------------------------------------------

export default function InvestHubPage() {
  const [query, setQuery] = useState("");

  return (
    <div className="mx-auto w-full max-w-6xl space-y-8 p-4 md:p-6">
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Invest</h1>
            <p className="text-sm text-muted-foreground">
              One front door to everything investable — markets, creator tokens, strategy funds,
              staking & open opportunities.
            </p>
          </div>
        </div>
        <div className="relative max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search markets, tokens & strategies…"
            className="pl-9"
            data-testid="discover-search"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="secondary">Markets</Badge>
          <Badge variant="secondary">Creator Tokens</Badge>
          <Badge variant="secondary">Strategy Funds</Badge>
          <Badge variant="secondary">Staking</Badge>
          <Badge variant="secondary">Opportunities</Badge>
        </div>
      </div>

      <MarketsSection query={query} />
      <TokensSection query={query} />
      <StrategiesSection query={query} />
      <StakingSection query={query} />
      <OpportunitiesSection query={query} />
    </div>
  );
}
