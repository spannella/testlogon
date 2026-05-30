import { useState, useMemo } from "react";
import { useQuery, useInfiniteQuery } from "@tanstack/react-query";
import {
  DollarSign,
  TrendingUp,
  Calendar,
  Clock,
  Loader2,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

import {
  getEarningsSummary,
  getEarningsTransactions,
  getEarningsQuickStats,
} from "@/api/endpoints/earnings";
import type {
  EarningsQuickStats,
  EarningsSummary,
  EarningsTransaction,
  TimeSeriesPoint,
} from "@/api/types";

// ─── Helpers ────────────────────────────────────────────────────

function formatCents(cents: number): string {
  return `$${(cents / 100).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

function formatDate(ts: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return isoDate(d);
}

const CATEGORY_COLORS: Record<string, string> = {
  tips: "#10B981",
  subscriptions: "#3B82F6",
  unlocks: "#F59E0B",
  vod_purchases: "#8B5CF6",
  other: "#6B7280",
};

const CATEGORY_LABELS: Record<string, string> = {
  tips: "Tips",
  subscriptions: "Subscriptions",
  unlocks: "Unlocks",
  vod_purchases: "VOD Purchases",
  other: "Other",
};

const PRESETS: { label: string; days: number | null }[] = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "1y", days: 365 },
  { label: "All", days: null },
];

// ─── QuickStatCard ──────────────────────────────────────────────

function QuickStatCard({
  title,
  amountCents,
  icon: Icon,
  isLoading,
}: {
  title: string;
  amountCents: number;
  icon: typeof DollarSign;
  isLoading: boolean;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        ) : (
          <div
            className="text-2xl font-bold"
            role="status"
            aria-label={`${title}: ${formatCents(amountCents)}`}
          >
            {formatCents(amountCents)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── RevenueChart ───────────────────────────────────────────────

function RevenueChart({
  timeSeries,
  isLoading,
}: {
  timeSeries: TimeSeriesPoint[];
  isLoading: boolean;
}) {
  const chartData = useMemo(
    () =>
      timeSeries.map((pt) => ({
        date: pt.date,
        Tips: (pt.tips ?? 0) / 100,
        Subscriptions: (pt.subscriptions ?? 0) / 100,
        Unlocks: (pt.unlocks ?? 0) / 100,
        "VOD Purchases": (pt.vod_purchases ?? 0) / 100,
        Other: (pt.other ?? 0) / 100,
      })),
    [timeSeries],
  );

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (chartData.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        No revenue data for this period
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300} aria-label="Revenue chart">
      <AreaChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="date" fontSize={12} />
        <YAxis
          fontSize={12}
          tickFormatter={(v: number) => `$${v}`}
        />
        <Tooltip
          formatter={(value: number) =>
            `$${value.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
          }
        />
        <Legend />
        <Area
          type="monotone"
          dataKey="Tips"
          stackId="1"
          stroke={CATEGORY_COLORS.tips}
          fill={CATEGORY_COLORS.tips}
          fillOpacity={0.6}
        />
        <Area
          type="monotone"
          dataKey="Subscriptions"
          stackId="1"
          stroke={CATEGORY_COLORS.subscriptions}
          fill={CATEGORY_COLORS.subscriptions}
          fillOpacity={0.6}
        />
        <Area
          type="monotone"
          dataKey="Unlocks"
          stackId="1"
          stroke={CATEGORY_COLORS.unlocks}
          fill={CATEGORY_COLORS.unlocks}
          fillOpacity={0.6}
        />
        <Area
          type="monotone"
          dataKey="VOD Purchases"
          stackId="1"
          stroke={CATEGORY_COLORS.vod_purchases}
          fill={CATEGORY_COLORS.vod_purchases}
          fillOpacity={0.6}
        />
        <Area
          type="monotone"
          dataKey="Other"
          stackId="1"
          stroke={CATEGORY_COLORS.other}
          fill={CATEGORY_COLORS.other}
          fillOpacity={0.6}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ─── BreakdownList ──────────────────────────────────────────────

function BreakdownList({
  breakdown,
  totalCents,
  isLoading,
}: {
  breakdown: Record<string, number> | undefined;
  totalCents: number;
  isLoading: boolean;
}) {
  if (isLoading || !breakdown) {
    return (
      <div className="flex h-32 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const categories = Object.entries(breakdown)
    .filter(([, v]) => v > 0)
    .sort(([, a], [, b]) => b - a);

  if (categories.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-muted-foreground text-sm">
        No earnings yet
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {categories.map(([cat, cents]) => {
        const pct = totalCents > 0 ? Math.round((cents / totalCents) * 100) : 0;
        return (
          <div key={cat} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <span
                  className="inline-block h-3 w-3 rounded-full"
                  style={{ backgroundColor: CATEGORY_COLORS[cat] ?? "#6B7280" }}
                />
                {CATEGORY_LABELS[cat] ?? cat}
              </span>
              <span className="font-medium">{formatCents(cents)} ({pct}%)</span>
            </div>
            <div className="h-2 w-full rounded-full bg-muted">
              <div
                className="h-2 rounded-full"
                style={{
                  width: `${pct}%`,
                  backgroundColor: CATEGORY_COLORS[cat] ?? "#6B7280",
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── TransactionTable ───────────────────────────────────────────

function CategoryBadge({ category }: { category: string }) {
  const colorMap: Record<string, string> = {
    tips: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200",
    subscriptions: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
    unlocks: "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200",
    vod_purchases: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
    other: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
  };
  return (
    <Badge variant="outline" className={colorMap[category] ?? colorMap.other}>
      {CATEGORY_LABELS[category] ?? category}
    </Badge>
  );
}

function TransactionTable({
  transactions,
  hasMore,
  onLoadMore,
  isLoadingMore,
  isLoading,
}: {
  transactions: EarningsTransaction[];
  hasMore: boolean;
  onLoadMore: () => void;
  isLoadingMore: boolean;
  isLoading: boolean;
}) {
  if (isLoading) {
    return (
      <div className="flex h-32 items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (transactions.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-muted-foreground text-sm">
        No transactions found
      </div>
    );
  }

  return (
    <div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Date</TableHead>
            <TableHead>Category</TableHead>
            <TableHead className="text-right">Amount</TableHead>
            <TableHead>Description</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {transactions.map((txn) => (
            <TableRow key={txn.entry_id}>
              <TableCell className="whitespace-nowrap">
                {formatDate(txn.ts)}
              </TableCell>
              <TableCell>
                <CategoryBadge category={txn.category} />
              </TableCell>
              <TableCell className="text-right font-medium">
                {formatCents(txn.amount_cents)}
              </TableCell>
              <TableCell className="max-w-xs truncate text-muted-foreground">
                {txn.reason}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {hasMore && (
        <div className="mt-4 flex justify-center">
          <Button
            variant="outline"
            onClick={onLoadMore}
            disabled={isLoadingMore}
            aria-label="Load more transactions"
          >
            {isLoadingMore ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : null}
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── EarningsPage ───────────────────────────────────────────────

export default function EarningsPage() {
  const [activePreset, setActivePreset] = useState<number | null>(30);
  const [granularity, setGranularity] = useState<"day" | "week" | "month">("day");

  const fromDate = activePreset != null ? daysAgo(activePreset) : undefined;
  const toDate = activePreset != null ? isoDate(new Date()) : undefined;

  // Quick stats
  const quickStatsQ = useQuery({
    queryKey: ["earnings", "quick-stats"],
    queryFn: getEarningsQuickStats,
  });

  // Summary with time series
  const summaryQ = useQuery({
    queryKey: ["earnings", "summary", fromDate, toDate, granularity],
    queryFn: () =>
      getEarningsSummary({
        from_date: fromDate,
        to_date: toDate,
        granularity,
      }),
  });

  // Paginated transactions
  const txnsQ = useInfiniteQuery({
    queryKey: ["earnings", "transactions", fromDate, toDate],
    queryFn: ({ pageParam }: { pageParam: string | undefined }) =>
      getEarningsTransactions({
        from_date: fromDate,
        to_date: toDate,
        limit: "50",
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });

  const allTransactions = useMemo(
    () => txnsQ.data?.pages.flatMap((p) => p.items) ?? [],
    [txnsQ.data],
  );

  const qs = quickStatsQ.data as EarningsQuickStats | undefined;
  const summary = summaryQ.data as EarningsSummary | undefined;

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Earnings</h1>
        <p className="text-muted-foreground">
          Track your revenue across tips, subscriptions, unlocks, and more.
        </p>
      </div>

      {/* Quick Stat Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <QuickStatCard
          title="Today"
          amountCents={qs?.today_cents ?? 0}
          icon={DollarSign}
          isLoading={quickStatsQ.isLoading}
        />
        <QuickStatCard
          title="This Week"
          amountCents={qs?.this_week_cents ?? 0}
          icon={TrendingUp}
          isLoading={quickStatsQ.isLoading}
        />
        <QuickStatCard
          title="This Month"
          amountCents={qs?.this_month_cents ?? 0}
          icon={Calendar}
          isLoading={quickStatsQ.isLoading}
        />
        <QuickStatCard
          title="All Time"
          amountCents={qs?.all_time_cents ?? 0}
          icon={Clock}
          isLoading={quickStatsQ.isLoading}
        />
      </div>

      {/* Time Range + Granularity Controls */}
      <div className="flex flex-wrap items-center gap-2">
        {PRESETS.map((p) => (
          <Button
            key={p.label}
            size="sm"
            variant={activePreset === p.days ? "default" : "outline"}
            onClick={() => setActivePreset(p.days)}
          >
            {p.label}
          </Button>
        ))}
        <Select
          value={granularity}
          onValueChange={(v) => setGranularity(v as "day" | "week" | "month")}
        >
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="day">Daily</SelectItem>
            <SelectItem value="week">Weekly</SelectItem>
            <SelectItem value="month">Monthly</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Revenue Chart + Breakdown */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Revenue Over Time</CardTitle>
          </CardHeader>
          <CardContent>
            <RevenueChart
              timeSeries={summary?.time_series ?? []}
              isLoading={summaryQ.isLoading}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Revenue Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            <BreakdownList
              breakdown={summary?.breakdown as unknown as Record<string, number>}
              totalCents={summary?.total_cents ?? 0}
              isLoading={summaryQ.isLoading}
            />
          </CardContent>
        </Card>
      </div>

      {/* Transaction Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Transactions</CardTitle>
        </CardHeader>
        <CardContent>
          <TransactionTable
            transactions={allTransactions}
            hasMore={txnsQ.hasNextPage ?? false}
            onLoadMore={() => txnsQ.fetchNextPage()}
            isLoadingMore={txnsQ.isFetchingNextPage}
            isLoading={txnsQ.isLoading}
          />
        </CardContent>
      </Card>
    </div>
  );
}
