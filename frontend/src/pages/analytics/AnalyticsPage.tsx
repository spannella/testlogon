import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams, useNavigate } from "react-router-dom";
import {
  BarChart3,
  DollarSign,
  Eye,
  UserPlus,
  Users,
  RefreshCw,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Bar,
  Legend,
  ComposedChart,
  Line,
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
  getAnalyticsOverview,
  getAnalyticsRevenue,
  getAnalyticsViews,
  getAnalyticsSubscribers,
  getAnalyticsTopContent,
  getAnalyticsAudience,
  refreshAnalytics,
} from "@/api/endpoints/analytics";
import { useAuthStore } from "@/stores/authStore";
import TopSupportersCard from "./TopSupportersCard";
import EngagementRateSection from "./EngagementRateSection";

// ── Helpers ──────────────────────────────────────────────────────

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 10);
}

function todayStr(): string {
  return new Date().toISOString().slice(0, 10);
}

const RANGE_PRESETS: { label: string; days: number }[] = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "1y", days: 365 },
];

const PIE_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

const STALE_TIME = 5 * 60 * 1000; // 5 minutes

// ── Page Component ──────────────────────────────────────────────

export default function AnalyticsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const userId = useAuthStore((s) => s.userId);

  // URL-driven state
  const fromDate = searchParams.get("from_date") || daysAgo(30);
  const toDate = searchParams.get("to_date") || todayStr();
  const granularity = searchParams.get("granularity") || "day";

  const [activeRange, setActiveRange] = useState<number>(() => {
    const diff = Math.round(
      (new Date(toDate).getTime() - new Date(fromDate).getTime()) / (1000 * 60 * 60 * 24)
    );
    return diff;
  });

  // Client-side sort for the Top Content "Engagement" column (ANALYTICS-002).
  // Engagement rate is computed server-side after BatchGetItem, so it is not a
  // valid backend sort_by key — we sort the returned rows in the browser.
  const [engagementSort, setEngagementSort] = useState<"none" | "desc" | "asc">("none");

  const params = useMemo(
    () => ({ from_date: fromDate, to_date: toDate, granularity }),
    [fromDate, toDate, granularity]
  );

  function setRange(days: number) {
    setActiveRange(days);
    const newParams = new URLSearchParams(searchParams);
    newParams.set("from_date", daysAgo(days));
    newParams.set("to_date", todayStr());
    setSearchParams(newParams, { replace: true });
  }

  function setGranularity(g: string) {
    const newParams = new URLSearchParams(searchParams);
    newParams.set("granularity", g);
    setSearchParams(newParams, { replace: true });
  }

  // ── Queries ──────────────────────────────────────────────────

  const overviewQ = useQuery({
    queryKey: ["analytics", "overview", { from_date: fromDate, to_date: toDate }],
    queryFn: () => getAnalyticsOverview({ from_date: fromDate, to_date: toDate }),
    staleTime: STALE_TIME,
  });

  const revenueQ = useQuery({
    queryKey: ["analytics", "revenue", params],
    queryFn: () => getAnalyticsRevenue(params),
    staleTime: STALE_TIME,
  });

  const viewsQ = useQuery({
    queryKey: ["analytics", "views", params],
    queryFn: () => getAnalyticsViews(params),
    staleTime: STALE_TIME,
  });

  const subscribersQ = useQuery({
    queryKey: ["analytics", "subscribers", params],
    queryFn: () => getAnalyticsSubscribers(params),
    staleTime: STALE_TIME,
  });

  const topContentQ = useQuery({
    queryKey: ["analytics", "top-content", { from_date: fromDate, to_date: toDate, sort_by: "views" }],
    queryFn: () => getAnalyticsTopContent({ from_date: fromDate, to_date: toDate, sort_by: "views" }),
    staleTime: STALE_TIME,
  });

  const audienceQ = useQuery({
    queryKey: ["analytics", "audience", { from_date: fromDate, to_date: toDate }],
    queryFn: () => getAnalyticsAudience({ from_date: fromDate, to_date: toDate }),
    staleTime: STALE_TIME,
  });

  const refreshMut = useMutation({
    mutationFn: refreshAnalytics,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
    },
  });

  const overview = overviewQ.data;
  const revenue = revenueQ.data;
  const views = viewsQ.data;
  const subscribers = subscribersQ.data;
  const topContent = topContentQ.data;
  const audience = audienceQ.data;

  // Apply client-side engagement sort when active.
  const topContentItems = useMemo(() => {
    const items = topContent?.items ?? [];
    if (engagementSort === "none") return items;
    const sorted = [...items].sort(
      (a, b) => (a.engagement_rate ?? 0) - (b.engagement_rate ?? 0)
    );
    return engagementSort === "desc" ? sorted.reverse() : sorted;
  }, [topContent, engagementSort]);

  function toggleEngagementSort() {
    setEngagementSort((prev) =>
      prev === "none" ? "desc" : prev === "desc" ? "asc" : "none"
    );
  }

  // ── Render ───────────────────────────────────────────────────

  return (
    <div className="space-y-6 p-4 md:p-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Analytics</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {/* Date range presets */}
          <div className="flex gap-1 rounded-full bg-muted p-1">
            {RANGE_PRESETS.map((p) => (
              <button
                key={p.days}
                onClick={() => setRange(p.days)}
                className={`rounded-full px-3 py-1 text-sm font-medium transition-colors ${
                  activeRange === p.days
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
          {/* Granularity selector */}
          <Select value={granularity} onValueChange={setGranularity}>
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="day">Daily</SelectItem>
              <SelectItem value="week">Weekly</SelectItem>
              <SelectItem value="month">Monthly</SelectItem>
            </SelectContent>
          </Select>
          {/* Refresh button */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => refreshMut.mutate()}
            disabled={refreshMut.isPending}
          >
            <RefreshCw className={`mr-1 h-4 w-4 ${refreshMut.isPending ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          title="Views"
          value={formatNumber(overview?.period_views ?? 0)}
          icon={<Eye className="h-5 w-5 text-blue-500" />}
          loading={overviewQ.isLoading}
        />
        <SummaryCard
          title="Revenue"
          value={formatCents(overview?.period_revenue_cents ?? 0)}
          icon={<DollarSign className="h-5 w-5 text-green-500" />}
          loading={overviewQ.isLoading}
        />
        <SummaryCard
          title="New Subscribers"
          value={formatNumber(overview?.period_new_subscribers ?? 0)}
          icon={<UserPlus className="h-5 w-5 text-purple-500" />}
          loading={overviewQ.isLoading}
        />
        <SummaryCard
          title="Total Subscribers"
          value={formatNumber(overview?.total_subscribers ?? 0)}
          icon={<Users className="h-5 w-5 text-orange-500" />}
          loading={overviewQ.isLoading}
        />
      </div>

      {/* Engagement Rate (FIN-012) */}
      <EngagementRateSection />

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* View Trends */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">View Trends</CardTitle>
          </CardHeader>
          <CardContent>
            {viewsQ.isLoading ? (
              <ChartSkeleton />
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={views?.time_series ?? []}>
                  <defs>
                    <linearGradient id="viewGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="views"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#viewGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Revenue Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Revenue Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            {revenueQ.isLoading ? (
              <ChartSkeleton />
            ) : (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width="50%" height={280}>
                  <PieChart>
                    <Pie
                      data={revenueBreakdownData(revenue?.breakdown)}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={90}
                      paddingAngle={2}
                    >
                      {revenueBreakdownData(revenue?.breakdown).map((_, i) => (
                        <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(v) => formatCents(Number(v))} />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-2 text-sm">
                  <div className="font-semibold">
                    Total: {formatCents(revenue?.total_cents ?? 0)}
                  </div>
                  {revenueBreakdownData(revenue?.breakdown).map((item, i) => (
                    <div key={item.name} className="flex items-center gap-2">
                      <span
                        className="inline-block h-3 w-3 rounded-full"
                        style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }}
                      />
                      <span>{item.name}</span>
                      <span className="ml-auto font-medium">{formatCents(item.value)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Subscriber Growth */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Subscriber Growth</CardTitle>
        </CardHeader>
        <CardContent>
          {subscribersQ.isLoading ? (
            <ChartSkeleton />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <ComposedChart data={subscribers?.time_series ?? []}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis yAxisId="left" tick={{ fontSize: 12 }} />
                <YAxis yAxisId="right" orientation="right" tick={{ fontSize: 12 }} />
                <Tooltip />
                <Legend />
                <Bar yAxisId="left" dataKey="new" fill="#22c55e" name="New" />
                <Bar yAxisId="left" dataKey="churned" fill="#ef4444" name="Churned" />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="total"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={false}
                  name="Total"
                />
              </ComposedChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* Top Content Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Top Content</CardTitle>
        </CardHeader>
        <CardContent>
          {topContentQ.isLoading ? (
            <div className="animate-pulse space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-8 rounded bg-muted" />
              ))}
            </div>
          ) : (topContent?.items?.length ?? 0) === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No content data yet</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-4">#</th>
                    <th className="pb-2 pr-4">Title</th>
                    <th className="pb-2 pr-4">Type</th>
                    <th className="pb-2 pr-4 text-right">Views</th>
                    <th className="pb-2 pr-4 text-right">Revenue</th>
                    <th className="pb-2 text-right">
                      <button
                        type="button"
                        onClick={toggleEngagementSort}
                        className="inline-flex items-center gap-1 hover:text-foreground"
                        aria-label="Sort by engagement"
                      >
                        Engagement
                        {engagementSort === "desc" && <span aria-hidden>↓</span>}
                        {engagementSort === "asc" && <span aria-hidden>↑</span>}
                      </button>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topContentItems.map((item, i) => (
                    <tr
                      key={item.content_id}
                      className="border-b last:border-0 cursor-pointer hover:bg-muted/50 transition-colors"
                      onClick={() => navigate(`/analytics/content/${item.content_id}`)}
                    >
                      <td className="py-2 pr-4 text-muted-foreground">{i + 1}</td>
                      <td className="py-2 pr-4 font-medium">{item.title}</td>
                      <td className="py-2 pr-4">
                        <span className="inline-block rounded-full bg-muted px-2 py-0.5 text-xs">
                          {item.content_type}
                        </span>
                      </td>
                      <td className="py-2 pr-4 text-right">{formatNumber(item.views)}</td>
                      <td className="py-2 pr-4 text-right">{formatCents(item.revenue_cents)}</td>
                      <td className="py-2 text-right">{(item.engagement_rate * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Top Supporters (SOCIAL-005) */}
      {userId && <TopSupportersCard creatorId={userId} />}

      {/* Audience Demographics */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Audience by Country</CardTitle>
          </CardHeader>
          <CardContent>
            {audienceQ.isLoading ? (
              <ChartSkeleton />
            ) : (audience?.countries?.length ?? 0) === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No audience data</p>
            ) : (
              <div>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={audience!.countries.slice(0, 6)}
                      dataKey="viewers"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={80}
                      paddingAngle={2}
                    >
                      {audience!.countries.slice(0, 6).map((_, i) => (
                        <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-4 space-y-2 text-sm">
                  {audience!.countries.slice(0, 10).map((c) => (
                    <div key={c.code} className="flex items-center gap-2">
                      <span className="w-8 font-mono text-xs text-muted-foreground">{c.code}</span>
                      <span className="flex-1">{c.name}</span>
                      <span className="text-muted-foreground">{c.percentage}%</span>
                      <span className="font-medium">{formatNumber(c.viewers)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Audience by Device</CardTitle>
          </CardHeader>
          <CardContent>
            {audienceQ.isLoading ? (
              <ChartSkeleton />
            ) : (audience?.devices?.length ?? 0) === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No device data</p>
            ) : (
              <div>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={audience!.devices}
                      dataKey="viewers"
                      nameKey="type"
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={80}
                      paddingAngle={2}
                    >
                      {audience!.devices.map((_, i) => (
                        <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-4 space-y-2 text-sm">
                  {audience!.devices.map((d) => (
                    <div key={d.type} className="flex items-center gap-2">
                      <span className="flex-1 capitalize">{d.type}</span>
                      <span className="text-muted-foreground">{d.percentage}%</span>
                      <span className="font-medium">{formatNumber(d.viewers)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Sub-components ──────────────────────────────────────────────

function SummaryCard({
  title,
  value,
  icon,
  loading,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  loading?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted">
          {icon}
        </div>
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          {loading ? (
            <div className="mt-1 h-6 w-20 animate-pulse rounded bg-muted" />
          ) : (
            <p className="text-xl font-bold">{value}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function ChartSkeleton() {
  return <div className="h-[280px] animate-pulse rounded bg-muted" />;
}

function revenueBreakdownData(breakdown?: {
  tips: number;
  subscriptions: number;
  unlocks: number;
  vod: number;
  ads: number;
  calls: number;
}) {
  if (!breakdown) return [];
  return [
    { name: "Tips", value: breakdown.tips },
    { name: "Subscriptions", value: breakdown.subscriptions },
    { name: "Unlocks", value: breakdown.unlocks },
    { name: "VOD", value: breakdown.vod },
    { name: "Ads", value: breakdown.ads },
    { name: "Calls", value: breakdown.calls },
  ].filter((d) => d.value > 0);
}
