import { useState, useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronLeft,
  Eye,
  DollarSign,
  TrendingUp,
  ThumbsUp,
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
  Legend,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { getAnalyticsContentDetail } from "@/api/endpoints/analytics";

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

function computeDateRange(preset: string): { fromDate: string; toDate: string } {
  const toDate = todayStr();
  switch (preset) {
    case "7d":
      return { fromDate: daysAgo(7), toDate };
    case "90d":
      return { fromDate: daysAgo(90), toDate };
    case "1y":
      return { fromDate: daysAgo(365), toDate };
    case "30d":
    default:
      return { fromDate: daysAgo(30), toDate };
  }
}

const PIE_COLORS = ["#3b82f6", "#10b981", "#f59e0b"];

// ── Page Component ──────────────────────────────────────────────

export default function ContentDetailPage() {
  const { contentId } = useParams<{ contentId: string }>();
  const navigate = useNavigate();
  const [dateRange, setDateRange] = useState("30d");

  const { fromDate, toDate } = useMemo(() => computeDateRange(dateRange), [dateRange]);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["analytics", "content", contentId, fromDate, toDate],
    queryFn: () => getAnalyticsContentDetail(contentId!, { from_date: fromDate, to_date: toDate }),
    enabled: !!contentId,
  });

  if (isLoading) {
    return (
      <div className="space-y-6 p-4 md:p-6">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate("/analytics")}>
            <ChevronLeft className="h-5 w-5" />
          </Button>
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
        </div>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 animate-pulse rounded-lg bg-muted" />
          ))}
        </div>
        <div className="h-[300px] animate-pulse rounded-lg bg-muted" />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="space-y-6 p-4 md:p-6">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate("/analytics")}>
            <ChevronLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-xl font-bold">Content Not Found</h1>
        </div>
        <p className="text-muted-foreground">
          The content item could not be loaded. It may not exist or you may not have access.
        </p>
      </div>
    );
  }

  const revData = [
    { name: "Tips", value: data.revenue_breakdown.tips },
    { name: "Unlocks", value: data.revenue_breakdown.unlocks },
    { name: "VOD", value: data.revenue_breakdown.vod },
  ].filter((d) => d.value > 0);

  return (
    <div className="space-y-6 p-4 md:p-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate("/analytics")}
          aria-label="Back to analytics"
        >
          <ChevronLeft className="h-5 w-5" />
        </Button>
        {data.thumbnail_url && (
          <img
            src={data.thumbnail_url}
            alt=""
            className="h-[60px] w-[80px] rounded object-cover"
          />
        )}
        <div>
          <h1 className="text-xl font-bold">{data.title}</h1>
          <div className="flex items-center gap-2">
            <Badge variant="outline">
              {data.content_type === "vod" ? "Video" : "Post"}
            </Badge>
            {data.published_at ? (
              <span className="text-sm text-muted-foreground">
                Published {new Date(data.published_at * 1000).toLocaleDateString()}
              </span>
            ) : null}
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <SummaryCard
          icon={<Eye className="h-5 w-5 text-blue-500" />}
          label="Total Views"
          value={formatNumber(data.total_views)}
        />
        <SummaryCard
          icon={<DollarSign className="h-5 w-5 text-green-500" />}
          label="Revenue"
          value={formatCents(data.total_revenue_cents)}
        />
        <SummaryCard
          icon={<TrendingUp className="h-5 w-5 text-purple-500" />}
          label="Engagement"
          value={`${(data.engagement_rate * 100).toFixed(1)}%`}
        />
        <SummaryCard
          icon={<ThumbsUp className="h-5 w-5 text-orange-500" />}
          label="Interactions"
          value={`${data.like_count} likes, ${data.comment_count} comments`}
        />
      </div>

      {/* View Trends Chart */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">View Trends</CardTitle>
          <Select value={dateRange} onValueChange={setDateRange}>
            <SelectTrigger className="w-24">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7d">7d</SelectItem>
              <SelectItem value="30d">30d</SelectItem>
              <SelectItem value="90d">90d</SelectItem>
              <SelectItem value="1y">1y</SelectItem>
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          {data.view_time_series.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={data.view_time_series}>
                <defs>
                  <linearGradient id="contentViewGrad" x1="0" y1="0" x2="0" y2="1">
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
                  fill="url(#contentViewGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <p className="py-12 text-center text-sm text-muted-foreground">
              No view data for this period
            </p>
          )}
        </CardContent>
      </Card>

      {/* Revenue Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Revenue Breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          {revData.length > 0 ? (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="50%" height={250}>
                <PieChart>
                  <Pie
                    data={revData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {revData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(v: number) => formatCents(v)} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex-1 space-y-3 text-sm">
                <div className="font-semibold">
                  Total: {formatCents(data.total_revenue_cents)}
                </div>
                {revData.map((item, i) => (
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
          ) : (
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">No revenue for this content</p>
              <div className="flex items-center gap-2">
                <span>Tips</span>
                <span className="ml-auto font-medium">$0.00</span>
              </div>
              <div className="flex items-center gap-2">
                <span>Unlocks</span>
                <span className="ml-auto font-medium">$0.00</span>
              </div>
              <div className="flex items-center gap-2">
                <span>VOD</span>
                <span className="ml-auto font-medium">$0.00</span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Metadata Footer */}
      <Card>
        <CardContent className="py-4">
          <div className="flex flex-wrap gap-6 text-sm text-muted-foreground">
            <div>
              <span className="font-medium text-foreground">Content ID:</span>{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                {data.content_id}
              </code>
            </div>
            <div>
              <span className="font-medium text-foreground">Type:</span>{" "}
              {data.content_type === "vod" ? "Video" : "Post"}
            </div>
            {data.published_at ? (
              <div>
                <span className="font-medium text-foreground">Published:</span>{" "}
                {new Date(data.published_at * 1000).toISOString()}
              </div>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Sub-components ──────────────────────────────────────────────

function SummaryCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted">
          {icon}
        </div>
        <div>
          <p className="text-sm text-muted-foreground">{label}</p>
          <p className="text-xl font-bold">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}
