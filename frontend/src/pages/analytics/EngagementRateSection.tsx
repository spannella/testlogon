import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Sparkles,
  TrendingUp,
  TrendingDown,
  Minus,
  Heart,
  MessageCircle,
  Share2,
  DollarSign,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import {
  getEngagementRate,
  getEngagementHistory,
  setEngagementPublic,
} from "@/api/endpoints/engagementRate";

const PERIODS = [7, 14, 30, 60, 90];
const STALE_TIME = 5 * 60 * 1000;

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 10);
}

function todayStr(): string {
  return new Date().toISOString().slice(0, 10);
}

function TrendIndicator({ trend, delta }: { trend: string; delta: number }) {
  if (trend === "up") {
    return (
      <span className="inline-flex items-center gap-1 text-sm text-green-500" data-testid="engagement-trend">
        <TrendingUp className="h-4 w-4" /> {Math.abs(delta).toFixed(2)}%
      </span>
    );
  }
  if (trend === "down") {
    return (
      <span className="inline-flex items-center gap-1 text-sm text-red-500" data-testid="engagement-trend">
        <TrendingDown className="h-4 w-4" /> {Math.abs(delta).toFixed(2)}%
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-sm text-muted-foreground" data-testid="engagement-trend">
      <Minus className="h-4 w-4" /> stable
    </span>
  );
}

function BreakdownStat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
}) {
  return (
    <div className="flex items-center gap-2 rounded-lg border p-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted">
        {icon}
      </div>
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="font-semibold">{value.toLocaleString()}</p>
      </div>
    </div>
  );
}

export default function EngagementRateSection() {
  const queryClient = useQueryClient();
  const [periodDays, setPeriodDays] = useState<number>(30);

  const engagementQ = useQuery({
    queryKey: ["engagement", "rate", periodDays],
    queryFn: () => getEngagementRate(periodDays),
    staleTime: STALE_TIME,
  });

  const historyQ = useQuery({
    queryKey: ["engagement", "history"],
    queryFn: () =>
      getEngagementHistory({ from_date: daysAgo(30), to_date: todayStr() }),
    staleTime: STALE_TIME,
  });

  const data = engagementQ.data;

  const publicMut = useMutation({
    mutationFn: (visible: boolean) => setEngagementPublic(visible),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["engagement"] });
    },
  });

  const [publicOn, setPublicOn] = useState(false);

  return (
    <div className="space-y-6" data-testid="engagement-section">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Sparkles className="h-5 w-5 text-amber-500" />
            Engagement Rate
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <div className="flex items-baseline gap-3">
                <span
                  className="text-4xl font-bold"
                  data-testid="engagement-rate-value"
                >
                  {(data?.engagement_rate ?? 0).toFixed(2)}%
                </span>
                {data && (
                  <TrendIndicator trend={data.trend} delta={data.trend_delta} />
                )}
              </div>
              <p className="mt-1 text-sm text-muted-foreground">
                {data?.total_interactions ?? 0} interactions across{" "}
                {data?.posts_in_period ?? 0} posts &middot;{" "}
                {data?.follower_count ?? 0} followers
              </p>
            </div>
            {/* Period selector */}
            <div className="flex gap-1 rounded-full bg-muted p-1">
              {PERIODS.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setPeriodDays(p)}
                  className={`rounded-full px-3 py-1 text-sm font-medium transition-colors ${
                    periodDays === p
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {p}d
                </button>
              ))}
            </div>
          </div>

          {/* Breakdown */}
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <BreakdownStat
              icon={<Heart className="h-4 w-4 text-rose-500" />}
              label="Likes"
              value={data?.likes ?? 0}
            />
            <BreakdownStat
              icon={<MessageCircle className="h-4 w-4 text-blue-500" />}
              label="Comments"
              value={data?.comments ?? 0}
            />
            <BreakdownStat
              icon={<Share2 className="h-4 w-4 text-purple-500" />}
              label="Shares"
              value={data?.shares ?? 0}
            />
            <BreakdownStat
              icon={<DollarSign className="h-4 w-4 text-green-500" />}
              label="Tips"
              value={data?.tips ?? 0}
            />
          </div>

          {/* Public profile toggle */}
          <div className="mt-4 flex items-center justify-between rounded-lg border p-3">
            <div>
              <p className="text-sm font-medium">
                Show engagement rate on public profile
              </p>
              <p className="text-xs text-muted-foreground">
                Visitors can see your 30-day engagement rate.
              </p>
            </div>
            <Switch
              checked={publicOn}
              onCheckedChange={(v) => {
                setPublicOn(v);
                publicMut.mutate(v);
              }}
              aria-label="Toggle public engagement"
              data-testid="engagement-public-toggle"
            />
          </div>
        </CardContent>
      </Card>

      {/* Trend chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Engagement Trend</CardTitle>
        </CardHeader>
        <CardContent>
          {historyQ.isLoading ? (
            <div className="h-[240px] animate-pulse rounded bg-muted" />
          ) : (historyQ.data?.items?.length ?? 0) === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No engagement data yet
            </p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={historyQ.data?.items ?? []}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} unit="%" />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="engagement_rate"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  dot={false}
                  name="Engagement %"
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
