/**
 * Hotel KPI Dashboard — HTL-035
 *
 * Route: hotels/reports/:hotelId
 *
 * Shows occupancy %, ADR (Average Daily Rate), RevPAR (Revenue per Available
 * Room), room revenue, arrivals/departures for a configurable date range.
 * Chart rendered with recharts (BarChart for the multi-metric overview).
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF). Returns 404 when off.
 * Money is stored in integer cents; displayed as formatted currency.
 */

import { useState, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartTooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  LineChart as LineChartIcon,
  Hotel,
  TrendingUp,
  BedDouble,
  DollarSign,
  Users,
  CalendarRange,
  AlertTriangle,
  Loader2,
  RefreshCw,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getHotelKpis,
  type HotelKpisOut,
} from "@/api/endpoints/hotelReports";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

// ─── Date / currency helpers ──────────────────────────────────────────────────

function centsToDisplay(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function toLocalDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function dateToStartOfDayTs(dateStr: string): number {
  return Math.floor(new Date(`${dateStr}T00:00:00Z`).getTime() / 1000);
}

function dateToEndOfDayTs(dateStr: string): number {
  return Math.floor(new Date(`${dateStr}T23:59:59Z`).getTime() / 1000) + 1;
}

// ─── Preset date ranges ───────────────────────────────────────────────────────

type Preset = "7d" | "30d" | "90d" | "365d" | "custom";

function presetLabel(p: Preset): string {
  switch (p) {
    case "7d": return "Last 7 days";
    case "30d": return "Last 30 days";
    case "90d": return "Last 90 days";
    case "365d": return "Last 365 days";
    case "custom": return "Custom";
  }
}

function presetToRange(preset: Preset): { from: string; to: string } {
  const now = new Date();
  const todayStr = toLocalDate(now);

  const daysAgo = (n: number) => {
    const d = new Date(now);
    d.setDate(d.getDate() - n);
    return toLocalDate(d);
  };

  switch (preset) {
    case "7d":   return { from: daysAgo(7),   to: todayStr };
    case "30d":  return { from: daysAgo(30),  to: todayStr };
    case "90d":  return { from: daysAgo(90),  to: todayStr };
    case "365d": return { from: daysAgo(365), to: todayStr };
    case "custom":
      return { from: daysAgo(30), to: todayStr };
  }
}

// ─── KPI stat card ────────────────────────────────────────────────────────────

interface KpiCardProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  highlight?: boolean;
}

function KpiCard({ icon, label, value, sub, highlight }: KpiCardProps) {
  return (
    <Card
      className={`transition-shadow hover:shadow-md ${
        highlight ? "border-primary/40 bg-primary/5" : ""
      }`}
    >
      <CardContent className="pt-5">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold tracking-tight">{value}</p>
            {sub && (
              <p className="text-xs text-muted-foreground">{sub}</p>
            )}
          </div>
          <div className="rounded-md bg-muted p-2 text-muted-foreground">
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Feature-off state ────────────────────────────────────────────────────────

function NotEnabledState() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <AlertTriangle className="h-12 w-12 text-amber-500" />
      <h2 className="text-xl font-semibold text-muted-foreground">
        Hotel PMS not enabled
      </h2>
      <p className="max-w-md text-sm text-muted-foreground">
        The Hotel PMS feature is currently disabled. Enable{" "}
        <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
          HOTEL_PMS_ENABLED
        </code>{" "}
        to view KPI reports.
      </p>
      <Button variant="outline" asChild>
        <Link to="/hotels/setup">Back to Hotels</Link>
      </Button>
    </div>
  );
}

// ─── Chart helpers ────────────────────────────────────────────────────────────

interface ChartDataPoint {
  name: string;
  occupancy: number;   // percent (0–100)
  adr: number;         // dollars
  revpar: number;      // dollars
}

function buildChartData(kpis: HotelKpisOut): ChartDataPoint[] {
  // Single-period summary: one bar per metric, normalised to human units
  return [
    {
      name: "Metrics",
      occupancy: Math.round(kpis.occupancy_pct * 10) / 10,
      adr: Math.round(kpis.adr_cents / 100 * 100) / 100,
      revpar: Math.round(kpis.revpar_cents / 100 * 100) / 100,
    },
  ];
}

// Custom tooltip for the recharts bar chart
function ChartTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border bg-popover px-3 py-2 text-sm shadow-md">
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <span
            className="inline-block h-2.5 w-2.5 rounded-sm"
            style={{ backgroundColor: p.color }}
          />
          <span className="capitalize text-muted-foreground">{p.name}:</span>
          <span className="font-semibold">
            {p.name === "occupancy" ? `${p.value}%` : `$${p.value.toFixed(2)}`}
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function HotelKpiDashboard() {
  const { hotelId } = useParams<{ hotelId: string }>();

  const [preset, setPreset] = useState<Preset>("30d");
  const [customFrom, setCustomFrom] = useState(() =>
    toLocalDate(new Date(Date.now() - 30 * 86400 * 1000)),
  );
  const [customTo, setCustomTo] = useState(() => toLocalDate(new Date()));

  const { from, to } = useMemo<{ from: string; to: string }>(() => {
    if (preset === "custom") return { from: customFrom, to: customTo };
    return presetToRange(preset);
  }, [preset, customFrom, customTo]);

  const fromTs = useMemo(() => dateToStartOfDayTs(from), [from]);
  const toTs = useMemo(() => dateToEndOfDayTs(to), [to]);

  const {
    data: kpis,
    isLoading,
    isFetching,
    error,
    isError,
    refetch,
  } = useQuery<HotelKpisOut, ApiError>({
    queryKey: ["hotel-kpis", hotelId, fromTs, toTs],
    queryFn: () => getHotelKpis(hotelId!, fromTs, toTs),
    enabled: !!hotelId && fromTs < toTs,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 422))
        return false;
      return failureCount < 2;
    },
  });

  // ── Feature off (HOTEL_PMS_ENABLED=false) ─────────────────────────────────

  const featureOff =
    isError &&
    error instanceof ApiError &&
    error.status === 404 &&
    (error.detail?.toLowerCase().includes("pms") ||
      error.detail?.toLowerCase().includes("enabled"));

  if (featureOff) {
    return (
      <div className="p-6">
        <NotEnabledState />
      </div>
    );
  }

  const rangeTooLarge =
    isError &&
    error instanceof ApiError &&
    error.status === 422 &&
    error.detail?.toLowerCase().includes("range");

  const currency = kpis?.currency?.toUpperCase() ?? "USD";

  const chartData = kpis ? buildChartData(kpis) : [];

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Hotel KPI Dashboard"
        description={
          hotelId
            ? `Performance metrics for hotel ${hotelId}`
            : "Hotel performance metrics"
        }
        actions={<LineChartIcon className="h-6 w-6 text-muted-foreground" />}
      />

      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Link
          to="/hotels/setup"
          className="hover:text-foreground hover:underline"
        >
          Hotels
        </Link>
        <span>/</span>
        {hotelId && (
          <>
            <Link
              to={`/hotels/setup/${hotelId}`}
              className="hover:text-foreground hover:underline"
            >
              {hotelId}
            </Link>
            <span>/</span>
          </>
        )}
        <span className="text-foreground">KPI Dashboard</span>
      </div>

      {/* Date range controls */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <CalendarRange className="h-4 w-4" />
            Date Range
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          {(["7d", "30d", "90d", "365d", "custom"] as Preset[]).map((p) => (
            <Button
              key={p}
              size="sm"
              variant={preset === p ? "default" : "outline"}
              onClick={() => setPreset(p)}
            >
              {presetLabel(p)}
            </Button>
          ))}

          {preset === "custom" && (
            <div className="flex items-center gap-2 text-sm">
              <label htmlFor="from-date" className="text-muted-foreground">
                From
              </label>
              <input
                id="from-date"
                type="date"
                value={customFrom}
                max={customTo}
                onChange={(e) => setCustomFrom(e.target.value)}
                className="rounded border bg-background px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
              />
              <label htmlFor="to-date" className="text-muted-foreground">
                To
              </label>
              <input
                id="to-date"
                type="date"
                value={customTo}
                min={customFrom}
                onChange={(e) => setCustomTo(e.target.value)}
                className="rounded border bg-background px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>
          )}

          <Button
            size="sm"
            variant="ghost"
            onClick={() => refetch()}
            disabled={isFetching}
            className="ml-auto gap-1.5"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isFetching ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        </CardContent>
      </Card>

      {/* Range context badge */}
      {!isLoading && (
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="secondary" className="text-xs">
            {from} → {to}
          </Badge>
          {kpis && (
            <Badge variant="outline" className="text-xs">
              Currency: {currency}
            </Badge>
          )}
          {isFetching && !isLoading && (
            <Badge
              variant="outline"
              className="gap-1 text-xs text-muted-foreground"
            >
              <Loader2 className="h-3 w-3 animate-spin" />
              Refreshing…
            </Badge>
          )}
        </div>
      )}

      {/* Loading skeleton */}
      {isLoading && (
        <div className="flex items-center gap-2 py-8 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-sm">Loading KPI data…</span>
        </div>
      )}

      {/* Range error */}
      {rangeTooLarge && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          The selected date range is too large (max 366 days). Please narrow
          your selection.
        </div>
      )}

      {/* Other errors */}
      {isError && !featureOff && !rangeTooLarge && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {error instanceof ApiError ? error.detail : String(error)}
        </div>
      )}

      {/* KPI stat cards */}
      {kpis && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard
              icon={<TrendingUp className="h-4 w-4" />}
              label="Occupancy"
              value={`${kpis.occupancy_pct.toFixed(1)}%`}
              sub={`${kpis.rooms_sold} room-nights sold`}
              highlight
            />
            <KpiCard
              icon={<DollarSign className="h-4 w-4" />}
              label="ADR (Avg Daily Rate)"
              value={centsToDisplay(kpis.adr_cents, currency)}
              sub="Per occupied room-night"
            />
            <KpiCard
              icon={<Hotel className="h-4 w-4" />}
              label="RevPAR"
              value={centsToDisplay(kpis.revpar_cents, currency)}
              sub="Revenue per available room"
            />
            <KpiCard
              icon={<BedDouble className="h-4 w-4" />}
              label="Room Revenue"
              value={centsToDisplay(kpis.room_revenue_cents, currency)}
              sub={`${kpis.rooms_available} room-nights available`}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <KpiCard
              icon={<Users className="h-4 w-4" />}
              label="Arrivals"
              value={kpis.arrivals.toLocaleString()}
              sub="Guest check-ins in period"
            />
            <KpiCard
              icon={<Users className="h-4 w-4" />}
              label="Departures"
              value={kpis.departures.toLocaleString()}
              sub="Guest check-outs in period"
            />
          </div>

          <Separator />

          {/* Chart */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">
                Metrics Overview
              </CardTitle>
              <CardDescription className="text-xs">
                Occupancy % · ADR ($) · RevPAR ($) — {from} to {to}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart
                  data={chartData}
                  margin={{ top: 10, right: 20, left: 10, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <RechartTooltip content={<ChartTooltip />} />
                  <Legend
                    formatter={(value) => (
                      <span className="capitalize text-sm">{value}</span>
                    )}
                  />
                  <Bar
                    dataKey="occupancy"
                    name="occupancy"
                    fill="hsl(var(--primary))"
                    radius={[4, 4, 0, 0]}
                  />
                  <Bar
                    dataKey="adr"
                    name="adr"
                    fill="hsl(var(--chart-2, 199 89% 48%))"
                    radius={[4, 4, 0, 0]}
                  />
                  <Bar
                    dataKey="revpar"
                    name="revpar"
                    fill="hsl(var(--chart-3, 142 71% 45%))"
                    radius={[4, 4, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Details table */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">
                Raw Numbers
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm sm:grid-cols-3 lg:grid-cols-4">
                <div>
                  <p className="text-xs text-muted-foreground">
                    Rooms available (room-nights)
                  </p>
                  <p className="font-mono font-medium">
                    {kpis.rooms_available.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">
                    Rooms sold (room-nights)
                  </p>
                  <p className="font-mono font-medium">
                    {kpis.rooms_sold.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">
                    Occupancy %
                  </p>
                  <p className="font-mono font-medium">
                    {kpis.occupancy_pct.toFixed(1)}%
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">
                    Room revenue (cents)
                  </p>
                  <p className="font-mono font-medium">
                    {kpis.room_revenue_cents.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">ADR (cents)</p>
                  <p className="font-mono font-medium">
                    {kpis.adr_cents.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">RevPAR (cents)</p>
                  <p className="font-mono font-medium">
                    {kpis.revpar_cents.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Arrivals</p>
                  <p className="font-mono font-medium">
                    {kpis.arrivals.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Departures</p>
                  <p className="font-mono font-medium">
                    {kpis.departures.toLocaleString()}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Link to cancellation policy */}
          {hotelId && (
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">
                Configure fee rules →
              </span>
              <Link
                to={`/hotels/policies/${hotelId}`}
                className="font-medium text-primary underline-offset-2 hover:underline"
              >
                Cancellation Policy Editor
              </Link>
            </div>
          )}
        </>
      )}
    </div>
  );
}
