import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BarChart3, Loader2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import FunnelChart from "@/components/shared/FunnelChart";
import VolumeChart from "@/components/shared/VolumeChart";
import ProcessingTimeHistogram from "@/components/shared/ProcessingTimeHistogram";
import RejectionReasonsPie from "@/components/shared/RejectionReasonsPie";
import PeriodComparisonCards from "@/components/shared/PeriodComparisonCards";
import {
  comparePeriods,
  getFunnel,
  getGeographic,
  getProcessingTimes,
  getRejectionReasons,
  getSnapshot,
  getTrends,
} from "@/api/endpoints/kyc-analytics";

const DAY = 86400;

const COUNTRIES = ["", "SE", "DE", "US", "GB", "FR", "NO", "DK"];
const TIERS = ["", "tier_1", "tier_2", "tier_3"];

function flagFor(country: string): string {
  if (!country || country.length !== 2) return "🏳️";
  const cc = country.toUpperCase();
  const base = 0x1f1e6;
  try {
    return String.fromCodePoint(
      base + (cc.charCodeAt(0) - 65),
      base + (cc.charCodeAt(1) - 65),
    );
  } catch {
    return "🏳️";
  }
}

export default function KycAnalyticsDashboard() {
  const nowSec = Math.floor(Date.now() / 1000);
  const [fromTs, setFromTs] = useState<number>(nowSec - 30 * DAY);
  const [toTs, setToTs] = useState<number>(nowSec);
  const [country, setCountry] = useState<string>("");
  const [tier, setTier] = useState<string>("");
  const [granularity, setGranularity] = useState<"daily" | "weekly" | "monthly">("daily");
  const [compare, setCompare] = useState<boolean>(false);

  const baseFilters = useMemo(
    () => ({ from: fromTs, to: toTs, country: country || undefined, tier: tier || undefined }),
    [fromTs, toTs, country, tier],
  );

  const funnelQ = useQuery({
    queryKey: ["kyc-analytics", "funnel", baseFilters],
    queryFn: () => getFunnel(baseFilters),
  });

  const snapshotQ = useQuery({
    queryKey: ["kyc-analytics", "snapshot", baseFilters],
    queryFn: () => getSnapshot(baseFilters),
  });

  const trendsQ = useQuery({
    queryKey: ["kyc-analytics", "trends", granularity],
    queryFn: () => getTrends({ granularity, periods: granularity === "monthly" ? 6 : 14 }),
  });

  const processingQ = useQuery({
    queryKey: ["kyc-analytics", "processing", fromTs, toTs],
    queryFn: () => getProcessingTimes({ from: fromTs, to: toTs }),
  });

  const rejectionQ = useQuery({
    queryKey: ["kyc-analytics", "rejection", fromTs, toTs],
    queryFn: () => getRejectionReasons({ from: fromTs, to: toTs }),
  });

  const geographicQ = useQuery({
    queryKey: ["kyc-analytics", "geographic", fromTs, toTs],
    queryFn: () => getGeographic({ from: fromTs, to: toTs }),
  });

  const periodLen = Math.max(DAY, toTs - fromTs);
  const compareQ = useQuery({
    queryKey: ["kyc-analytics", "compare", fromTs, toTs, compare],
    queryFn: () =>
      comparePeriods({
        current_from: fromTs,
        current_to: toTs,
        previous_from: fromTs - periodLen,
        previous_to: fromTs,
      }),
    enabled: compare,
  });

  const snap = snapshotQ.data?.snapshot;

  const setRangeDays = (days: number) => {
    const n = Math.floor(Date.now() / 1000);
    setFromTs(n - days * DAY);
    setToTs(n);
  };

  return (
    <div className="space-y-6 p-1">
      <div className="flex items-center gap-2">
        <BarChart3 className="h-6 w-6" />
        <h1 className="text-2xl font-bold" data-testid="kyc-analytics-heading">
          KYC Analytics
        </h1>
      </div>

      {/* Filter bar */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-4 pt-6">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">From</label>
            <Input
              type="date"
              data-testid="filter-from"
              value={new Date(fromTs * 1000).toISOString().slice(0, 10)}
              onChange={(e) =>
                setFromTs(Math.floor(new Date(e.target.value).getTime() / 1000))
              }
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">To</label>
            <Input
              type="date"
              data-testid="filter-to"
              value={new Date(toTs * 1000).toISOString().slice(0, 10)}
              onChange={(e) =>
                setToTs(Math.floor(new Date(e.target.value).getTime() / 1000))
              }
            />
          </div>
          <div className="flex gap-1">
            <Button variant="outline" size="sm" data-testid="range-7d" onClick={() => setRangeDays(7)}>
              Last 7 days
            </Button>
            <Button variant="outline" size="sm" data-testid="range-30d" onClick={() => setRangeDays(30)}>
              Last 30 days
            </Button>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Country</label>
            <Select
              value={country || "all"}
              onValueChange={(v) => setCountry(v === "all" ? "" : v)}
            >
              <SelectTrigger className="w-32" data-testid="filter-country">
                <SelectValue placeholder="All" />
              </SelectTrigger>
              <SelectContent>
                {COUNTRIES.map((c) => (
                  <SelectItem key={c || "all"} value={c || "all"}>
                    {c ? `${flagFor(c)} ${c}` : "All"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Tier</label>
            <Select value={tier || "all"} onValueChange={(v) => setTier(v === "all" ? "" : v)}>
              <SelectTrigger className="w-32" data-testid="filter-tier">
                <SelectValue placeholder="All" />
              </SelectTrigger>
              <SelectContent>
                {TIERS.map((t) => (
                  <SelectItem key={t || "all"} value={t || "all"}>
                    {t ? t.replace("_", " ") : "All"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 text-sm" data-testid="compare-toggle-label">
            <input
              type="checkbox"
              data-testid="compare-toggle"
              checked={compare}
              onChange={(e) => setCompare(e.target.checked)}
            />
            Compare with previous period
          </label>
        </CardContent>
      </Card>

      {/* Metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card data-testid="metric-conversion">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Conversion Rate</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {snap ? `${(snap.conversion_rate * 100).toFixed(1)}%` : "—"}
            </div>
          </CardContent>
        </Card>
        <Card data-testid="metric-total">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Total Applications</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{snap?.total_applications ?? "—"}</div>
          </CardContent>
        </Card>
        <Card data-testid="metric-approved">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Approved</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{snap?.approved_count ?? "—"}</div>
          </CardContent>
        </Card>
        <Card data-testid="metric-processing">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Avg Processing (h)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{snap?.avg_processing_hours ?? "—"}</div>
          </CardContent>
        </Card>
      </div>

      {/* Comparison */}
      {compare && compareQ.data && (
        <Card>
          <CardHeader>
            <CardTitle>Period Comparison</CardTitle>
          </CardHeader>
          <CardContent>
            <PeriodComparisonCards
              current={compareQ.data.current}
              previous={compareQ.data.previous}
              deltas={compareQ.data.deltas}
            />
          </CardContent>
        </Card>
      )}

      {/* Funnel */}
      <Card>
        <CardHeader>
          <CardTitle>KYC Funnel</CardTitle>
        </CardHeader>
        <CardContent>
          {funnelQ.isLoading ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : (
            <FunnelChart
              funnel={funnelQ.data?.funnel ?? []}
              conversionRate={funnelQ.data?.conversion_rate ?? 0}
            />
          )}
        </CardContent>
      </Card>

      {/* Volume trends */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Volume Trends</CardTitle>
          <div className="flex gap-1">
            {(["daily", "weekly", "monthly"] as const).map((g) => (
              <Button
                key={g}
                size="sm"
                variant={granularity === g ? "default" : "outline"}
                data-testid={`granularity-${g}`}
                onClick={() => setGranularity(g)}
              >
                {g[0].toUpperCase() + g.slice(1)}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          <VolumeChart trends={trendsQ.data?.trends ?? []} granularity={granularity} />
        </CardContent>
      </Card>

      {/* Processing + Rejection */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Processing Time Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ProcessingTimeHistogram
              histogram={processingQ.data?.histogram ?? []}
              percentiles={
                processingQ.data?.percentiles ?? { p50: 0, p75: 0, p90: 0, p99: 0 }
              }
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Rejection Reasons</CardTitle>
          </CardHeader>
          <CardContent>
            <RejectionReasonsPie reasons={rejectionQ.data?.reasons ?? {}} />
          </CardContent>
        </Card>
      </div>

      {/* Geographic */}
      <Card>
        <CardHeader>
          <CardTitle>Geographic Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <Table data-testid="geographic-table">
            <TableHeader>
              <TableRow>
                <TableHead>Country</TableHead>
                <TableHead className="text-right">Count</TableHead>
                <TableHead className="text-right">Approved</TableHead>
                <TableHead className="text-right">Rejected</TableHead>
                <TableHead className="text-right">Approval Rate</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(geographicQ.data?.countries ?? []).map((c) => (
                <TableRow key={c.country} data-testid={`geo-row-${c.country}`}>
                  <TableCell>
                    {flagFor(c.country)} {c.country}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{c.count}</TableCell>
                  <TableCell className="text-right tabular-nums">{c.approved}</TableCell>
                  <TableCell className="text-right tabular-nums">{c.rejected}</TableCell>
                  <TableCell className="text-right tabular-nums">{c.approval_rate}%</TableCell>
                </TableRow>
              ))}
              {(geographicQ.data?.countries?.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    No data for this period.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
