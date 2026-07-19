import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  getAnalyticsSummary,
  getAnalyticsTimeseries,
  getAnalyticsBreakdown,
  getAdRoasReport,
  exportAnalyticsCsv,
  listMyAdAccounts,
} from "@/api/endpoints/ads";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Download, BarChart3, TrendingUp, TrendingDown } from "lucide-react";

const DATE_RANGES = [
  { label: "Last 7 days", value: "7" },
  { label: "Last 30 days", value: "30" },
  { label: "Last 90 days", value: "90" },
];

function KpiCard({
  title,
  value,
  changePct,
  format = "number",
}: {
  title: string;
  value: number;
  changePct?: number;
  format?: "number" | "currency" | "percent";
}) {
  let display: string;
  if (format === "currency") {
    display = `$${(value / 100).toFixed(2)}`;
  } else if (format === "percent") {
    display = `${value.toFixed(2)}%`;
  } else {
    display = value.toLocaleString();
  }

  return (
    <Card>
      <CardContent className="pt-4 pb-3">
        <p className="text-sm text-muted-foreground">{title}</p>
        <p className="text-2xl font-bold mt-1">{display}</p>
        {changePct !== undefined && (
          <div className="flex items-center gap-1 mt-1">
            {changePct >= 0 ? (
              <TrendingUp className="h-3 w-3 text-green-600" />
            ) : (
              <TrendingDown className="h-3 w-3 text-red-600" />
            )}
            <span
              className={`text-xs ${
                changePct >= 0 ? "text-green-600" : "text-red-600"
              }`}
            >
              {changePct >= 0 ? "+" : ""}
              {changePct.toFixed(1)}%
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function AdAnalyticsDashboard() {
  const [days, setDays] = useState("30");
  // Account selection: seed from ?account_id= if present, otherwise the in-page
  // picker (below) defaults to the first advertiser account so the dashboard is
  // usable straight from nav without a manual URL param.
  const [accountId, setAccountId] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("account_id") || "";
  });

  const accountsQ = useQuery({
    queryKey: ["ad-analytics", "accounts"],
    queryFn: () => listMyAdAccounts(),
    staleTime: 60_000,
  });
  const accounts = accountsQ.data ?? [];

  // Auto-select the first account once accounts load and nothing is selected yet.
  useEffect(() => {
    if (!accountId && accounts.length > 0) {
      setAccountId(accounts[0]!.account_id);
    }
  }, [accountId, accounts]);

  const daysNum = parseInt(days, 10);

  const summaryQ = useQuery({
    queryKey: ["ad-analytics", "summary", accountId, daysNum],
    queryFn: () => getAnalyticsSummary(accountId, { days: daysNum }),
    enabled: !!accountId,
    staleTime: 60_000,
  });

  const timeseriesQ = useQuery({
    queryKey: ["ad-analytics", "timeseries", accountId, daysNum],
    queryFn: () =>
      getAnalyticsTimeseries(accountId, { days: daysNum, granularity: "daily" }),
    enabled: !!accountId,
    staleTime: 60_000,
  });

  const breakdownQ = useQuery({
    queryKey: ["ad-analytics", "breakdown", accountId, daysNum],
    queryFn: () =>
      getAnalyticsBreakdown(accountId, { dimension: "creative", days: daysNum }),
    enabled: !!accountId,
    staleTime: 60_000,
  });

  const roasQ = useQuery({
    queryKey: ["ad-analytics", "roas", accountId, daysNum],
    queryFn: () => getAdRoasReport(accountId, { days: daysNum }),
    enabled: !!accountId,
    staleTime: 60_000,
  });

  const summary = summaryQ.data;
  const timeseries = timeseriesQ.data ?? [];
  const breakdown = breakdownQ.data ?? [];
  const roas = roasQ.data;

  const handleExport = () => {
    const url = exportAnalyticsCsv(accountId, { days: daysNum });
    window.open(url, "_blank");
  };

  // No account resolved yet: while accounts load, show a spinner-ish message;
  // if the user genuinely has no advertiser accounts, guide them to create one.
  if (!accountId) {
    return (
      <div className="p-6" data-testid="ad-analytics-dashboard">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Ad Analytics Dashboard</h1>
        </div>
        {accountsQ.isLoading ? (
          <p className="text-muted-foreground mt-4">Loading your advertiser accounts…</p>
        ) : accountsQ.isError ? (
          <p className="text-muted-foreground mt-4">
            Couldn&apos;t load your advertiser accounts. Please try again.
          </p>
        ) : (
          <p className="text-muted-foreground mt-4" data-testid="no-accounts">
            You don&apos;t have any advertiser accounts yet. Create one to see analytics.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="ad-analytics-dashboard">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Ad Analytics Dashboard</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {accounts.length > 0 && (
            <Select value={accountId} onValueChange={setAccountId}>
              <SelectTrigger className="w-[220px]" data-testid="account-select">
                <SelectValue placeholder="Select account" />
              </SelectTrigger>
              <SelectContent>
                {accounts.map((a) => (
                  <SelectItem key={a.account_id} value={a.account_id}>
                    {a.company_name || a.account_id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <Select value={days} onValueChange={setDays}>
            <SelectTrigger className="w-[160px]" data-testid="date-range-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DATE_RANGES.map((r) => (
                <SelectItem key={r.value} value={r.value}>
                  {r.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={handleExport} data-testid="export-btn">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <KpiCard
            title="Impressions"
            value={summary.impressions}
            changePct={summary.impressions_change_pct}
          />
          <KpiCard
            title="Clicks"
            value={summary.clicks}
            changePct={summary.clicks_change_pct}
          />
          <KpiCard
            title="CTR"
            value={summary.ctr_pct}
            format="percent"
          />
          <KpiCard
            title="Spend"
            value={summary.spend_cents}
            changePct={summary.spend_change_pct}
            format="currency"
          />
          <KpiCard
            title="CPC"
            value={summary.cpc_cents}
            changePct={summary.cpc_change_pct}
            format="currency"
          />
        </div>
      )}

      {/* ROAS & Conversions (ADV3-8) - sourced from the same ledger as the KPIs */}
      {roas && (
        <Card data-testid="ad-roas-panel">
          <CardHeader>
            <CardTitle>ROAS &amp; Conversions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Conversions</p>
                <p className="text-xl font-semibold">
                  {roas.totals.conversions.toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Conversion Value</p>
                <p className="text-xl font-semibold">
                  ${(roas.totals.conversion_value_cents / 100).toFixed(2)}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Spend</p>
                <p className="text-xl font-semibold">
                  ${(roas.totals.spend_cents / 100).toFixed(2)}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">ROAS</p>
                <p className="text-xl font-semibold">{roas.totals.roas.toFixed(2)}x</p>
              </div>
            </div>
            {roas.campaigns.length > 0 && (
              <table className="w-full text-sm mt-4">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2">Campaign</th>
                    <th className="text-right py-2">Conv.</th>
                    <th className="text-right py-2">Value</th>
                    <th className="text-right py-2">Spend</th>
                    <th className="text-right py-2">ROAS</th>
                  </tr>
                </thead>
                <tbody>
                  {roas.campaigns.map((c) => (
                    <tr key={c.campaign_id ?? "unknown"} className="border-b">
                      <td className="py-1.5">{c.campaign_id ?? "unknown"}</td>
                      <td className="text-right">{c.conversions.toLocaleString()}</td>
                      <td className="text-right">
                        ${(c.conversion_value_cents / 100).toFixed(2)}
                      </td>
                      <td className="text-right">
                        ${(c.spend_cents / 100).toFixed(2)}
                      </td>
                      <td className="text-right">{c.roas.toFixed(2)}x</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Time Series Chart Area */}
      <Card data-testid="analytics-chart">
        <CardHeader>
          <CardTitle>Performance Over Time</CardTitle>
        </CardHeader>
        <CardContent>
          {timeseries.length === 0 ? (
            <p className="text-muted-foreground text-sm">No data for this period.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2">Date</th>
                    <th className="text-right py-2">Impressions</th>
                    <th className="text-right py-2">Clicks</th>
                    <th className="text-right py-2">CTR %</th>
                    <th className="text-right py-2">Spend</th>
                  </tr>
                </thead>
                <tbody>
                  {timeseries.map((p) => (
                    <tr key={p.date} className="border-b">
                      <td className="py-1.5">{p.date}</td>
                      <td className="text-right">{p.impressions.toLocaleString()}</td>
                      <td className="text-right">{p.clicks.toLocaleString()}</td>
                      <td className="text-right">{p.ctr_pct.toFixed(2)}%</td>
                      <td className="text-right">${(p.spend_cents / 100).toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Breakdown Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>By Creative</CardTitle>
          </CardHeader>
          <CardContent>
            {breakdown.length === 0 ? (
              <p className="text-muted-foreground text-sm">No breakdown data.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2">Creative</th>
                    <th className="text-right py-2">Impressions</th>
                    <th className="text-right py-2">Clicks</th>
                    <th className="text-right py-2">CTR %</th>
                  </tr>
                </thead>
                <tbody>
                  {breakdown.map((b) => (
                    <tr key={b.dimension_key} className="border-b">
                      <td className="py-1.5">{b.dimension_key}</td>
                      <td className="text-right">{b.impressions.toLocaleString()}</td>
                      <td className="text-right">{b.clicks.toLocaleString()}</td>
                      <td className="text-right">{b.ctr_pct.toFixed(2)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
