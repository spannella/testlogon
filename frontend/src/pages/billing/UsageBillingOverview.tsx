import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getUsageSummary, getUsageDaily, getUsageStorage } from "@/api/endpoints/files";

function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function formatPercent(value: number): string {
  return `${Math.max(0, value).toFixed(1)}%`;
}

function currentPeriodId(): string {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

function periodBounds(periodId: string): { from: string; to: string } {
  const [yStr, mStr] = periodId.split("-");
  const year = Number(yStr);
  const monthIdx = Number(mStr) - 1;
  if (!Number.isInteger(year) || !Number.isInteger(monthIdx) || monthIdx < 0 || monthIdx > 11) {
    const today = new Date().toISOString().slice(0, 10);
    return { from: today, to: today };
  }
  const first = new Date(Date.UTC(year, monthIdx, 1));
  const last = new Date(Date.UTC(year, monthIdx + 1, 0));
  return {
    from: first.toISOString().slice(0, 10),
    to: last.toISOString().slice(0, 10),
  };
}

type UsageCardProps = {
  title: string;
  used: number;
  limit: number;
  percent: number;
};

function UsageCard({ title, used, limit, percent }: UsageCardProps) {
  const capped = Math.min(percent, 100);
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-xl">{formatBytes(used)}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="text-xs text-muted-foreground">
          {limit > 0 ? `${formatBytes(limit)} limit` : "No configured limit"}
        </div>
        <div className="h-2 rounded bg-muted">
          <div className="h-2 rounded bg-primary" style={{ width: `${Math.max(2, capped)}%` }} />
        </div>
        <div className="text-xs">{formatPercent(percent)} used</div>
      </CardContent>
    </Card>
  );
}

export default function UsageBillingOverview() {
  const [periodId, setPeriodId] = React.useState(currentPeriodId());
  const [periodInput, setPeriodInput] = React.useState(currentPeriodId());

  const summaryQuery = useQuery({
    queryKey: ["usage-summary", periodId],
    queryFn: () => getUsageSummary(periodId),
  });

  const dailyRange = React.useMemo(() => periodBounds(periodId), [periodId]);
  const dailyQuery = useQuery({
    queryKey: ["usage-daily", dailyRange.from, dailyRange.to],
    queryFn: () => getUsageDaily({ from: dailyRange.from, to: dailyRange.to }),
  });

  const storageQuery = useQuery({
    queryKey: ["usage-storage"],
    queryFn: () => getUsageStorage(5),
  });

  const summary = summaryQuery.data;
  const dailyItems = dailyQuery.data?.items ?? [];
  const maxDaily = Math.max(
    1,
    ...dailyItems.map((d) => Math.max(d.upload_bytes_total, d.download_bytes_total)),
  );

  const estimatedOverage = React.useMemo(() => {
    if (!summary) return null;
    const metrics = [
      ["Upload", summary.upload],
      ["Download", summary.download],
      ["Storage", summary.storage],
    ] as const;
    return metrics
      .filter(([, metric]) => metric.limit_bytes > 0 && metric.used_bytes > metric.limit_bytes)
      .map(([label, metric]) => ({
        label,
        over: metric.used_bytes - metric.limit_bytes,
      }));
  }, [summary]);

  const applyPeriod = () => {
    if (/^\d{4}-\d{2}$/.test(periodInput)) {
      setPeriodId(periodInput);
    }
  };

  return (
    <div className="space-y-6" data-testid="usage-billing-overview">
      <div className="flex flex-wrap items-end gap-2">
        <div className="space-y-1">
          <div className="text-sm font-medium">Billing period (UTC month)</div>
          <Input className="w-36" value={periodInput} onChange={(e) => setPeriodInput(e.target.value)} placeholder="YYYY-MM" />
        </div>
        <Button type="button" variant="outline" onClick={applyPeriod}>Apply</Button>
        <div className="text-xs text-muted-foreground">Current: {periodId}</div>
      </div>

      {summaryQuery.isLoading ? (
        <div className="grid gap-4 md:grid-cols-3">
          <Skeleton className="h-36" />
          <Skeleton className="h-36" />
          <Skeleton className="h-36" />
        </div>
      ) : summary ? (
        <div className="grid gap-4 md:grid-cols-3">
          <UsageCard title="Upload usage" used={summary.upload.used_bytes} limit={summary.upload.limit_bytes} percent={summary.upload.percent_used} />
          <UsageCard title="Download usage" used={summary.download.used_bytes} limit={summary.download.limit_bytes} percent={summary.download.percent_used} />
          <UsageCard title="Storage usage" used={summary.storage.used_bytes} limit={summary.storage.limit_bytes} percent={summary.storage.percent_used} />
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Daily trend</CardTitle>
          <CardDescription>Uploads and downloads per day in selected period</CardDescription>
        </CardHeader>
        <CardContent>
          {dailyQuery.isLoading ? (
            <Skeleton className="h-52" />
          ) : dailyItems.length === 0 ? (
            <div className="text-sm text-muted-foreground">No daily usage events in this range.</div>
          ) : (
            <div className="space-y-2">
              {dailyItems.map((item) => (
                <div key={item.day_utc} className="grid grid-cols-[88px_1fr_1fr] items-center gap-2 text-xs">
                  <span className="font-medium">{item.day_utc.slice(5)}</span>
                  <div className="h-2 rounded bg-muted" title={`Upload ${formatBytes(item.upload_bytes_total)}`}>
                    <div className="h-2 rounded bg-blue-500" style={{ width: `${Math.max(2, (item.upload_bytes_total / maxDaily) * 100)}%` }} />
                  </div>
                  <div className="h-2 rounded bg-muted" title={`Download ${formatBytes(item.download_bytes_total)}`}>
                    <div className="h-2 rounded bg-emerald-500" style={{ width: `${Math.max(2, (item.download_bytes_total / maxDaily) * 100)}%` }} />
                  </div>
                </div>
              ))}
              <div className="text-xs text-muted-foreground">Blue = upload, Green = download</div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Estimated overage</CardTitle>
          <CardDescription>Simple over-limit estimate based on current period usage</CardDescription>
        </CardHeader>
        <CardContent>
          {!estimatedOverage || estimatedOverage.length === 0 ? (
            <div className="text-sm text-muted-foreground">No overage currently estimated.</div>
          ) : (
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {estimatedOverage.map((row) => (
                <li key={row.label}>{row.label}: {formatBytes(row.over)} over limit</li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Current storage footprint</CardTitle>
          <CardDescription>Top files by size across active files</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="text-sm font-medium">Total: {formatBytes(storageQuery.data?.storage_bytes_current ?? 0)}</div>
          <ul className="space-y-1 text-sm text-muted-foreground">
            {(storageQuery.data?.top_files ?? []).map((f) => (
              <li key={f.path} className="flex items-center justify-between gap-2">
                <span className="truncate">{f.path}</span>
                <span>{formatBytes(f.size)}</span>
              </li>
            ))}
          </ul>
          <div className="pt-2 text-xs">
            <Link className="text-primary underline" to="/files">Go to Files</Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
