/**
 * RentAgingPage — AR aging view for rent ledger (RNT-006)
 * Route: /property/rent/aging
 *
 * Shows aging breakdown across all leases for the selected period.
 * Flag off → shows not-enabled state.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, AlertTriangle, BarChart3 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
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

import { ApiError } from "@/api/client";
import { getRentSummary, getRentPeriods } from "@/api/endpoints/rentLedger";

// ─── Helpers ────────────────────────────────────────────────────────────────

function fmtCents(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function pct(part: number, total: number): string {
  if (total === 0) return "0%";
  return `${Math.round((part / total) * 100)}%`;
}

// ─── Aging bar ───────────────────────────────────────────────────────────────

interface AgingBarProps {
  current: number;
  d30: number;
  d60: number;
  d90: number;
  total: number;
}

function AgingBar({ current, d30, d60, d90, total }: AgingBarProps) {
  if (total === 0) {
    return <div className="h-4 w-full rounded bg-muted" />;
  }
  return (
    <div className="flex h-4 w-full overflow-hidden rounded">
      <div
        title={`Current: ${fmtCents(current)}`}
        style={{ width: pct(current, total) }}
        className="bg-green-500"
      />
      <div
        title={`1-30 days: ${fmtCents(d30)}`}
        style={{ width: pct(d30, total) }}
        className="bg-yellow-400"
      />
      <div
        title={`31-60 days: ${fmtCents(d60)}`}
        style={{ width: pct(d60, total) }}
        className="bg-orange-500"
      />
      <div
        title={`90+ days: ${fmtCents(d90)}`}
        style={{ width: pct(d90, total) }}
        className="bg-destructive"
      />
    </div>
  );
}

// ─── Main component ──────────────────────────────────────────────────────────

export default function RentAgingPage() {
  const [selectedPeriod, setSelectedPeriod] = useState<string>("");

  const periodsQuery = useQuery({
    queryKey: ["rent", "periods"],
    queryFn: () => getRentPeriods({ count: 12 }),
    retry: false,
  });

  const summaryQuery = useQuery({
    queryKey: ["rent", "summary", selectedPeriod],
    queryFn: () => getRentSummary({ period: selectedPeriod || undefined }),
    retry: false,
    enabled: periodsQuery.isSuccess,
  });

  const isNotEnabled =
    (periodsQuery.error instanceof ApiError &&
      (periodsQuery.error.status === 404 || periodsQuery.error.status === 503)) ||
    (summaryQuery.error instanceof ApiError &&
      (summaryQuery.error.status === 404 || summaryQuery.error.status === 503));

  if (isNotEnabled) {
    return (
      <div className="flex flex-col gap-6 p-6">
        <PageHeader title="Rent Aging View" />
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <BarChart3 className="h-10 w-10 text-muted-foreground" />
            <p className="text-lg font-medium">Rent Ledger is not enabled</p>
            <p className="text-sm text-muted-foreground">
              Set <code>RENT_LEDGER_ENABLED=1</code> to activate this feature.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const periods = periodsQuery.data?.periods ?? [];
  const summary = summaryQuery.data;
  const aging = summary?.aging;
  const isLoading = periodsQuery.isLoading || summaryQuery.isLoading;

  const total = aging?.total_open_cents ?? 0;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Rent Aging View"
        description="Accounts receivable aging breakdown across all leases"
        actions={
          periods.length > 0 ? (
            <Select
              value={selectedPeriod || (periods[periods.length - 1] ?? "")}
              onValueChange={setSelectedPeriod}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Period" />
              </SelectTrigger>
              <SelectContent>
                {[...periods].reverse().map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : undefined
        }
      />

      <Button variant="ghost" size="sm" className="w-fit" asChild>
        <Link to="/property/rent">
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to Rent Ledger
        </Link>
      </Button>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : (
        <>
          {/* Summary row */}
          <div className="grid gap-4 sm:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Period</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold">{summary?.period ?? "—"}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total Outstanding</CardTitle>
              </CardHeader>
              <CardContent>
                <p className={`text-2xl font-bold ${summary?.outstanding_cents ? "text-destructive" : ""}`}>
                  {fmtCents(summary?.outstanding_cents ?? 0)}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Overdue</CardTitle>
              </CardHeader>
              <CardContent>
                <p className={`text-2xl font-bold ${summary?.overdue_cents ? "text-destructive" : ""}`}>
                  {fmtCents(summary?.overdue_cents ?? 0)}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Aging detail */}
          {aging ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  AR Aging Breakdown
                  <span className="ml-2 text-xs font-normal text-muted-foreground">
                    source: {aging.source}
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Visual bar */}
                <div className="space-y-1">
                  <AgingBar
                    current={aging.current_cents}
                    d30={aging.days_30_cents}
                    d60={aging.days_60_cents}
                    d90={aging.days_90_plus_cents}
                    total={total || 1}
                  />
                  <div className="flex gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <span className="inline-block h-2 w-2 rounded-sm bg-green-500" />
                      Current
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="inline-block h-2 w-2 rounded-sm bg-yellow-400" />
                      1-30 days
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="inline-block h-2 w-2 rounded-sm bg-orange-500" />
                      31-60 days
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="inline-block h-2 w-2 rounded-sm bg-destructive" />
                      90+ days
                    </span>
                  </div>
                </div>

                {/* Table */}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Bucket</TableHead>
                      <TableHead className="text-right">Amount</TableHead>
                      <TableHead className="text-right">% of Total</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    <TableRow>
                      <TableCell>Current (not yet due)</TableCell>
                      <TableCell className="text-right font-mono">{fmtCents(aging.current_cents)}</TableCell>
                      <TableCell className="text-right">{pct(aging.current_cents, total)}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="text-yellow-600">1–30 days overdue</TableCell>
                      <TableCell className="text-right font-mono text-yellow-600">{fmtCents(aging.days_30_cents)}</TableCell>
                      <TableCell className="text-right">{pct(aging.days_30_cents, total)}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="text-orange-600">31–60 days overdue</TableCell>
                      <TableCell className="text-right font-mono text-orange-600">{fmtCents(aging.days_60_cents)}</TableCell>
                      <TableCell className="text-right">{pct(aging.days_60_cents, total)}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="text-destructive">90+ days overdue</TableCell>
                      <TableCell className="text-right font-mono text-destructive">{fmtCents(aging.days_90_plus_cents)}</TableCell>
                      <TableCell className="text-right">{pct(aging.days_90_plus_cents, total)}</TableCell>
                    </TableRow>
                    <TableRow className="font-semibold border-t-2">
                      <TableCell>Total Open</TableCell>
                      <TableCell className="text-right font-mono">{fmtCents(aging.total_open_cents)}</TableCell>
                      <TableCell className="text-right">100%</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>

                <p className="text-xs text-muted-foreground">
                  {aging.open_item_count} open item{aging.open_item_count !== 1 ? "s" : ""}
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-dashed">
              <CardContent className="flex flex-col items-center gap-3 py-10">
                <AlertTriangle className="h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  No aging data available.{" "}
                  {!getattr("ar_ap_subledgers_enabled")
                    ? "Enable the AR/AP subledger or wait for charge activity."
                    : "No open items found for this period."}
                </p>
              </CardContent>
            </Card>
          )}

          {/* Quick summary */}
          {summary && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Period Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm sm:grid-cols-4">
                  <div>
                    <dt className="text-muted-foreground">Charged</dt>
                    <dd className="font-medium">{fmtCents(summary.charged_cents)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Collected</dt>
                    <dd className="font-medium text-green-600">{fmtCents(summary.collected_cents)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Charges</dt>
                    <dd className="font-medium">{summary.charge_count}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Leases</dt>
                    <dd className="font-medium">{summary.lease_count}</dd>
                  </div>
                </dl>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

// Helper to avoid direct settings access on frontend
function getattr(_: string): boolean {
  return false;
}
