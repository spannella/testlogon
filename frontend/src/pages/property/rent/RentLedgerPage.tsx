/**
 * RentLedgerPage — Overview / summary dashboard for the rent ledger (RNT-004)
 * Route: /property/rent
 *
 * Shows period summary cards and period navigation.
 * Flag off → 404/503; shows a "not enabled" state.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BarChart3, Calendar, DollarSign, AlertTriangle, Clock } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

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

// ─── Summary card ────────────────────────────────────────────────────────────

interface SummaryCardProps {
  title: string;
  value: string;
  icon: React.ReactNode;
  variant?: "default" | "success" | "warning" | "destructive";
}

function SummaryCard({ title, value, icon, variant = "default" }: SummaryCardProps) {
  const borderColor =
    variant === "success"
      ? "border-green-500/40"
      : variant === "warning"
        ? "border-yellow-500/40"
        : variant === "destructive"
          ? "border-destructive/40"
          : "";
  return (
    <Card className={borderColor}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <span className="text-muted-foreground">{icon}</span>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
      </CardContent>
    </Card>
  );
}

// ─── Aging table ─────────────────────────────────────────────────────────────

interface AgingTableProps {
  current_cents: number;
  days_30_cents: number;
  days_60_cents: number;
  days_90_plus_cents: number;
  total_open_cents: number;
  open_item_count: number;
  source: string;
}

function AgingTable(a: AgingTableProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">AR Aging Breakdown</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-md border p-3 text-center">
            <p className="text-xs text-muted-foreground">Current</p>
            <p className="mt-1 font-semibold">{fmtCents(a.current_cents)}</p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-xs text-muted-foreground">1–30 days</p>
            <p className="mt-1 font-semibold text-yellow-600">{fmtCents(a.days_30_cents)}</p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-xs text-muted-foreground">31–60 days</p>
            <p className="mt-1 font-semibold text-orange-600">{fmtCents(a.days_60_cents)}</p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-xs text-muted-foreground">90+ days</p>
            <p className="mt-1 font-semibold text-destructive">{fmtCents(a.days_90_plus_cents)}</p>
          </div>
        </div>
        <p className="mt-3 text-xs text-muted-foreground">
          {a.open_item_count} open item{a.open_item_count !== 1 ? "s" : ""} · source: {a.source}
        </p>
      </CardContent>
    </Card>
  );
}

// ─── Main component ──────────────────────────────────────────────────────────

export default function RentLedgerPage() {
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
        <PageHeader title="Rent Ledger" description="Monthly rent tracking and payment collection" />
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <BarChart3 className="h-10 w-10 text-muted-foreground" />
            <p className="text-lg font-medium">Rent Ledger is not enabled</p>
            <p className="text-sm text-muted-foreground">
              Set <code>RENT_LEDGER_ENABLED=1</code> in your environment to activate this feature.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const periods = periodsQuery.data?.periods ?? [];
  const summary = summaryQuery.data;
  const isLoading = periodsQuery.isLoading || summaryQuery.isLoading;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Rent Ledger"
        description="Monthly rent tracking and payment collection"
        actions={
          <div className="flex items-center gap-2">
            {periods.length > 0 && (
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
            )}
            <Button asChild variant="outline" size="sm">
              <Link to="/property/rent/aging">Aging View</Link>
            </Button>
          </div>
        }
      />

      {/* Summary cards */}
      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-32" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : summary ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <SummaryCard
              title="Charged"
              value={fmtCents(summary.charged_cents)}
              icon={<DollarSign className="h-4 w-4" />}
            />
            <SummaryCard
              title="Collected"
              value={fmtCents(summary.collected_cents)}
              icon={<DollarSign className="h-4 w-4" />}
              variant="success"
            />
            <SummaryCard
              title="Outstanding"
              value={fmtCents(summary.outstanding_cents)}
              icon={<Clock className="h-4 w-4" />}
              variant={summary.outstanding_cents > 0 ? "warning" : "default"}
            />
            <SummaryCard
              title="Overdue"
              value={fmtCents(summary.overdue_cents)}
              icon={<AlertTriangle className="h-4 w-4" />}
              variant={summary.overdue_cents > 0 ? "destructive" : "default"}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Period</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-muted-foreground" />
                  <span className="font-semibold">{summary.period}</span>
                  <Badge variant="outline">{summary.scope === "all" ? "All leases" : `Lease ${summary.scope}`}</Badge>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Charges / Payments</CardTitle>
              </CardHeader>
              <CardContent>
                <span className="text-2xl font-bold">{summary.charge_count}</span>
                <span className="ml-1 text-muted-foreground text-sm">charges</span>
                <span className="ml-3 text-2xl font-bold">{summary.payment_count}</span>
                <span className="ml-1 text-muted-foreground text-sm">payments</span>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">All-time Due (settled)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{fmtCents(summary.due_settled_cents_all_time)}</div>
              </CardContent>
            </Card>
          </div>

          {summary.aging && <AgingTable {...summary.aging} />}
        </>
      ) : null}

      {/* Quick links */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Quick Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3">
            <Button asChild variant="outline">
              <Link to="/property/rent/aging">View Aging Report</Link>
            </Button>
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            To record a payment or charge rent, open the lease detail from the{" "}
            <Link to="/property/leases" className="underline hover:text-foreground">
              Leases
            </Link>{" "}
            section and navigate to its rent tab.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
