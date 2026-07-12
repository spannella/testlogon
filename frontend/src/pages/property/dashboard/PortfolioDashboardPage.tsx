/**
 * PMD-004 — Portfolio Dashboard page.
 *
 * Route: /property/dashboard
 *
 * Surfaces:
 *   - Four headline KPI cards (occupancy, leases, outstanding rent, work orders)
 *   - Monthly rent snapshot with year/month navigation (recharts BarChart)
 *   - Priority-items panel (upcoming lease expirations + open work orders)
 *   - Rent-policy dialog (admin/root only)
 *
 * Flag-gated: PROPERTY_DASHBOARD_ENABLED (default OFF).
 * When off, every backend endpoint returns 404 — the page renders a
 * "not enabled" state without crashing.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  Building,
  FileText,
  DollarSign,
  Wrench,
  ChevronLeft,
  ChevronRight,
  Settings,
  Loader2,
  AlertCircle,
  CalendarClock,
} from "lucide-react";
import { Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";

import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import { ApiError } from "@/api/client";
import {
  getPortfolioKpis,
  getRentSnapshot,
  getPriorityItems,
  getRentPolicy,
  updateRentPolicy,
  type PriorityItem,
} from "@/api/endpoints/propertyDashboard";

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatCents(cents: number, currency = "usd"): string {
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: currency.toUpperCase(),
      minimumFractionDigits: 2,
    }).format(cents / 100);
  } catch {
    return `$${(cents / 100).toFixed(2)}`;
  }
}

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function daysUntil(ts?: number | null): number {
  if (!ts) return 0;
  return Math.floor((ts - Date.now() / 1000) / 86400);
}

const MONTH_NAMES = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

// ─── Feature-not-enabled guard ───────────────────────────────────────────────

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-lg font-medium">Property Dashboard is not enabled</p>
      <p className="text-sm">Enable the <code>PROPERTY_DASHBOARD_ENABLED</code> flag to use this feature.</p>
    </div>
  );
}

// ─── Rent-policy form schema ─────────────────────────────────────────────────

const policySchema = z.object({
  rent_due_day: z.coerce.number().int().min(1).max(28),
  late_fee_cents: z.coerce.number().int().min(0),
  grace_period_days: z.coerce.number().int().min(0),
  currency: z.string().length(3).regex(/^[a-zA-Z]+$/, "Must be 3 letters"),
});

type PolicyFormValues = z.infer<typeof policySchema>;

// ─── Rent-policy dialog ──────────────────────────────────────────────────────

interface RentPolicyDialogProps {
  open: boolean;
  onClose: () => void;
}

function RentPolicyDialog({ open, onClose }: RentPolicyDialogProps) {
  const queryClient = useQueryClient();

  const policyQuery = useQuery({
    queryKey: ["property", "rent-policy"],
    queryFn: getRentPolicy,
    enabled: open,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const policy = policyQuery.data;

  const form = useForm<PolicyFormValues>({
    resolver: zodResolver(policySchema),
    values: policy
      ? {
          rent_due_day: policy.rent_due_day,
          late_fee_cents: policy.late_fee_cents,
          grace_period_days: policy.grace_period_days,
          currency: policy.currency,
        }
      : {
          rent_due_day: 1,
          late_fee_cents: 0,
          grace_period_days: 0,
          currency: "usd",
        },
  });

  const saveMut = useMutation({
    mutationFn: (vals: PolicyFormValues) =>
      updateRentPolicy({
        rent_due_day: vals.rent_due_day,
        late_fee_cents: vals.late_fee_cents,
        grace_period_days: vals.grace_period_days,
        currency: vals.currency.toLowerCase(),
      }),
    onSuccess: () => {
      toast.success("Rent policy saved");
      void queryClient.invalidateQueries({ queryKey: ["property", "rent-policy"] });
      void queryClient.invalidateQueries({ queryKey: ["property", "kpis"] });
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to save policy"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Rent Policy Settings</DialogTitle>
        </DialogHeader>

        {policyQuery.isLoading && (
          <div className="flex justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}

        {policyQuery.isError && (
          <p className="text-sm text-destructive py-4">
            {policyQuery.error instanceof ApiError && policyQuery.error.status === 404
              ? "Feature not enabled"
              : "Failed to load policy"}
          </p>
        )}

        {policy && (
          <form
            onSubmit={form.handleSubmit((vals) => saveMut.mutate(vals))}
            className="space-y-4"
          >
            {policy.is_default && (
              <p className="text-sm text-muted-foreground bg-muted px-3 py-2 rounded-md">
                Using platform defaults — no custom policy saved yet.
              </p>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <Label htmlFor="rent_due_day">Rent Due Day (1–28)</Label>
                <Input
                  id="rent_due_day"
                  type="number"
                  min={1}
                  max={28}
                  {...form.register("rent_due_day")}
                />
                {form.formState.errors.rent_due_day && (
                  <p className="text-xs text-destructive">{form.formState.errors.rent_due_day.message}</p>
                )}
              </div>

              <div className="space-y-1">
                <Label htmlFor="grace_period_days">Grace Period (days)</Label>
                <Input
                  id="grace_period_days"
                  type="number"
                  min={0}
                  {...form.register("grace_period_days")}
                />
                {form.formState.errors.grace_period_days && (
                  <p className="text-xs text-destructive">{form.formState.errors.grace_period_days.message}</p>
                )}
              </div>

              <div className="space-y-1">
                <Label htmlFor="late_fee_cents">Late Fee (cents)</Label>
                <Input
                  id="late_fee_cents"
                  type="number"
                  min={0}
                  {...form.register("late_fee_cents")}
                />
                {form.formState.errors.late_fee_cents && (
                  <p className="text-xs text-destructive">{form.formState.errors.late_fee_cents.message}</p>
                )}
              </div>

              <div className="space-y-1">
                <Label htmlFor="currency">Currency (ISO-4217)</Label>
                <Input
                  id="currency"
                  maxLength={3}
                  placeholder="usd"
                  {...form.register("currency")}
                />
                {form.formState.errors.currency && (
                  <p className="text-xs text-destructive">{form.formState.errors.currency.message}</p>
                )}
              </div>
            </div>

            <DialogFooter className="mt-4">
              <Button type="button" variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={saveMut.isPending}>
                {saveMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                Save Policy
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─── KPI card ────────────────────────────────────────────────────────────────

interface KpiCardProps {
  title: string;
  value: string;
  icon: React.ReactNode;
  loading?: boolean;
}

function KpiCard({ title, value, icon, loading }: KpiCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <span className="text-muted-foreground">{icon}</span>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-28" />
        ) : (
          <p className="text-2xl font-bold">{value}</p>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Priority item row ───────────────────────────────────────────────────────

function PriorityRow({ item }: { item: PriorityItem }) {
  if (item.kind === "lease_expiring") {
    const days = daysUntil(item.end_date);
    const urgent = days <= 14;
    return (
      <tr className="border-b last:border-0">
        <td className="py-2 pr-4">
          <div className="flex items-center gap-2">
            <CalendarClock className="h-4 w-4 text-muted-foreground shrink-0" />
            <span className="text-sm font-medium">Lease Expiring</span>
          </div>
        </td>
        <td className="py-2 pr-4 text-sm text-muted-foreground">
          {item.lease_number ?? item.lease_id ?? "—"}
        </td>
        <td className="py-2 pr-4 text-sm">{fmtDate(item.end_date)}</td>
        <td className="py-2 text-sm">
          <Badge variant={urgent ? "destructive" : "secondary"}>
            {days <= 0 ? "Expired" : `${days}d`}
          </Badge>
        </td>
        <td className="py-2 pl-4 text-sm">
          {item.monthly_rent_cents != null ? formatCents(item.monthly_rent_cents) : "—"}
        </td>
        <td className="py-2 pl-4 text-sm">
          {item.lease_id ? (
            <Link
              to={`/property/leases/${item.lease_id}`}
              className="text-primary hover:underline"
            >
              View
            </Link>
          ) : "—"}
        </td>
      </tr>
    );
  }

  const id = item.ticket_id ?? item.work_order_id;
  return (
    <tr className="border-b last:border-0">
      <td className="py-2 pr-4">
        <div className="flex items-center gap-2">
          <Wrench className="h-4 w-4 text-muted-foreground shrink-0" />
          <span className="text-sm font-medium">
            {item.kind === "open_ticket" ? "Open Ticket" : "Work Order"}
          </span>
        </div>
      </td>
      <td className="py-2 pr-4 text-sm text-muted-foreground">
        {item.title ?? item.subject ?? id ?? "—"}
      </td>
      <td className="py-2 pr-4 text-sm">
        {item.updated_at ? fmtDate(item.updated_at) : "—"}
      </td>
      <td className="py-2 text-sm">
        {item.status ? <Badge variant="outline">{item.status}</Badge> : "—"}
      </td>
      <td className="py-2 pl-4 text-sm">
        {item.priority ? <Badge variant="secondary">{item.priority}</Badge> : "—"}
      </td>
      <td className="py-2 pl-4 text-sm">
        {id ? (
          <Link
            to={item.ticket_id ? `/tickets?id=${item.ticket_id}` : `/property/work-orders/${id}`}
            className="text-primary hover:underline"
          >
            View
          </Link>
        ) : "—"}
      </td>
    </tr>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────────

export default function PortfolioDashboardPage() {
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const canEdit = role === "admin" || role === "root";

  const [policyOpen, setPolicyOpen] = useState(false);

  // Year/month navigation for snapshot
  const now = new Date();
  const [snapYear, setSnapYear] = useState(now.getFullYear());
  const [snapMonth, setSnapMonth] = useState(now.getMonth() + 1); // 1-indexed

  function prevMonth() {
    if (snapMonth === 1) { setSnapYear(y => y - 1); setSnapMonth(12); }
    else setSnapMonth(m => m - 1);
  }

  function nextMonth() {
    const isCurrentOrFuture = snapYear > now.getFullYear() ||
      (snapYear === now.getFullYear() && snapMonth >= now.getMonth() + 1);
    if (isCurrentOrFuture) return;
    if (snapMonth === 12) { setSnapYear(y => y + 1); setSnapMonth(1); }
    else setSnapMonth(m => m + 1);
  }

  // ── Queries ──────────────────────────────────────────────────────────────

  const notEnabledOpts = {
    retry: (count: number, err: unknown) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  };

  const kpisQuery = useQuery({
    queryKey: ["property", "kpis"],
    queryFn: getPortfolioKpis,
    refetchInterval: 60_000,
    ...notEnabledOpts,
  });

  const snapshotQuery = useQuery({
    queryKey: ["property", "rent-snapshot", snapYear, snapMonth],
    queryFn: () => getRentSnapshot(snapYear, snapMonth),
    ...notEnabledOpts,
  });

  const priorityQuery = useQuery({
    queryKey: ["property", "priority-items"],
    queryFn: () => getPriorityItems(20),
    ...notEnabledOpts,
  });

  // ── Detect flag-off ───────────────────────────────────────────────────────

  const isDisabled =
    (kpisQuery.isError && kpisQuery.error instanceof ApiError && kpisQuery.error.status === 404) ||
    (kpisQuery.isError && kpisQuery.error instanceof ApiError && kpisQuery.error.status === 503);

  if (isDisabled) {
    return <FeatureDisabled />;
  }

  // ── KPI values ────────────────────────────────────────────────────────────

  const kpis = kpisQuery.data;
  const kpisLoading = kpisQuery.isLoading;

  const occupancyPct = kpis
    ? `${(kpis.occupancy_rate * 100).toFixed(1)}%`
    : "—";

  // ── Snapshot chart data ───────────────────────────────────────────────────

  const snap = snapshotQuery.data;
  const chartData = snap
    ? [
        { name: "Charged", value: snap.charged_cents / 100 },
        { name: "Collected", value: snap.collected_cents / 100 },
        { name: "Outstanding", value: snap.outstanding_cents / 100 },
        { name: "Overdue", value: snap.overdue_cents / 100 },
      ]
    : [];

  // ── Priority items ────────────────────────────────────────────────────────

  const items = priorityQuery.data?.items ?? [];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Portfolio Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Landlord overview — occupancy, rent, leases &amp; work orders
          </p>
        </div>
        {canEdit && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPolicyOpen(true)}
            className="gap-2"
          >
            <Settings className="h-4 w-4" />
            Rent Policy
          </Button>
        )}
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Occupancy Rate"
          value={kpis ? `${occupancyPct} (${kpis.occupied_units}/${kpis.unit_count})` : "—"}
          icon={<Building className="h-4 w-4" />}
          loading={kpisLoading}
        />
        <KpiCard
          title="Active Leases"
          value={kpis ? String(kpis.active_lease_count) : "—"}
          icon={<FileText className="h-4 w-4" />}
          loading={kpisLoading}
        />
        <KpiCard
          title="Outstanding Rent"
          value={kpis ? formatCents(kpis.outstanding_rent_cents) : "—"}
          icon={<DollarSign className="h-4 w-4" />}
          loading={kpisLoading}
        />
        <KpiCard
          title="Open Work Orders"
          value={kpis ? String(kpis.open_work_order_count) : "—"}
          icon={<Wrench className="h-4 w-4" />}
          loading={kpisLoading}
        />
      </div>

      {/* Monthly rent snapshot */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Monthly Rent Snapshot</CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={prevMonth}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm font-medium w-24 text-center">
                {MONTH_NAMES[snapMonth - 1]} {snapYear}
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={nextMonth}
                disabled={
                  snapYear === now.getFullYear() && snapMonth === now.getMonth() + 1
                }
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {snapshotQuery.isLoading && (
            <div className="flex items-center justify-center h-48">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          )}
          {snapshotQuery.isError && (
            <p className="text-sm text-muted-foreground text-center py-8">
              {snapshotQuery.error instanceof ApiError && snapshotQuery.error.status === 404
                ? "No data available"
                : "Failed to load snapshot"}
            </p>
          )}
          {snap && (
            <div className="space-y-4">
              {/* Summary row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: "Charged", cents: snap.charged_cents, color: "text-foreground" },
                  { label: "Collected", cents: snap.collected_cents, color: "text-green-600" },
                  { label: "Outstanding", cents: snap.outstanding_cents, color: "text-amber-600" },
                  { label: "Overdue", cents: snap.overdue_cents, color: "text-red-600" },
                ].map(({ label, cents, color }) => (
                  <div key={label} className="rounded-lg border p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1">{label}</p>
                    <p className={`text-lg font-semibold ${color}`}>
                      {formatCents(cents)}
                    </p>
                  </div>
                ))}
              </div>

              {/* Bar chart */}
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                    <YAxis
                      tickFormatter={(v: number) => `$${v.toLocaleString()}`}
                      tick={{ fontSize: 11 }}
                    />
                    <Tooltip
                      formatter={(v: unknown) => [`$${(v as number).toLocaleString()}`, ""]}
                    />
                    <Legend />
                    <Bar dataKey="value" name="Amount ($)" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {snap.overdue_cents > 0 && (
                <p className="text-xs text-red-600">
                  Overdue as of day {snap.rent_due_day} + {snap.grace_period_days} grace days
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Priority items */}
      <Card>
        <CardHeader>
          <CardTitle>Priority Items</CardTitle>
        </CardHeader>
        <CardContent>
          {priorityQuery.isLoading && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          )}
          {priorityQuery.isError && (
            <p className="text-sm text-muted-foreground py-4 text-center">
              {priorityQuery.error instanceof ApiError && priorityQuery.error.status === 404
                ? "No priority data available"
                : "Failed to load priority items"}
            </p>
          )}
          {!priorityQuery.isLoading && !priorityQuery.isError && items.length === 0 && (
            <p className="text-sm text-muted-foreground py-8 text-center">
              No priority items — all caught up!
            </p>
          )}
          {items.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b text-left">
                    <th className="pb-2 pr-4 text-xs font-medium text-muted-foreground">Type</th>
                    <th className="pb-2 pr-4 text-xs font-medium text-muted-foreground">Identifier</th>
                    <th className="pb-2 pr-4 text-xs font-medium text-muted-foreground">Date</th>
                    <th className="pb-2 text-xs font-medium text-muted-foreground">Status</th>
                    <th className="pb-2 pl-4 text-xs font-medium text-muted-foreground">Extra</th>
                    <th className="pb-2 pl-4 text-xs font-medium text-muted-foreground"></th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item, idx) => (
                    <PriorityRow key={`${item.kind}-${item.lease_id ?? item.ticket_id ?? item.work_order_id ?? idx}`} item={item} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Rent-policy dialog (admin/root only) */}
      {canEdit && (
        <RentPolicyDialog
          open={policyOpen}
          onClose={() => setPolicyOpen(false)}
        />
      )}
    </div>
  );
}
