import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Loader2, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { useAuthStore } from "@/stores/authStore";
import {
  listCreatorSubscribers,
  getCreatorSubscriptionAnalytics,
  removeCreatorSubscriber,
  stopCreatorSubscriberRenewal,
  type CreatorSubscriberRow,
} from "@/api/endpoints/subscriptions";

// SUBX-41 — web creator "Subscribers & MRR" console (parity with the Android screen).
// Owner-scoped: the signed-in creator is the X-User-Id AND the creator-id path. Wires the
// E4 endpoints (subscribers list + MRR/analytics incl. the SUBX-43 per-tier breakdown) and
// the reconciled remove / stop-renewal actions. Resolves the E5 /subscriptions/subscribers
// deep-link that previously 404'd on web.

function formatPrice(cents: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function formatDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

const STATUS_FILTERS: Array<{ label: string; value?: string }> = [
  { label: "All" },
  { label: "Active", value: "active" },
  { label: "Trialing", value: "trialing" },
  { label: "Past due", value: "past_due" },
  { label: "Canceled", value: "canceled" },
];

export default function CreatorSubscribers() {
  const creatorId = useAuthStore((s) => s.userId) ?? "";
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined);
  const [planFilter, setPlanFilter] = useState<string | undefined>(undefined);
  const [pendingRemove, setPendingRemove] = useState<CreatorSubscriberRow | null>(null);

  const analyticsQuery = useQuery({
    queryKey: ["creator-sub-analytics", creatorId],
    queryFn: () => getCreatorSubscriptionAnalytics(creatorId),
    enabled: !!creatorId,
  });

  const listQuery = useQuery({
    queryKey: ["creator-subscribers", creatorId, statusFilter, planFilter],
    queryFn: () => listCreatorSubscribers(creatorId, { status: statusFilter, plan_id: planFilter }),
    enabled: !!creatorId,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["creator-subscribers", creatorId] });
    queryClient.invalidateQueries({ queryKey: ["creator-sub-analytics", creatorId] });
  };

  const removeMutation = useMutation({
    mutationFn: (subId: string) => removeCreatorSubscriber(creatorId, subId, "creator_removed"),
    onSuccess: () => { toast.success("Subscriber removed and refunded."); invalidate(); },
    onError: () => toast.error("Could not remove this subscriber."),
  });

  const stopMutation = useMutation({
    mutationFn: (subId: string) => stopCreatorSubscriberRenewal(creatorId, subId, "creator_stop_renewal"),
    onSuccess: () => { toast.success("Auto-renewal stopped."); invalidate(); },
    onError: () => toast.error("Could not stop renewal."),
  });

  const a = analyticsQuery.data;
  const currency = a?.currency?.toUpperCase() ?? "USD";
  const tiers = a?.by_tier ?? [];

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4">
      <div className="flex items-center gap-2">
        <Users className="h-5 w-5" />
        <h1 className="text-2xl font-semibold">Subscribers &amp; MRR</h1>
      </div>

      {/* Analytics */}
      {analyticsQuery.isLoading ? (
        <Skeleton className="h-28 w-full" />
      ) : a ? (
        <Card>
          <CardHeader><CardTitle>Overview</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label="Active" value={String(a.active_subscribers)} />
            <Stat label="MRR" value={formatPrice(a.mrr_cents, currency)} />
            <Stat label="ARPU" value={formatPrice(a.arpu_cents, currency)} />
            <Stat label="Churn" value={`${Math.round(a.churn_rate * 100)}%`} />
            <Stat label="Trialing" value={String(a.trialing)} />
            <Stat label="Past due" value={String(a.past_due)} />
            {a.past_due_mrr_cents > 0 && (
              <Stat label="Past-due MRR" value={formatPrice(a.past_due_mrr_cents, currency)} />
            )}
            <Stat label="Net to date" value={formatPrice(a.net_revenue_to_date_cents, currency)} />
          </CardContent>
        </Card>
      ) : null}

      {/* Per-tier breakdown (SUBX-43 C8) */}
      {tiers.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Revenue by tier</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {tiers.map((t) => (
              <div key={t.plan_id ?? "none"} className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                <div className="font-medium">{t.plan_name ?? "Subscription"}</div>
                <div className="text-sm text-muted-foreground">
                  {t.active_subscribers} active · MRR {formatPrice(t.mrr_cents, currency)} · Net {formatPrice(t.net_revenue_to_date_cents, currency)}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        {STATUS_FILTERS.map((f) => (
          <Button
            key={f.label}
            size="sm"
            variant={statusFilter === f.value ? "default" : "outline"}
            onClick={() => setStatusFilter(f.value)}
          >
            {f.label}
          </Button>
        ))}
        {tiers.filter((t) => t.plan_id).length > 0 && (
          <span className="mx-1 self-center text-muted-foreground">|</span>
        )}
        <Button size="sm" variant={!planFilter ? "default" : "outline"} onClick={() => setPlanFilter(undefined)}>
          All tiers
        </Button>
        {tiers.filter((t) => t.plan_id).map((t) => (
          <Button
            key={t.plan_id}
            size="sm"
            variant={planFilter === t.plan_id ? "default" : "outline"}
            onClick={() => setPlanFilter(t.plan_id ?? undefined)}
          >
            {t.plan_name ?? t.plan_id}
          </Button>
        ))}
      </div>

      {/* Subscriber list */}
      {listQuery.isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : !listQuery.data || listQuery.data.subscribers.length === 0 ? (
        <EmptyState icon={<Users className="h-8 w-8" />} title="No subscribers" description="When people subscribe to your tiers they'll appear here." />
      ) : (
        <div className="space-y-3">
          {listQuery.data.subscribers.map((row) => (
            <Card key={row.subscription_id}>
              <CardContent className="flex flex-col gap-2 p-4">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{row.subscriber_name || row.subscriber_id}</span>
                  <StatusBadge className="capitalize">{row.status.replace(/_/g, " ")}</StatusBadge>
                </div>
                <div className="text-sm text-muted-foreground">
                  {row.plan_name ?? "Subscription"} · {formatPrice(row.price_cents, row.currency)} · since {formatDate(row.since)}
                  {row.is_gift && " · gift"}
                  {row.is_trial && " · trial"}
                </div>
                <div className="text-sm">Next billing: {formatDate(row.next_billing_date ?? row.current_period_end)}</div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={stopMutation.isPending}
                    onClick={() => stopMutation.mutate(row.subscription_id)}
                  >
                    {stopMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Stop renewal"}
                  </Button>
                  <Button size="sm" variant="destructive" onClick={() => setPendingRemove(row)}>
                    Remove &amp; refund
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={pendingRemove !== null}
        onOpenChange={(open) => { if (!open) setPendingRemove(null); }}
        title="Remove subscriber?"
        description={`${pendingRemove?.subscriber_name || pendingRemove?.subscriber_id || "This subscriber"} loses access now and is refunded the unused portion of their cycle.`}
        confirmLabel="Remove"
        onConfirm={() => {
          if (pendingRemove) removeMutation.mutate(pendingRemove.subscription_id);
          setPendingRemove(null);
        }}
      />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-muted p-3">
      <div className="text-lg font-semibold">{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
