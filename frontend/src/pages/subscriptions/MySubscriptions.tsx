import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  CreditCard,
  ChevronDown,
  ChevronUp,
  Loader2,
  Play,
  Pause,
  XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  listSubscriptions,
  getSubscriptionSummary,
  listInvoices,
  cancelSubscription,
  resumeSubscription,
} from "@/api/endpoints/subscriptions";
import type { SubscriptionOut, SubscriptionSummary, SubscriptionInvoice } from "@/api/types";

// ─── Helpers ──────────────────────────────────────────────────

function formatPrice(cents: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function statusVariant(status: string) {
  switch (status) {
    case "active":
      return "success" as const;
    case "trialing":
      return "info" as const;
    case "canceling":
      return "warning" as const;
    case "canceled":
      return "neutral" as const;
    case "past_due":
      return "danger" as const;
    default:
      return "info" as const;
  }
}

// ─── Invoice List ───────────────────────────────────────────────

function InvoiceList({ subId }: { subId: string }) {
  const { data: invoices, isLoading } = useQuery({
    queryKey: ["subscriptions", subId, "invoices"],
    queryFn: () => listInvoices(subId),
  });

  if (isLoading) {
    return (
      <div className="space-y-2 pt-2">
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    );
  }

  const items: SubscriptionInvoice[] = invoices ?? [];

  if (items.length === 0) {
    return <p className="py-2 text-xs text-muted-foreground">No invoices yet.</p>;
  }

  return (
    <div className="mt-2 border-t pt-2">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-muted-foreground">
            <th className="pb-1 text-left font-medium">Period</th>
            <th className="pb-1 text-left font-medium">Amount</th>
            <th className="pb-1 text-left font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map((inv) => (
            <tr key={inv.invoice_id} className="border-t border-border/50">
              <td className="py-1">
                {formatDate(inv.period_start)} — {formatDate(inv.period_end)}
              </td>
              <td className="py-1">
                {formatPrice(inv.amount_cents, inv.currency)}
                {inv.is_proration && (
                  <span className="ml-1 text-muted-foreground">(proration)</span>
                )}
              </td>
              <td className="py-1 capitalize">{inv.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Summary Row ────────────────────────────────────────────────

function SummaryRow({ subId }: { subId: string }) {
  const { data: summary } = useQuery({
    queryKey: ["subscriptions", subId, "summary"],
    queryFn: () => getSubscriptionSummary(subId),
  });

  if (!summary) return null;

  const s: SubscriptionSummary = summary;

  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
      <div>
        <dt className="text-muted-foreground">Total Paid</dt>
        <dd className="font-medium">{formatPrice(s.total_paid_cents, s.currency)}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground">Next Amount</dt>
        <dd className="font-medium">{formatPrice(s.next_amount_cents, s.currency)}</dd>
      </div>
      {s.next_renewal_at && (
        <div>
          <dt className="text-muted-foreground">Next Renewal</dt>
          <dd className="font-medium">{formatDate(s.next_renewal_at)}</dd>
        </div>
      )}
      {s.last_invoice_at && (
        <div>
          <dt className="text-muted-foreground">Last Invoice</dt>
          <dd className="font-medium">{formatDate(s.last_invoice_at)}</dd>
        </div>
      )}
    </dl>
  );
}

// ─── Subscription Card ──────────────────────────────────────────

function SubscriptionCard({ sub }: { sub: SubscriptionOut }) {
  const queryClient = useQueryClient();
  const [invoicesOpen, setInvoicesOpen] = useState(false);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);

  const canCancel = sub.status === "active" || sub.status === "trialing";
  const canResume = sub.status === "canceling" || sub.status === "canceled";

  const cancelMut = useMutation({
    mutationFn: () =>
      cancelSubscription(sub.subscription_id, { cancel_at_period_end: true }),
    onSuccess: () => {
      toast.success("Subscription will be cancelled at period end");
      void queryClient.invalidateQueries({ queryKey: ["subscriptions"] });
      setCancelDialogOpen(false);
    },
    onError: () => toast.error("Failed to cancel subscription"),
  });

  const resumeMut = useMutation({
    mutationFn: () => resumeSubscription(sub.subscription_id),
    onSuccess: () => {
      toast.success("Subscription resumed");
      void queryClient.invalidateQueries({ queryKey: ["subscriptions"] });
    },
    onError: () => toast.error("Failed to resume subscription"),
  });

  return (
    <>
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{sub.plan?.name ?? sub.plan_id}</CardTitle>
            <StatusBadge variant={statusVariant(sub.status)} className="capitalize">
              {sub.status}
            </StatusBadge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Price / billing info */}
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold">
              {formatPrice(sub.price_cents, sub.currency)}
            </span>
            <span className="text-sm text-muted-foreground">/ {sub.interval}</span>
          </div>

          {/* Key dates */}
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">Started</dt>
              <dd>{formatDate(sub.start_at)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Period Ends</dt>
              <dd>{formatDate(sub.current_period_end)}</dd>
            </div>
            {sub.trial_end && (
              <div>
                <dt className="text-muted-foreground">Trial Ends</dt>
                <dd>{formatDate(sub.trial_end)}</dd>
              </div>
            )}
          </dl>

          {sub.cancel_at_period_end && (
            <p className="text-xs text-warning">
              Will be cancelled on {formatDate(sub.current_period_end)}
            </p>
          )}

          {/* Summary */}
          <SummaryRow subId={sub.subscription_id} />

          {/* Actions */}
          <div className="flex flex-wrap gap-2 pt-1">
            {canResume && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => resumeMut.mutate()}
                disabled={resumeMut.isPending}
              >
                {resumeMut.isPending ? (
                  <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                ) : (
                  <Play className="mr-1.5 h-4 w-4" />
                )}
                Resume
              </Button>
            )}
            {canCancel && (
              <Button
                size="sm"
                variant="destructive"
                onClick={() => setCancelDialogOpen(true)}
              >
                {sub.cancel_at_period_end ? (
                  <>
                    <XCircle className="mr-1.5 h-4 w-4" />
                    Cancel Now
                  </>
                ) : (
                  <>
                    <Pause className="mr-1.5 h-4 w-4" />
                    Cancel
                  </>
                )}
              </Button>
            )}

            {/* Invoices toggle */}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setInvoicesOpen(!invoicesOpen)}
            >
              {invoicesOpen ? (
                <>
                  <ChevronUp className="mr-1 h-4 w-4" /> Hide Invoices
                </>
              ) : (
                <>
                  <ChevronDown className="mr-1 h-4 w-4" /> Invoices
                </>
              )}
            </Button>
          </div>

          {/* Expandable invoices */}
          {invoicesOpen && <InvoiceList subId={sub.subscription_id} />}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={cancelDialogOpen}
        onOpenChange={setCancelDialogOpen}
        title="Cancel Subscription"
        description="Your subscription will remain active until the end of the current billing period. You can resume at any time before then."
        confirmLabel="Cancel Subscription"
        variant="danger"
        onConfirm={() => cancelMut.mutate()}
        loading={cancelMut.isPending}
      />
    </>
  );
}

// ─── Main Component ─────────────────────────────────────────────

export function MySubscriptions() {
  const { data: subscriptions, isLoading } = useQuery({
    queryKey: ["subscriptions"],
    queryFn: () => listSubscriptions(),
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-48 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  const subs: SubscriptionOut[] = subscriptions ?? [];

  if (subs.length === 0) {
    return (
      <EmptyState
        icon={<CreditCard className="h-8 w-8" />}
        title="No subscriptions"
        description="You don't have any active subscriptions yet."
      />
    );
  }

  return (
    <div className="space-y-4">
      {subs.map((sub) => (
        <SubscriptionCard key={sub.subscription_id} sub={sub} />
      ))}
    </div>
  );
}
