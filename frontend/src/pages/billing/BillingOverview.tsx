import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  DollarSign,
  CreditCard,
  ArrowRight,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { getBalance, getSettings, getConfig, setAutopay, payBalance } from "@/api/endpoints/billing";
import {
  getPaymentIssues,
  confirmAndRetryCharge,
  retryAutomaticPayment,
  setDefaultAndRetryAutomaticPayment,
  getPaymentMethods,
  type PaymentIssue,
} from "@/api/endpoints/billing";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { useState } from "react";

function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

interface BillingOverviewProps {
  onTabChange?: (tab: string) => void;
}

export function BillingOverview({ onTabChange }: BillingOverviewProps) {
  const queryClient = useQueryClient();
  const [payOpen, setPayOpen] = useState(false);
  const [retryOpen, setRetryOpen] = useState(false);
  const [retryResult, setRetryResult] = useState<{ ok: boolean; code: string; message: string } | null>(null);
  const [resolvedIssueIds, setResolvedIssueIds] = useState<string[]>([]);
  const [methodConfirmed, setMethodConfirmed] = useState(false);
  const [selectedMethodId, setSelectedMethodId] = useState<string>("");
  const [autoRetryResult, setAutoRetryResult] = useState<{ ok: boolean; code: string; message: string } | null>(null);

  const balanceQuery = useQuery({
    queryKey: ["billing", "balance"],
    queryFn: getBalance,
  });

  const settingsQuery = useQuery({
    queryKey: ["billing", "settings"],
    queryFn: getSettings,
  });

  const configQuery = useQuery({
    queryKey: ["billing", "config"],
    queryFn: getConfig,
  });

  const paymentIssuesQuery = useQuery({
    queryKey: ["billing", "payment-issues"],
    queryFn: () => getPaymentIssues(50),
  });

  const paymentMethodsQuery = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
  });

  const autopayMutation = useMutation({
    mutationFn: (enabled: boolean) => setAutopay({ enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["billing", "settings"] });
      toast.success("Autopay setting updated");
    },
    onError: () => {
      toast.error("Failed to update autopay");
    },
  });

  const payMutation = useMutation({
    mutationFn: () => payBalance({}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["billing", "balance"] });
      setPayOpen(false);
      toast.success("Payment submitted");
    },
    onError: () => {
      toast.error("Payment failed");
    },
  });

  const retryMutation = useMutation({
    mutationFn: (issueId: string) => confirmAndRetryCharge(issueId),
    onSuccess: (result) => {
      setRetryResult(result);
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-issues"] });
      queryClient.invalidateQueries({ queryKey: ["billing", "balance"] });
      if (result.ok) {
        toast.success("Retry requested");
      } else {
        toast.error("Retry could not be completed");
      }
    },
    onError: () => {
      setRetryResult({ ok: false, code: "request_failed", message: "Unable to process retry request." });
      toast.error("Retry failed");
    },
  });

  const autoRetryMutation = useMutation({
    mutationFn: (input: { issueId: string; paymentMethodId?: string }) => {
      if (input.paymentMethodId) {
        return setDefaultAndRetryAutomaticPayment(input.paymentMethodId, input.issueId);
      }
      return retryAutomaticPayment(input.issueId);
    },
    onSuccess: (result, input) => {
      setAutoRetryResult(result);
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-issues"] });
      if (result.ok) {
        setResolvedIssueIds((prev) => [...prev, input.issueId]);
        toast.success("Automatic payment retry submitted");
      } else {
        toast.error("Automatic retry failed");
      }
    },
    onError: () => {
      setAutoRetryResult({ ok: false, code: "request_failed", message: "Unable to process automatic retry." });
      toast.error("Automatic retry failed");
    },
  });

  const balance = balanceQuery.data;
  const settings = settingsQuery.data;
  const config = configQuery.data;

  const totalOwed = (balance?.owed_settled_cents ?? 0) + (balance?.owed_pending_cents ?? 0);
  const totalPayments = (balance?.payments_settled_cents ?? 0) + (balance?.payments_pending_cents ?? 0);
  const netBalance = totalPayments - totalOwed;

  const isLoading = balanceQuery.isLoading || settingsQuery.isLoading;
  const paymentIssues = (paymentIssuesQuery.data?.items ?? []).filter((issue) => !resolvedIssueIds.includes(issue.incident_id));
  const immediateIssue: PaymentIssue | null = paymentIssues.find((issue) => {
    const action = String(issue.customer_action_type || "");
    const status = String(issue.status || "");
    return Boolean(issue.requires_customer_action) && (
      action === "confirm" || action === "retry" || status === "customer_action_required" || status === "ready_to_retry"
    );
  }) ?? null;
  const autoPaymentIssue: PaymentIssue | null = paymentIssues.find((issue) => {
    const action = String(issue.customer_action_type || "");
    return Boolean(issue.requires_customer_action) && action === "update_method";
  }) ?? null;
  const repeatedFailure = ((autoPaymentIssue?.retry_attempts?.length ?? 0) >= 2) || autoRetryResult?.ok === false;
  const availableMethods = paymentMethodsQuery.data ?? [];
  const retryEnabled = Boolean(autoPaymentIssue && methodConfirmed && selectedMethodId && !autoRetryMutation.isPending);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-40 w-full rounded-xl" />
        <div className="grid gap-4 sm:grid-cols-2">
          <Skeleton className="h-24 rounded-xl" />
          <Skeleton className="h-24 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {immediateIssue && (
        <Card className="border-orange-300 bg-orange-50/60 dark:border-orange-900 dark:bg-orange-950/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Payment issue needs confirmation</CardTitle>
            <CardDescription>
              We couldn&apos;t complete a recent charge. Confirm to retry immediately.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm text-muted-foreground">
              Issue <span className="font-mono">{immediateIssue.incident_id}</span> • {immediateIssue.provider || "provider"} • {immediateIssue.status}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => { setRetryResult(null); setRetryOpen(true); }}>
                Confirm and Retry Charge
              </Button>
              <Button variant="outline" onClick={() => onTabChange?.("methods")}>
                Review payment methods
              </Button>
            </div>
            {retryResult && (
              <div className={cn("rounded-md border p-2 text-sm", retryResult.ok ? "border-emerald-300 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/30" : "border-destructive/30 bg-destructive/10")}>
                {retryResult.ok
                  ? "Retry submitted successfully. We’ll update this page when payment state changes."
                  : "Retry did not complete. Please verify your payment method and try again."}
                <span className="ml-1 text-xs text-muted-foreground">({retryResult.code})</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {autoPaymentIssue && (
        <Card className="border-blue-300 bg-blue-50/60 dark:border-blue-900 dark:bg-blue-950/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Automatic payment needs a method fix</CardTitle>
            <CardDescription>
              Update/confirm a valid payment method, then retry automatic payment.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm text-muted-foreground">
              Issue <span className="font-mono">{autoPaymentIssue.incident_id}</span> • {autoPaymentIssue.provider || "provider"} • {autoPaymentIssue.status}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={() => onTabChange?.("methods")}>
                Fix payment method
              </Button>
            </div>

            <div className="space-y-2 rounded-md border p-3">
              <label className="text-sm font-medium" htmlFor="retry-method-select">Payment method to use</label>
              <select
                id="retry-method-select"
                className="h-9 w-full rounded-md border bg-background px-3 text-sm"
                value={selectedMethodId}
                onChange={(e) => setSelectedMethodId(e.target.value)}
              >
                <option value="">Select method…</option>
                {availableMethods.map((pm) => (
                  <option key={pm.payment_method_id} value={pm.payment_method_id}>
                    {pm.label || pm.payment_method_id}
                  </option>
                ))}
              </select>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={methodConfirmed}
                  onChange={(e) => setMethodConfirmed(e.target.checked)}
                />
                I updated/confirmed this payment method
              </label>
              <Button
                onClick={() => autoRetryMutation.mutate({ issueId: autoPaymentIssue.incident_id, paymentMethodId: selectedMethodId || undefined })}
                disabled={!retryEnabled}
              >
                Retry automatic payment
              </Button>
            </div>

            {autoRetryResult && (
              <div className={cn("rounded-md border p-2 text-sm", autoRetryResult.ok ? "border-emerald-300 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/30" : "border-destructive/30 bg-destructive/10")}>
                {autoRetryResult.ok
                  ? "Automatic retry submitted. This issue has been removed from your active queue."
                  : "Automatic retry failed again. Please verify card details, contact your bank, or use a different payment method."}
                <span className="ml-1 text-xs text-muted-foreground">({autoRetryResult.code})</span>
              </div>
            )}

            {repeatedFailure && (
              <div className="rounded-md border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
                We still can&apos;t process automatic payment. Please switch to another method or contact support if this persists.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Balance card */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <DollarSign className="h-5 w-5" />
            Account Balance
          </CardTitle>
          <CardDescription>
            Current billing balance as of{" "}
            {balance?.updated_at
              ? new Date(balance.updated_at * 1000).toLocaleDateString()
              : "now"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end justify-between">
            <div>
              <p
                className={cn(
                  "text-4xl font-bold tracking-tight",
                  netBalance >= 0 ? "text-green-600 dark:text-green-400" : "text-destructive",
                )}
              >
                {formatCents(Math.abs(netBalance), balance?.currency)}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {netBalance >= 0 ? "Credit" : "Amount owed"}
              </p>
            </div>
            {totalOwed > 0 && (
              <Button onClick={() => setPayOpen(true)}>
                Pay Balance
              </Button>
            )}
          </div>

          <Separator className="my-4" />

          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <p className="text-xs text-muted-foreground">Owed (Settled)</p>
              <p className="text-sm font-medium text-destructive">
                {formatCents(balance?.owed_settled_cents ?? 0, balance?.currency)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Owed (Pending)</p>
              <p className="text-sm font-medium text-orange-600 dark:text-orange-400">
                {formatCents(balance?.owed_pending_cents ?? 0, balance?.currency)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Payments (Settled)</p>
              <p className="text-sm font-medium text-green-600 dark:text-green-400">
                {formatCents(balance?.payments_settled_cents ?? 0, balance?.currency)}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Autopay + Config */}
      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Zap className="h-4 w-4" />
              Autopay
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <Label htmlFor="autopay-toggle" className="text-sm">
                Automatically pay outstanding balance
              </Label>
              <Switch
                id="autopay-toggle"
                checked={settings?.autopay_enabled ?? false}
                onCheckedChange={(checked) => autopayMutation.mutate(checked)}
                disabled={autopayMutation.isPending}
              />
            </div>
            {settings?.default_payment_method_id && (
              <p className="mt-2 text-xs text-muted-foreground">
                Using default payment method
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <CreditCard className="h-4 w-4" />
              Billing Config
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Currency</span>
                <span className="font-medium uppercase">{config?.currency ?? settings?.currency ?? "USD"}</span>
              </div>
              {config?.publishable_key && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Stripe</span>
                  <span className="font-mono text-xs">
                    {config.publishable_key.slice(0, 12)}...
                  </span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick links */}
      <Card>
        <CardContent className="py-4">
          <div className="grid gap-2 sm:grid-cols-3">
            {[
              { label: "Payment Methods", tab: "methods" },
              { label: "Transaction Ledger", tab: "ledger" },
              { label: "Subscriptions", tab: "subscriptions" },
            ].map((link) => (
              <button
                key={link.tab}
                className="flex items-center justify-between rounded-lg border px-4 py-3 text-sm font-medium transition-colors hover:bg-accent"
                onClick={() => onTabChange?.(link.tab)}
              >
                {link.label}
                <ArrowRight className="h-4 w-4 text-muted-foreground" />
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Pay balance confirmation */}
      <ConfirmDialog
        open={payOpen}
        onOpenChange={setPayOpen}
        title="Pay Balance"
        description={`Pay the outstanding balance of ${formatCents(totalOwed, balance?.currency)}?`}
        confirmLabel="Pay Now"
        onConfirm={() => payMutation.mutate()}
        loading={payMutation.isPending}
      />

      <ConfirmDialog
        open={retryOpen}
        onOpenChange={setRetryOpen}
        title="Confirm and Retry Charge"
        description="We will retry your failed payment immediately using your current billing settings."
        confirmLabel="Retry Charge"
        onConfirm={() => {
          if (!immediateIssue) return;
          retryMutation.mutate(immediateIssue.incident_id);
          setRetryOpen(false);
        }}
        loading={retryMutation.isPending}
      />
    </div>
  );
}
