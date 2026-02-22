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

  const balance = balanceQuery.data;
  const settings = settingsQuery.data;
  const config = configQuery.data;

  const totalOwed = (balance?.owed_settled_cents ?? 0) + (balance?.owed_pending_cents ?? 0);
  const totalPayments = (balance?.payments_settled_cents ?? 0) + (balance?.payments_pending_cents ?? 0);
  const netBalance = totalPayments - totalOwed;

  const isLoading = balanceQuery.isLoading || settingsQuery.isLoading;

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
    </div>
  );
}
