// Cash (USD) — the fiat on/off-ramp for the trading & custody area.
//
// This surface REUSES the existing billing wallet rails end-to-end:
//   getWallet / depositToWallet / withdrawFromWallet / getPaymentMethods
// (frontend/src/api/endpoints/billing.ts). It does NOT introduce a new
// on-ramp. The billing USD wallet IS the trading/margin/fees cash source
// (see fees.ts: pay_with "USD" = fiat wallet), so there is no separate
// custody USD balance to bridge — that relationship is stated in copy.
import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Banknote,
  ArrowDownToLine,
  ArrowUpFromLine,
  Info,
  AlertTriangle,
  CreditCard,
} from "lucide-react";
import { toast } from "sonner";

import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getWallet,
  depositToWallet,
  withdrawFromWallet,
  getPaymentMethods,
} from "@/api/endpoints/billing";
import {
  formatCents,
  validateDeposit,
  validateWithdraw,
} from "@/lib/cashMath";

export default function CustodyCashPage() {
  const qc = useQueryClient();

  const {
    data: wallet,
    isLoading: walletLoading,
    error: walletError,
  } = useQuery({
    queryKey: ["billing", "wallet"],
    queryFn: getWallet,
    retry: false,
  });

  const { data: methods = [] } = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    retry: false,
  });

  const balanceCents = wallet?.wallet_balance_cents ?? 0;
  const currency = (wallet?.currency ?? "usd").toUpperCase();

  // Honest degrade-on-404: the wallet read is expected live, but if the
  // billing backend isn't reachable we show an "unavailable" state.
  const walletUnavailable =
    walletError instanceof ApiError && walletError.status === 404;

  // ── Deposit ────────────────────────────────────────────────────────────
  const [depositDollars, setDepositDollars] = useState("");
  const [depositPmId, setDepositPmId] = useState<string>("");
  const [showDepositConfirm, setShowDepositConfirm] = useState(false);

  const depositCheck = validateDeposit(depositDollars);

  const depositMut = useMutation({
    mutationFn: () =>
      depositToWallet({
        amount_cents: depositCheck.cents,
        payment_method_id: depositPmId || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["billing", "wallet"] });
      toast.success(`Added ${formatCents(depositCheck.cents)} to your cash balance`);
      setDepositDollars("");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Deposit failed");
    },
  });

  // ── Withdraw ───────────────────────────────────────────────────────────
  const [withdrawDollars, setWithdrawDollars] = useState("");
  const [showWithdrawConfirm, setShowWithdrawConfirm] = useState(false);

  const withdrawCheck = validateWithdraw(withdrawDollars, balanceCents);

  const withdrawMut = useMutation({
    mutationFn: () => withdrawFromWallet({ amount_cents: withdrawCheck.cents }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["billing", "wallet"] });
      toast.success(`Withdrew ${formatCents(withdrawCheck.cents)} from your cash balance`);
      setWithdrawDollars("");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Withdrawal failed");
    },
  });

  const noPaymentMethods = methods.length === 0;

  return (
    <div className="mx-auto w-full max-w-3xl p-4 md:p-6">
      {/* Header */}
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
          <Banknote className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight md:text-2xl">Cash (USD)</h1>
          <p className="text-sm text-muted-foreground">
            Your fiat balance for the trading account.
          </p>
        </div>
      </div>

      {walletUnavailable ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
              <AlertTriangle className="h-6 w-6" />
            </div>
            <p className="font-medium">Cash is unavailable</p>
            <p className="max-w-sm text-sm text-muted-foreground">
              Your USD wallet isn&apos;t reachable on this account yet. Try again
              later or open{" "}
              <Link to="/billing?tab=wallet" className="underline">
                Billing
              </Link>
              .
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {/* Balance */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Banknote className="h-5 w-5" />
                Cash balance
              </CardTitle>
              <CardDescription>
                Usable for trading, margin &amp; fees
              </CardDescription>
            </CardHeader>
            <CardContent>
              {walletLoading ? (
                <Skeleton className="h-10 w-40" />
              ) : (
                <p className="text-4xl font-bold">
                  {formatCents(balanceCents, currency)}
                </p>
              )}
              <div className="mt-3 flex items-start gap-2 rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
                <Info className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  This is your USD wallet — the same balance that funds your
                  trading account, margin and platform fees. Adding cash here
                  makes it immediately available to trade; there&apos;s no
                  separate transfer step.
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Deposit */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ArrowDownToLine className="h-5 w-5" />
                Add cash
              </CardTitle>
              <CardDescription>
                Charge a payment method to fund your trading cash balance
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="cash-deposit-amount">Amount (USD)</Label>
                <Input
                  id="cash-deposit-amount"
                  type="number"
                  min="1"
                  step="0.01"
                  placeholder="0.00"
                  value={depositDollars}
                  onChange={(e) => setDepositDollars(e.target.value)}
                />
                {depositDollars !== "" && !depositCheck.valid && (
                  <p className="text-xs text-destructive">{depositCheck.reason}</p>
                )}
              </div>

              {noPaymentMethods ? (
                <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
                  <CreditCard className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>
                    You don&apos;t have a payment method yet.{" "}
                    <Link
                      to="/billing?tab=methods"
                      className="font-medium underline"
                    >
                      Add a payment method
                    </Link>{" "}
                    to add cash.
                  </span>
                </div>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="cash-deposit-pm">Payment method</Label>
                  <Select value={depositPmId} onValueChange={setDepositPmId}>
                    <SelectTrigger id="cash-deposit-pm">
                      <SelectValue placeholder="Default payment method" />
                    </SelectTrigger>
                    <SelectContent>
                      {methods.map((pm) => (
                        <SelectItem
                          key={pm.payment_method_id}
                          value={pm.payment_method_id}
                        >
                          {pm.label ??
                            `${pm.brand ?? pm.method_type} ····${pm.last4}`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              <Button
                onClick={() => setShowDepositConfirm(true)}
                disabled={
                  !depositCheck.valid || noPaymentMethods || depositMut.isPending
                }
              >
                {depositMut.isPending ? "Adding…" : "Add cash"}
              </Button>
            </CardContent>
          </Card>

          {/* Withdraw */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ArrowUpFromLine className="h-5 w-5" />
                Withdraw cash
              </CardTitle>
              <CardDescription>
                Move cash out of your trading account back to your bank
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="cash-withdraw-amount">Amount (USD)</Label>
                <Input
                  id="cash-withdraw-amount"
                  type="number"
                  min="1"
                  step="0.01"
                  placeholder="0.00"
                  value={withdrawDollars}
                  onChange={(e) => setWithdrawDollars(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Available: {formatCents(balanceCents, currency)}
                </p>
                {withdrawDollars !== "" && !withdrawCheck.valid && (
                  <p className="text-xs text-destructive">{withdrawCheck.reason}</p>
                )}
              </div>
              <Button
                variant="outline"
                onClick={() => setShowWithdrawConfirm(true)}
                disabled={!withdrawCheck.valid || withdrawMut.isPending}
              >
                {withdrawMut.isPending ? "Withdrawing…" : "Withdraw"}
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Money-safety confirms */}
      <ConfirmDialog
        open={showDepositConfirm}
        onOpenChange={setShowDepositConfirm}
        title="Confirm deposit"
        description={`Charge your payment method and add ${formatCents(
          depositCheck.cents,
        )} to your trading cash balance?`}
        confirmLabel="Add cash"
        onConfirm={() => {
          setShowDepositConfirm(false);
          depositMut.mutate();
        }}
      />
      <ConfirmDialog
        open={showWithdrawConfirm}
        onOpenChange={setShowWithdrawConfirm}
        title="Confirm withdrawal"
        description={`Withdraw ${formatCents(
          withdrawCheck.cents,
        )} from your trading cash balance?`}
        confirmLabel="Withdraw"
        onConfirm={() => {
          setShowWithdrawConfirm(false);
          withdrawMut.mutate();
        }}
      />
    </div>
  );
}
