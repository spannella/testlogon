import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Wallet as WalletIcon, ArrowDownToLine, ArrowUpFromLine } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { getWallet, depositToWallet, withdrawFromWallet, getPaymentMethods } from "@/api/endpoints/billing";

function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
}

function formatTs(ts?: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function Wallet() {
  const qc = useQueryClient();

  const { data: wallet, isLoading: walletLoading } = useQuery({
    queryKey: ["billing", "wallet"],
    queryFn: getWallet,
  });

  const { data: methods = [] } = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
  });

  // ── Deposit state ──────────────────────────────────────────────────────────
  const [depositDollars, setDepositDollars] = useState("");
  const [depositPmId, setDepositPmId] = useState<string>("");

  const depositMut = useMutation({
    mutationFn: () =>
      depositToWallet({
        amount_cents: Math.round(parseFloat(depositDollars) * 100),
        payment_method_id: depositPmId || undefined,
      }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["billing", "wallet"] });
      toast.success(`Deposited ${formatCents(data.wallet_balance_cents > 0 ? Math.round(parseFloat(depositDollars) * 100) : 0)} to wallet`);
      setDepositDollars("");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Deposit failed");
    },
  });

  const depositAmountCents = Math.round((parseFloat(depositDollars) || 0) * 100);
  const depositValid = depositAmountCents >= 100 && !isNaN(parseFloat(depositDollars));

  // ── Withdraw state ─────────────────────────────────────────────────────────
  const [withdrawDollars, setWithdrawDollars] = useState("");
  const [showWithdrawConfirm, setShowWithdrawConfirm] = useState(false);

  const withdrawMut = useMutation({
    mutationFn: () =>
      withdrawFromWallet({ amount_cents: Math.round(parseFloat(withdrawDollars) * 100) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["billing", "wallet"] });
      toast.success(`Withdrawn ${formatCents(Math.round(parseFloat(withdrawDollars) * 100))} from wallet`);
      setWithdrawDollars("");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Withdrawal failed");
    },
  });

  const withdrawAmountCents = Math.round((parseFloat(withdrawDollars) || 0) * 100);
  const balanceCents = wallet?.wallet_balance_cents ?? 0;
  const withdrawValid =
    withdrawAmountCents >= 100 &&
    !isNaN(parseFloat(withdrawDollars)) &&
    withdrawAmountCents <= balanceCents;

  return (
    <div className="space-y-6 pt-4">
      {/* Balance card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <WalletIcon className="h-5 w-5" />
            Wallet Balance
          </CardTitle>
          <CardDescription>Your prepaid wallet balance</CardDescription>
        </CardHeader>
        <CardContent>
          {walletLoading ? (
            <Skeleton className="h-10 w-40" />
          ) : (
            <div className="space-y-1">
              <p className="text-4xl font-bold">
                {formatCents(balanceCents, (wallet?.currency ?? "usd").toUpperCase())}
              </p>
              <p className="text-sm text-muted-foreground">
                {wallet?.currency?.toUpperCase() ?? "USD"} · Last updated: {formatTs(wallet?.updated_at)}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Deposit card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowDownToLine className="h-5 w-5" />
            Deposit
          </CardTitle>
          <CardDescription>Charge your payment method and add funds to your wallet</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="deposit-amount">Amount (USD)</Label>
            <Input
              id="deposit-amount"
              type="number"
              min="1"
              step="0.01"
              placeholder="0.00"
              value={depositDollars}
              onChange={(e) => setDepositDollars(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="deposit-pm">Payment Method</Label>
            <Select value={depositPmId} onValueChange={setDepositPmId}>
              <SelectTrigger id="deposit-pm">
                <SelectValue placeholder="Default payment method" />
              </SelectTrigger>
              <SelectContent>
                {methods.map((pm) => (
                  <SelectItem key={pm.payment_method_id} value={pm.payment_method_id}>
                    {pm.label ?? `${pm.brand ?? pm.method_type} ····${pm.last4}`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button
            onClick={() => depositMut.mutate()}
            disabled={!depositValid || depositMut.isPending}
          >
            {depositMut.isPending ? "Depositing…" : "Deposit"}
          </Button>
        </CardContent>
      </Card>

      {/* Withdraw card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowUpFromLine className="h-5 w-5" />
            Withdraw
          </CardTitle>
          <CardDescription>
            Transfer wallet funds back to your bank (simulated in dev mode)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="withdraw-amount">Amount (USD)</Label>
            <Input
              id="withdraw-amount"
              type="number"
              min="1"
              step="0.01"
              placeholder="0.00"
              value={withdrawDollars}
              onChange={(e) => setWithdrawDollars(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Max: {formatCents(balanceCents)}
            </p>
          </div>
          <Button
            variant="outline"
            onClick={() => setShowWithdrawConfirm(true)}
            disabled={!withdrawValid || withdrawMut.isPending}
          >
            {withdrawMut.isPending ? "Withdrawing…" : "Withdraw"}
          </Button>
          <p className="text-xs text-muted-foreground">
            Payouts are simulated in dev mode.
          </p>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={showWithdrawConfirm}
        onOpenChange={setShowWithdrawConfirm}
        title="Confirm Withdrawal"
        description={`Withdraw ${formatCents(withdrawAmountCents)} from your wallet?`}
        confirmLabel="Confirm"
        onConfirm={() => {
          setShowWithdrawConfirm(false);
          withdrawMut.mutate();
        }}
      />
    </div>
  );
}
