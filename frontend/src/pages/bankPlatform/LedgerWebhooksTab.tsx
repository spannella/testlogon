/**
 * PLT-005: Ledger Webhook Threshold tab.
 *
 * Allows users to set a low-balance threshold; when enabled, the backend fires
 * `balance.threshold` and `account.balance_low` webhook events on a downward
 * balance crossing.
 *
 * Endpoints:
 *   GET  /ui/billing/wallet               (always available)
 *   PUT  /ui/billing/wallet/threshold     (PLT-005 — 404 when disabled)
 *
 * Flag: OPEN_BANK_PROJECT_ENABLED + ACCOUNT_LEDGER_WEBHOOKS_ENABLED
 */

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Bell, BellOff, Save, RefreshCw, Wallet } from "lucide-react";

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
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  getWalletBalance,
  setWalletThreshold,
} from "@/api/endpoints/bankPlatform";

/** Convert integer cents to display dollars. */
function centsToDisplay(cents: number) {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function LedgerWebhooksTab() {
  const qc = useQueryClient();

  const walletQuery = useQuery({
    queryKey: ["bank-platform", "wallet"],
    queryFn: getWalletBalance,
    retry: false,
  });

  const thresholdCents =
    walletQuery.data?.balance_threshold_cents ??
    walletQuery.data?.threshold_cents ??
    0;

  const [inputCents, setInputCents] = useState<string>("");
  const [inputDollars, setInputDollars] = useState<string>("");

  // Sync input when query loads
  useEffect(() => {
    if (walletQuery.data != null) {
      const cents =
        walletQuery.data.balance_threshold_cents ??
        walletQuery.data.threshold_cents ??
        0;
      setInputCents(String(cents));
      setInputDollars((cents / 100).toFixed(2));
    }
  }, [walletQuery.data]);

  const saveMut = useMutation({
    mutationFn: (cents: number) => setWalletThreshold({ threshold_cents: cents }),
    onSuccess: (data) => {
      toast.success(
        data.threshold_cents === 0
          ? "Low-balance threshold disabled."
          : `Threshold set to ${centsToDisplay(data.threshold_cents)}.`,
      );
      qc.invalidateQueries({ queryKey: ["bank-platform", "wallet"] });
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
        toast.error(
          "The ledger webhook feature is not enabled. Set ACCOUNT_LEDGER_WEBHOOKS_ENABLED=1.",
        );
      } else {
        toast.error(err.message ?? "Failed to update threshold");
      }
    },
  });

  function handleSave(e: React.FormEvent) {
    e.preventDefault();
    const cents = parseInt(inputCents, 10);
    if (isNaN(cents) || cents < 0) {
      toast.error("Please enter a valid non-negative amount in cents.");
      return;
    }
    saveMut.mutate(cents);
  }

  function handleDollarsChange(val: string) {
    setInputDollars(val);
    const parsed = parseFloat(val);
    if (!isNaN(parsed) && parsed >= 0) {
      setInputCents(String(Math.round(parsed * 100)));
    }
  }

  function handleCentsChange(val: string) {
    setInputCents(val);
    const parsed = parseInt(val, 10);
    if (!isNaN(parsed) && parsed >= 0) {
      setInputDollars((parsed / 100).toFixed(2));
    }
  }

  const balance = walletQuery.data?.wallet_balance_cents ?? 0;
  const thresholdActive = walletQuery.data?.last_threshold_crossed ?? walletQuery.data?.threshold_active ?? false;
  const isNotEnabled =
    walletQuery.error instanceof ApiError &&
    (walletQuery.error.status === 404 || walletQuery.error.status === 503);

  return (
    <div className="flex flex-col gap-4">
      {/* Wallet balance card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Wallet className="h-5 w-5" />
            Wallet Balance
          </CardTitle>
        </CardHeader>
        <CardContent>
          {walletQuery.isLoading ? (
            <Skeleton className="h-8 w-32" />
          ) : walletQuery.isError && !isNotEnabled ? (
            <p className="text-sm text-destructive">
              {walletQuery.error instanceof Error
                ? walletQuery.error.message
                : "Failed to load wallet"}
            </p>
          ) : (
            <div className="flex items-center gap-3">
              <span className="text-3xl font-semibold tabular-nums">
                {centsToDisplay(balance)}
              </span>
              <span className="text-sm text-muted-foreground uppercase">
                {walletQuery.data?.currency ?? "USD"}
              </span>
              {thresholdActive && (
                <Badge variant="destructive" className="gap-1">
                  <BellOff className="h-3 w-3" />
                  Below threshold
                </Badge>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Threshold configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Bell className="h-5 w-5" />
            Low-Balance Alert Threshold
          </CardTitle>
          <CardDescription>
            When your wallet balance falls below this threshold, the backend fires{" "}
            <code className="rounded bg-muted px-1 text-xs">balance.threshold</code> and{" "}
            <code className="rounded bg-muted px-1 text-xs">account.balance_low</code> webhook
            events. Set to 0 to disable.
            <br />
            <span className="text-xs mt-1 block">
              Requires{" "}
              <code className="rounded bg-muted px-1 text-xs">ACCOUNT_LEDGER_WEBHOOKS_ENABLED=1</code>{" "}
              and{" "}
              <code className="rounded bg-muted px-1 text-xs">WEBHOOKS_ENABLED=1</code>.
            </span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {walletQuery.isLoading ? (
            <Skeleton className="h-28 w-full" />
          ) : (
            <>
              {/* Current threshold summary */}
              {thresholdCents > 0 && (
                <div className="mb-4 flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2">
                  <Bell className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">
                    Current threshold:{" "}
                    <strong>{centsToDisplay(thresholdCents)}</strong> ({thresholdCents} cents)
                  </span>
                  {thresholdActive && (
                    <Badge variant="destructive" className="ml-auto text-xs">
                      Currently triggered
                    </Badge>
                  )}
                </div>
              )}

              <form onSubmit={handleSave} className="flex flex-col gap-4">
                <div className="grid grid-cols-2 gap-4 max-w-sm">
                  <div className="flex flex-col gap-1.5">
                    <Label htmlFor="threshold-dollars">Amount ($)</Label>
                    <Input
                      id="threshold-dollars"
                      type="number"
                      min={0}
                      step={0.01}
                      placeholder="0.00"
                      value={inputDollars}
                      onChange={(e) => handleDollarsChange(e.target.value)}
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label htmlFor="threshold-cents">Amount (cents)</Label>
                    <Input
                      id="threshold-cents"
                      type="number"
                      min={0}
                      step={1}
                      placeholder="0"
                      value={inputCents}
                      onChange={(e) => handleCentsChange(e.target.value)}
                    />
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  Set to 0 to disable the threshold alert.
                </p>
                <div className="flex gap-2">
                  <Button
                    type="submit"
                    size="sm"
                    disabled={saveMut.isPending}
                    className="gap-1.5"
                  >
                    <Save className="h-4 w-4" />
                    {saveMut.isPending ? "Saving…" : "Save threshold"}
                  </Button>
                  {thresholdCents > 0 && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={saveMut.isPending}
                      onClick={() => {
                        setInputCents("0");
                        setInputDollars("0.00");
                        saveMut.mutate(0);
                      }}
                    >
                      Disable
                    </Button>
                  )}
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={walletQuery.isFetching}
                    onClick={() => walletQuery.refetch()}
                    className="gap-1.5"
                  >
                    <RefreshCw
                      className={`h-4 w-4 ${walletQuery.isFetching ? "animate-spin" : ""}`}
                    />
                    Refresh
                  </Button>
                </div>
              </form>

              {/* Event taxonomy info */}
              <div className="mt-6 rounded-md border bg-muted/30 p-4">
                <p className="text-sm font-medium mb-2">PLT-005 webhook events</p>
                <div className="flex flex-col gap-1.5 text-xs text-muted-foreground">
                  <div>
                    <code className="rounded bg-muted px-1">transaction.created</code> — fires on
                    every new ledger entry (wallet deposit, withdrawal, charge, refund).
                  </div>
                  <div>
                    <code className="rounded bg-muted px-1">balance.threshold</code> — fires when
                    balance crosses below your configured threshold (downward edge only).
                  </div>
                  <div>
                    <code className="rounded bg-muted px-1">account.balance_low</code> — alias for{" "}
                    <code className="rounded bg-muted px-1">balance.threshold</code>; both fire
                    simultaneously on a crossing.
                  </div>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
