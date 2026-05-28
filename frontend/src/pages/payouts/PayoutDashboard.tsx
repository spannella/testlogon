import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Wallet,
  DollarSign,
  Clock,
  TrendingUp,
  Loader2,
  Ban,
  AlertCircle,
} from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "@/api/client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import {
  getPayoutBalance,
  requestPayout,
  cancelPayout,
  listPayouts,
  getEarningsSummary,
  getEarningsTransactions,
} from "@/api/endpoints/payouts";
import type { Payout, EarningsTransaction } from "@/api/types";

// ─── Helpers ────────────────────────────────────────────────────

function formatCents(cents: number): string {
  return `$${(cents / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function formatDate(ts: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDateTime(ts: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const STATUS_BADGE_VARIANT: Record<string, string> = {
  completed: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  requested: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  approved: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  processing: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  rejected: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  cancelled: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200",
};

const CATEGORY_BADGE_VARIANT: Record<string, string> = {
  subscriptions: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
  tips: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  unlocks: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  vod_purchases: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  other: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200",
};

const CATEGORY_LABELS: Record<string, string> = {
  subscriptions: "Subscriptions",
  tips: "Tips",
  unlocks: "Unlocks",
  vod_purchases: "VOD Purchases",
  other: "Other",
};

const RANGE_PRESETS = [
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "Last 90 days", days: 90 },
  { label: "All time", days: 0 },
];

function tsFromDaysAgo(days: number): number {
  if (days === 0) return 0;
  return Math.floor((Date.now() - days * 86400_000) / 1000);
}

// ─── Page Component ─────────────────────────────────────────────

export default function PayoutDashboard() {
  const queryClient = useQueryClient();

  // ── Date range state ──
  const [rangeDays, setRangeDays] = useState(0);
  const fromTs = tsFromDaysAgo(rangeDays);
  const toTs = rangeDays > 0 ? Math.floor(Date.now() / 1000) : 0;

  // ── Payout request form state ──
  const [payoutAmount, setPayoutAmount] = useState("");
  const [payoutMethod, setPayoutMethod] = useState("bank_transfer");
  const [payoutNotes, setPayoutNotes] = useState("");

  // ── Cancel dialog state ──
  const [cancelTarget, setCancelTarget] = useState<Payout | null>(null);

  // ── Queries ──
  const balanceQ = useQuery({
    queryKey: ["payouts", "balance"],
    queryFn: getPayoutBalance,
    staleTime: 30_000,
    refetchInterval: 30_000,
  });

  const payoutsQ = useQuery({
    queryKey: ["payouts", "list"],
    queryFn: () => listPayouts({ limit: 25 }),
    staleTime: 60_000,
  });

  const summaryQ = useQuery({
    queryKey: ["earnings", "summary", fromTs, toTs],
    queryFn: () => getEarningsSummary({
      from_ts: fromTs || undefined,
      to_ts: toTs || undefined,
    }),
    staleTime: 60_000,
  });

  const txnQ = useQuery({
    queryKey: ["earnings", "transactions", fromTs, toTs],
    queryFn: () => getEarningsTransactions({
      limit: 50,
      from_ts: fromTs || undefined,
      to_ts: toTs || undefined,
    }),
    staleTime: 60_000,
  });

  // ── Mutations ──
  const requestMut = useMutation({
    mutationFn: requestPayout,
    onSuccess: () => {
      toast.success("Payout requested successfully");
      queryClient.invalidateQueries({ queryKey: ["payouts"] });
      setPayoutAmount("");
      setPayoutNotes("");
      setPayoutMethod("bank_transfer");
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          toast.error("You already have a pending payout request");
        } else {
          toast.error(err.detail || "Failed to request payout");
        }
      } else {
        toast.error("Failed to request payout");
      }
    },
  });

  const cancelMut = useMutation({
    mutationFn: cancelPayout,
    onSuccess: () => {
      toast.success("Payout cancelled");
      queryClient.invalidateQueries({ queryKey: ["payouts"] });
      setCancelTarget(null);
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        toast.error(err.detail || "Failed to cancel payout");
      } else {
        toast.error("Failed to cancel payout");
      }
      setCancelTarget(null);
    },
  });

  // ── Form validation ──
  const parsedAmount = parseFloat(payoutAmount);
  const amountCents = Math.round(parsedAmount * 100);
  const minCents = balanceQ.data?.minimum_payout_cents ?? 1000;
  const availCents = balanceQ.data?.available_cents ?? 0;
  const amountError =
    payoutAmount && !isNaN(parsedAmount)
      ? amountCents < minCents
        ? `Minimum payout is ${formatCents(minCents)}`
        : amountCents > availCents
          ? "Insufficient available balance"
          : null
      : null;

  const canSubmit =
    !requestMut.isPending &&
    payoutAmount !== "" &&
    !isNaN(parsedAmount) &&
    parsedAmount > 0 &&
    amountCents >= minCents &&
    amountCents <= availCents;

  function handleRequestPayout() {
    if (!canSubmit) return;
    requestMut.mutate({
      amount_cents: amountCents,
      method: payoutMethod,
      notes: payoutNotes || undefined,
    });
  }

  // ── Earnings breakdown data ──
  const breakdown = summaryQ.data?.breakdown;
  const breakdownEntries = breakdown
    ? (Object.entries(breakdown) as [string, number][]).filter(([, v]) => v > 0)
    : [];
  const breakdownTotal = breakdownEntries.reduce((s, [, v]) => s + v, 0);

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Wallet className="h-7 w-7 text-primary" />
        <h1 className="text-2xl font-bold tracking-tight">Payouts</h1>
      </div>

      {/* ── Balance Cards ── */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card className="border-green-200 dark:border-green-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Available Balance
            </CardTitle>
            <DollarSign className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-green-600" data-testid="available-balance">
              {balanceQ.isLoading ? "..." : formatCents(balanceQ.data?.available_cents ?? 0)}
            </p>
            <p className="text-xs text-muted-foreground">Available to withdraw</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Pending Payouts
            </CardTitle>
            <Clock className="h-4 w-4 text-yellow-600" />
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold" data-testid="pending-balance">
              {balanceQ.isLoading ? "..." : formatCents(balanceQ.data?.pending_cents ?? 0)}
            </p>
            <p className="text-xs text-muted-foreground">In transit</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              On Hold
            </CardTitle>
            <AlertCircle className="h-4 w-4 text-orange-600" />
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold" data-testid="hold-balance">
              {balanceQ.isLoading ? "..." : formatCents(balanceQ.data?.hold_cents ?? 0)}
            </p>
            <p className="text-xs text-muted-foreground">Within hold period</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Earned
            </CardTitle>
            <TrendingUp className="h-4 w-4 text-blue-600" />
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold" data-testid="total-earned">
              {balanceQ.isLoading ? "..." : formatCents(balanceQ.data?.total_earned_cents ?? 0)}
            </p>
            <p className="text-xs text-muted-foreground">Lifetime earnings</p>
          </CardContent>
        </Card>
      </div>

      {/* ── Request Payout Form ── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Request Payout</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="space-y-2">
              <Label htmlFor="payout-amount">Amount (USD)</Label>
              <Input
                id="payout-amount"
                type="number"
                step="0.01"
                min="0"
                placeholder="0.00"
                value={payoutAmount}
                onChange={(e) => setPayoutAmount(e.target.value)}
              />
              {amountError && (
                <p className="text-sm text-red-500">{amountError}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Minimum: {formatCents(minCents)}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="payout-method">Method</Label>
              <Select value={payoutMethod} onValueChange={setPayoutMethod}>
                <SelectTrigger id="payout-method">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="bank_transfer">Bank Transfer</SelectItem>
                  <SelectItem value="paypal">PayPal</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="payout-notes">Notes (optional)</Label>
              <Input
                id="payout-notes"
                placeholder="e.g. Monthly withdrawal"
                maxLength={500}
                value={payoutNotes}
                onChange={(e) => setPayoutNotes(e.target.value)}
              />
            </div>

            <div className="flex items-end">
              <Button
                className="w-full"
                disabled={!canSubmit}
                onClick={handleRequestPayout}
              >
                {requestMut.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Wallet className="mr-2 h-4 w-4" />
                )}
                Request Payout
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── Earnings Breakdown + Date Range ── */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg">Earnings Breakdown</CardTitle>
          <div className="flex gap-2">
            {RANGE_PRESETS.map((preset) => (
              <Button
                key={preset.days}
                variant={rangeDays === preset.days ? "default" : "outline"}
                size="sm"
                onClick={() => setRangeDays(preset.days)}
              >
                {preset.label}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          {summaryQ.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : breakdownTotal === 0 ? (
            <p className="py-8 text-center text-muted-foreground">No earnings yet</p>
          ) : (
            <div className="space-y-3">
              {breakdownEntries.map(([category, cents]) => {
                const pct = breakdownTotal > 0 ? Math.round((cents / breakdownTotal) * 100) : 0;
                return (
                  <div key={category} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium">
                        {CATEGORY_LABELS[category] ?? category}
                      </span>
                      <span className="text-muted-foreground">
                        {formatCents(cents)} ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted">
                      <div
                        className="h-2 rounded-full bg-primary"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
              <Separator />
              <p className="text-sm text-muted-foreground">
                {summaryQ.data?.transaction_count ?? 0} transactions totaling{" "}
                {formatCents(summaryQ.data?.total_cents ?? 0)}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Payout History ── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Payout History</CardTitle>
        </CardHeader>
        <CardContent>
          {payoutsQ.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !payoutsQ.data?.items?.length ? (
            <p className="py-8 text-center text-muted-foreground">
              No payout requests yet
            </p>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Date</TableHead>
                    <TableHead>Amount</TableHead>
                    <TableHead>Method</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {payoutsQ.data.items.map((payout: Payout) => (
                    <TableRow key={payout.payout_id}>
                      <TableCell>
                        {payout.completed_at
                          ? formatDate(payout.completed_at)
                          : formatDate(payout.created_at)}
                      </TableCell>
                      <TableCell className="font-medium">
                        {formatCents(payout.amount_cents)}
                      </TableCell>
                      <TableCell>
                        {payout.method === "bank_transfer"
                          ? "Bank Transfer"
                          : "PayPal"}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_BADGE_VARIANT[payout.status] ?? ""}`}
                          data-testid={`status-${payout.status}`}
                        >
                          {payout.status}
                        </span>
                        {payout.status === "rejected" && payout.reject_reason && (
                          <p className="mt-1 text-xs text-red-500">
                            {payout.reject_reason}
                          </p>
                        )}
                      </TableCell>
                      <TableCell>
                        {(payout.status === "requested" ||
                          payout.status === "approved") && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-600 hover:text-red-700"
                            onClick={() => setCancelTarget(payout)}
                          >
                            <Ban className="mr-1 h-3 w-3" />
                            Cancel
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {payoutsQ.data.next_cursor && (
                <div className="mt-4 flex justify-center">
                  <Button variant="outline" size="sm">
                    Load more
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* ── Earnings Transactions ── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Earnings Transactions</CardTitle>
        </CardHeader>
        <CardContent>
          {txnQ.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !txnQ.data?.items?.length ? (
            <p className="py-8 text-center text-muted-foreground">
              No earnings yet
            </p>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Date/Time</TableHead>
                    <TableHead>Amount</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {txnQ.data.items.map((txn: EarningsTransaction) => (
                    <TableRow key={txn.entry_id}>
                      <TableCell>{formatDateTime(txn.ts)}</TableCell>
                      <TableCell className="font-medium text-green-600">
                        +{formatCents(txn.amount_cents)}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${CATEGORY_BADGE_VARIANT[txn.category] ?? CATEGORY_BADGE_VARIANT.other}`}
                        >
                          {CATEGORY_LABELS[txn.category] ?? txn.category}
                        </span>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-sm text-muted-foreground">
                        {txn.reason}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {txnQ.data.next_cursor && (
                <div className="mt-4 flex justify-center">
                  <Button variant="outline" size="sm">
                    Load more
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* ── Cancel Confirmation Dialog ── */}
      <Dialog
        open={cancelTarget !== null}
        onOpenChange={(open) => {
          if (!open) setCancelTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel Payout Request</DialogTitle>
            <DialogDescription>
              Are you sure you want to cancel this payout request for{" "}
              {cancelTarget ? formatCents(cancelTarget.amount_cents) : ""}?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCancelTarget(null)}>
              Keep Request
            </Button>
            <Button
              variant="destructive"
              disabled={cancelMut.isPending}
              onClick={() => {
                if (cancelTarget) {
                  cancelMut.mutate(cancelTarget.payout_id);
                }
              }}
            >
              {cancelMut.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Yes, Cancel Payout
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
