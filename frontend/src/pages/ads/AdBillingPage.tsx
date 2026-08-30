import { useState, useEffect, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listMyAdAccounts,
  getAdBillingHistory,
  depositAdFunds,
  getAdInvoice,
  listCampaigns,
} from "@/api/endpoints/ads";
import type { AdAccount, AdBillingEntry, Campaign, AdInvoice } from "@/api/types";
import { quoteFee, type FeeQuote } from "@/api/endpoints/fees";
import { getBalance, mergeBalances } from "@/api/endpoints/custody";
import { ApiError } from "@/api/client";
import {
  quoteExpirySeconds,
  insufficientForCents,
  rateLine,
  totalLine,
  feeLine,
  formatCoin,
  formatCountdown,
} from "@/lib/checkoutCrypto";
import {
  PRESET_TOPUPS_CENTS,
  isValidTopUpCents,
  topUpLabel,
  newBalanceCents,
  dollarsToCents,
} from "@/lib/adDeposit";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  DollarSign,
  Plus,
  Receipt,
  TrendingUp,
  Bitcoin,
  CreditCard,
  Loader2,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function entryTypeBadge(t: string) {
  if (t === "budget_deposit") return <Badge variant="default">Deposit</Badge>;
  if (t === "impression_charge") return <Badge variant="destructive">Impression</Badge>;
  if (t === "click_charge") return <Badge variant="destructive">Click</Badge>;
  if (t === "conversion_charge") return <Badge variant="destructive">Conversion</Badge>;
  return <Badge variant="secondary">{t}</Badge>;
}

export default function AdBillingPage() {
  const queryClient = useQueryClient();
  const [selectedAccountId, setSelectedAccountId] = useState<string>("");
  const [depositOpen, setDepositOpen] = useState(false);
  const [depositAmount, setDepositAmount] = useState("");
  const [invoiceMonth, setInvoiceMonth] = useState(
    new Date().toISOString().slice(0, 7),
  );

  // Fund-with-crypto state (FE-160) — mirrors Checkout.tsx pay-with-crypto (FE-152).
  const [payCrypto, setPayCrypto] = useState(false);
  const [cryptoAsset, setCryptoAsset] = useState<string | null>(null);
  const [quote, setQuote] = useState<FeeQuote | null>(null);
  const [quoteLoading, setQuoteLoading] = useState(false);
  const [quoteError, setQuoteError] = useState("");
  const [cryptoUnavailable, setCryptoUnavailable] = useState(false);
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));
  const [confirmOpen, setConfirmOpen] = useState(false);

  // Fetch accounts
  const { data: accounts = [] } = useQuery<AdAccount[]>({
    queryKey: ["ad-accounts"],
    queryFn: listMyAdAccounts,
  });

  const accountId = selectedAccountId || accounts[0]?.account_id || "";

  // Fetch billing history
  const { data: entries = [] } = useQuery<AdBillingEntry[]>({
    queryKey: ["ad-billing", accountId],
    queryFn: () => getAdBillingHistory(accountId),
    enabled: !!accountId,
  });

  // Fetch campaigns
  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ["ad-campaigns", accountId],
    queryFn: () => listCampaigns(accountId),
    enabled: !!accountId,
  });

  // Fetch invoice
  const { data: invoice } = useQuery<AdInvoice>({
    queryKey: ["ad-invoice", accountId, invoiceMonth],
    queryFn: () => getAdInvoice(accountId, invoiceMonth),
    enabled: !!accountId && !!invoiceMonth,
  });

  // Crypto balances (custody). Degrade on 404 -> hide the crypto option.
  const balanceQuery = useQuery({
    queryKey: ["custody", "balance"],
    queryFn: getBalance,
    retry: false,
  });

  const currentAccount = accounts.find((a) => a.account_id === accountId);

  // --- Fund-with-crypto derived state -------------------------------------
  const cryptoAvailable = balanceQuery.isSuccess && !!balanceQuery.data;
  const balanceRows = useMemo(
    () => mergeBalances(balanceQuery.data?.balances),
    [balanceQuery.data],
  );
  const selectedRow = useMemo(
    () => balanceRows.find((r) => r.symbol === cryptoAsset) ?? null,
    [balanceRows, cryptoAsset],
  );
  const selectedBalance = selectedRow ? Number(selectedRow.balance) : 0;
  const secondsLeft = quote ? quoteExpirySeconds(quote.expires_at, nowSec) : 0;
  const quoteStale = !!quote && secondsLeft <= 0;
  const insufficient =
    !!quote && !quoteStale && insufficientForCents(selectedBalance, quote);

  // Parsed top-up amount (cents) + validity from the pure lib.
  const topUpCents = dollarsToCents(depositAmount);
  const validTopUp = isValidTopUpCents(topUpCents);

  // --- Quote lifecycle (mirror of Checkout.tsx) ---------------------------
  const fetchQuote = async (asset: string, amountCents: number) => {
    if (!asset || amountCents <= 0) return;
    setQuoteLoading(true);
    setQuoteError("");
    try {
      const q = await quoteFee({ amount_cents: amountCents, pay_with: asset });
      setQuote(q);
      setNowSec(Math.floor(Date.now() / 1000));
    } catch (err) {
      const status = err instanceof ApiError ? err.status : 0;
      if (status === 404) {
        setCryptoUnavailable(true);
        setPayCrypto(false);
        setQuote(null);
      } else {
        setQuote(null);
        setQuoteError(
          err instanceof ApiError ? err.detail : "Could not get a rate. Try again.",
        );
      }
    } finally {
      setQuoteLoading(false);
    }
  };

  const handleSelectCryptoAsset = (asset: string) => {
    setPayCrypto(true);
    setCryptoAsset(asset);
    setQuote(null);
    if (validTopUp) void fetchQuote(asset, topUpCents);
  };

  const handleRequote = () => {
    if (cryptoAsset && validTopUp) void fetchQuote(cryptoAsset, topUpCents);
  };

  // Re-quote when the amount changes while a coin is chosen.
  useEffect(() => {
    if (!payCrypto || !cryptoAsset) return;
    if (!validTopUp) {
      setQuote(null);
      return;
    }
    void fetchQuote(cryptoAsset, topUpCents);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topUpCents, cryptoAsset, payCrypto]);

  // Live 1Hz countdown for the rate lock while a crypto quote is shown.
  useEffect(() => {
    if (!payCrypto || !quote) return;
    const id = setInterval(
      () => setNowSec(Math.floor(Date.now() / 1000)),
      1000,
    );
    return () => clearInterval(id);
  }, [payCrypto, quote]);

  const resetDeposit = () => {
    setDepositOpen(false);
    setDepositAmount("");
    setPayCrypto(false);
    setCryptoAsset(null);
    setQuote(null);
    setQuoteError("");
  };

  // Deposit mutation (card/default OR crypto).
  const depositMut = useMutation({
    mutationFn: () => {
      const body: {
        amount_cents: number;
        pay_with?: string;
        quote_token?: string;
      } = { amount_cents: topUpCents };
      if (payCrypto && quote) {
        body.pay_with = quote.pay_with;
        body.quote_token = quote.quote_token;
      }
      return depositAdFunds(accountId, body);
    },
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["ad-billing", accountId] });
      queryClient.invalidateQueries({ queryKey: ["ad-accounts"] });
      queryClient.invalidateQueries({ queryKey: ["custody", "balance"] });
      setConfirmOpen(false);
      toast.success(
        `Funded — new balance ${formatCents(Number(res.new_balance_cents))}`,
      );
      resetDeposit();
    },
    onError: (err: unknown) => {
      const detail = err instanceof ApiError ? err.detail : undefined;
      const status = err instanceof ApiError ? err.status : 0;
      if (status === 409 && payCrypto) {
        toast.error("Rate expired — refreshing the quote.");
        handleRequote();
      } else if (status === 402 && payCrypto) {
        toast.error(detail || "Insufficient crypto balance.");
        setQuoteError(detail || "Insufficient crypto balance.");
      } else {
        toast.error(detail || "Deposit failed");
      }
    },
  });

  // Enablement for the primary deposit button.
  const canSubmit =
    validTopUp &&
    (payCrypto
      ? !!quote && !quoteStale && !insufficient && !quoteLoading
      : true);

  return (
    <div className="space-y-6 p-6" data-testid="ad-billing-page">
      <h1 className="text-2xl font-bold">Ad Billing</h1>

      {/* Account selector */}
      {accounts.length > 1 && (
        <select
          className="border rounded px-2 py-1"
          value={accountId}
          onChange={(e) => setSelectedAccountId(e.target.value)}
          data-testid="account-selector"
        >
          {accounts.map((a) => (
            <option key={a.account_id} value={a.account_id}>
              {a.company_name} ({a.account_id})
            </option>
          ))}
        </select>
      )}

      {!accountId && (
        <p className="text-muted-foreground">No ad accounts found. Create one to get started.</p>
      )}

      {accountId && currentAccount && (
        <>
          {/* Balance Card */}
          <Card data-testid="balance-card">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <DollarSign className="h-5 w-5" />
                Account Balance
              </CardTitle>
              <Button
                size="sm"
                onClick={() => setDepositOpen(true)}
                data-testid="deposit-button"
              >
                <Plus className="h-4 w-4 mr-1" />
                Deposit
              </Button>
            </CardHeader>
            <CardContent>
              <div className="flex gap-8">
                <div>
                  <p className="text-sm text-muted-foreground">Current Balance</p>
                  <p className="text-2xl font-bold" data-testid="current-balance">
                    {formatCents(Number(currentAccount.balance_cents))}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Lifetime Spend</p>
                  <p className="text-2xl font-bold" data-testid="lifetime-spend">
                    {formatCents(Number(currentAccount.lifetime_spend_cents))}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Budget Meters */}
          {campaigns.length > 0 && (
            <Card data-testid="budget-meters">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  Campaign Budgets
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {campaigns.map((c) => {
                  const pct = c.budget_cents > 0
                    ? Math.min(100, Math.round((Number(c.lifetime_spent_cents) / Number(c.budget_cents)) * 100))
                    : 0;
                  const color = pct >= 80 ? "bg-red-500" : pct >= 50 ? "bg-yellow-500" : "bg-green-500";
                  return (
                    <div key={c.campaign_id} data-testid="budget-meter">
                      <div className="flex justify-between text-sm mb-1">
                        <span>{c.name}</span>
                        <span>
                          {formatCents(Number(c.lifetime_spent_cents))} / {formatCents(Number(c.budget_cents))} ({pct}%)
                        </span>
                      </div>
                      <div className="w-full bg-secondary rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${color}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {/* Transaction List */}
          <Card data-testid="transaction-list">
            <CardHeader>
              <CardTitle>Recent Transactions</CardTitle>
            </CardHeader>
            <CardContent>
              {entries.length === 0 ? (
                <p className="text-muted-foreground">No transactions yet.</p>
              ) : (
                <div className="space-y-2">
                  {entries.map((e) => (
                    <div
                      key={e.entry_id}
                      className="flex items-center justify-between border-b py-2 last:border-0"
                      data-testid="billing-entry"
                    >
                      <div className="flex items-center gap-3">
                        {entryTypeBadge(e.entry_type)}
                        <div>
                          <p className="text-sm font-medium">{e.reason}</p>
                          <p className="text-xs text-muted-foreground">
                            {new Date(Number(e.created_at) * 1000).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      <span
                        className={`font-mono ${
                          e.entry_type === "budget_deposit"
                            ? "text-green-600"
                            : "text-red-600"
                        }`}
                      >
                        {e.entry_type === "budget_deposit" ? "+" : "-"}
                        {formatCents(Number(e.amount_cents))}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Invoice Section */}
          <Card data-testid="invoice-section">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Receipt className="h-5 w-5" />
                Monthly Invoice
              </CardTitle>
              <Input
                type="month"
                value={invoiceMonth}
                onChange={(e) => setInvoiceMonth(e.target.value)}
                className="w-40"
                data-testid="invoice-month-input"
              />
            </CardHeader>
            <CardContent>
              {invoice ? (
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span>Total Charges:</span>
                    <span className="font-bold" data-testid="invoice-total-charges">
                      {formatCents(invoice.total_charges_cents)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Total Deposits:</span>
                    <span data-testid="invoice-total-deposits">
                      {formatCents(invoice.total_deposits_cents)}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm text-muted-foreground">
                    <span>Entries:</span>
                    <span>{invoice.entry_count}</span>
                  </div>
                  {invoice.campaigns.length > 0 && (
                    <div className="mt-4">
                      <h4 className="text-sm font-medium mb-2">Campaign Breakdown</h4>
                      {invoice.campaigns.map((c) => (
                        <div
                          key={c.campaign_id}
                          className="flex justify-between text-sm border-b py-1"
                          data-testid="invoice-campaign-line"
                        >
                          <span>{c.campaign_id}</span>
                          <span>
                            {c.impressions} imp / {c.clicks} clicks / {c.conversions} conv = {formatCents(c.total_cents)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-muted-foreground">No invoice data.</p>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Deposit Dialog */}
      <Dialog
        open={depositOpen}
        onOpenChange={(o) => (o ? setDepositOpen(true) : resetDeposit())}
      >
        <DialogContent data-testid="deposit-dialog">
          <DialogHeader>
            <DialogTitle>Deposit Funds</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm text-muted-foreground">Amount (USD)</label>
              <Input
                type="number"
                min={1}
                step={1}
                value={depositAmount}
                onChange={(e) => setDepositAmount(e.target.value)}
                placeholder="25.00"
                data-testid="deposit-amount-input"
              />
              {depositAmount && !validTopUp && (
                <p className="mt-1 text-xs text-destructive" data-testid="topup-invalid">
                  Enter a whole-cent amount of at least {topUpLabel(100)}.
                </p>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {PRESET_TOPUPS_CENTS.map((cents) => (
                <Button
                  key={cents}
                  variant="outline"
                  size="sm"
                  onClick={() => setDepositAmount(String(cents / 100))}
                  data-testid={`topup-preset-${cents}`}
                >
                  {topUpLabel(cents)}
                </Button>
              ))}
            </div>

            {/* Funding method: card/default vs crypto balance (FE-160) */}
            <div className="space-y-2 pt-1">
              <p className="text-xs font-medium text-muted-foreground">
                Funding method
              </p>
              <button
                type="button"
                className={`flex w-full items-center gap-3 rounded-lg border px-4 py-2.5 text-left transition-colors ${
                  !payCrypto ? "border-primary bg-primary/5" : "hover:bg-accent"
                }`}
                onClick={() => setPayCrypto(false)}
                data-testid="fund-card-option"
              >
                <CreditCard className="h-5 w-5 shrink-0 text-muted-foreground" />
                <span className="text-sm font-medium">Card / default method</span>
              </button>

              {cryptoAvailable && !cryptoUnavailable && (
                <button
                  type="button"
                  className={`flex w-full items-center gap-3 rounded-lg border px-4 py-2.5 text-left transition-colors ${
                    payCrypto ? "border-primary bg-primary/5" : "hover:bg-accent"
                  }`}
                  onClick={() => setPayCrypto(true)}
                  data-testid="fund-crypto-option"
                >
                  <Bitcoin className="h-5 w-5 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <span className="text-sm font-medium">
                      Fund with crypto balance
                    </span>
                    <span className="ml-2 text-sm text-muted-foreground">
                      any supported coin
                    </span>
                  </div>
                </button>
              )}

              {cryptoUnavailable && (
                <p className="text-xs text-muted-foreground" data-testid="crypto-unavailable">
                  Crypto funding unavailable.
                </p>
              )}

              {payCrypto && cryptoAvailable && !cryptoUnavailable && (
                <div className="space-y-3 rounded-lg border border-dashed p-3">
                  {/* Asset picker */}
                  <div>
                    <p className="mb-1.5 text-xs font-medium text-muted-foreground">
                      Choose a coin
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {balanceRows.map((row) => (
                        <button
                          key={row.symbol}
                          type="button"
                          className={`rounded-md border px-3 py-1.5 text-sm transition-colors ${
                            cryptoAsset === row.symbol
                              ? "border-primary bg-primary/10 font-medium"
                              : "hover:bg-accent"
                          }`}
                          onClick={() => handleSelectCryptoAsset(row.symbol)}
                          data-testid={`crypto-asset-${row.symbol}`}
                        >
                          {row.symbol}
                          <span className="ml-1.5 text-xs text-muted-foreground">
                            {formatCoin(Number(row.balance))}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>

                  {!validTopUp && (
                    <p className="text-xs text-muted-foreground">
                      Enter an amount to get a locked rate.
                    </p>
                  )}

                  {quoteLoading && (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Fetching rate…
                    </div>
                  )}

                  {quoteError && !quoteLoading && (
                    <p className="text-sm text-destructive" data-testid="crypto-quote-error">
                      {quoteError}
                    </p>
                  )}

                  {quote && !quoteLoading && (
                    <div className="space-y-1.5 rounded-md bg-muted/50 p-3 text-sm" data-testid="crypto-rate-lock">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">{rateLine(quote)}</span>
                        {quoteStale ? (
                          <Badge variant="destructive" className="text-[10px]">
                            Rate expired
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="text-[10px]" data-testid="crypto-countdown">
                            Locked {formatCountdown(secondsLeft)}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center justify-between font-medium">
                        <span>{totalLine(quote)}</span>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {feeLine(quote)} · balance {formatCoin(selectedBalance)}{" "}
                        {quote.pay_with}
                      </div>

                      {insufficient && (
                        <p className="flex items-center gap-1.5 text-xs text-destructive" data-testid="crypto-insufficient">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          Insufficient {quote.pay_with} balance for this top-up.
                        </p>
                      )}

                      {(quoteStale || !insufficient) && (
                        <button
                          type="button"
                          className="mt-1 flex items-center gap-1 text-xs text-primary hover:underline"
                          onClick={handleRequote}
                          data-testid="crypto-requote"
                        >
                          <RefreshCw className="h-3 w-3" />
                          {quoteStale ? "Refresh rate" : "Re-quote"}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={resetDeposit}>
              Cancel
            </Button>
            <Button
              onClick={() => setConfirmOpen(true)}
              disabled={!canSubmit || depositMut.isPending}
              data-testid="deposit-submit"
            >
              {depositMut.isPending
                ? "Processing..."
                : payCrypto && quote && !quoteStale
                  ? `Fund ${formatCoin(quote.total_native)} ${quote.pay_with}`
                  : "Deposit"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Confirm Deposit"
        description={
          payCrypto && quote
            ? `${totalLine(quote)} (${rateLine(quote)}) to add ${topUpLabel(topUpCents)} — new balance ${formatCents(newBalanceCents(Number(currentAccount?.balance_cents ?? 0), topUpCents))}?`
            : `Add ${topUpLabel(topUpCents)} to your ad balance — new balance ${formatCents(newBalanceCents(Number(currentAccount?.balance_cents ?? 0), topUpCents))}?`
        }
        confirmLabel="Deposit"
        onConfirm={() => depositMut.mutate()}
        loading={depositMut.isPending}
      />
    </div>
  );
}
