import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listMyAdAccounts,
  getAdBillingHistory,
  depositAdFunds,
  getAdInvoice,
  listCampaigns,
} from "@/api/endpoints/ads";
import type { AdAccount, AdBillingEntry, Campaign, AdInvoice } from "@/api/types";
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
import { Badge } from "@/components/ui/badge";
import { DollarSign, Plus, Receipt, TrendingUp } from "lucide-react";

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

  // Deposit mutation
  const depositMut = useMutation({
    mutationFn: (amount: number) =>
      depositAdFunds(accountId, { amount_cents: amount }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-billing", accountId] });
      queryClient.invalidateQueries({ queryKey: ["ad-accounts"] });
      setDepositOpen(false);
      setDepositAmount("");
    },
  });

  const currentAccount = accounts.find((a) => a.account_id === accountId);

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
      <Dialog open={depositOpen} onOpenChange={setDepositOpen}>
        <DialogContent data-testid="deposit-dialog">
          <DialogHeader>
            <DialogTitle>Deposit Funds</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm text-muted-foreground">Amount (USD)</label>
              <Input
                type="number"
                min={50}
                step={1}
                value={depositAmount}
                onChange={(e) => setDepositAmount(e.target.value)}
                placeholder="50.00"
                data-testid="deposit-amount-input"
              />
            </div>
            <div className="flex gap-2">
              {[50, 100, 250, 500].map((amt) => (
                <Button
                  key={amt}
                  variant="outline"
                  size="sm"
                  onClick={() => setDepositAmount(String(amt))}
                >
                  ${amt}
                </Button>
              ))}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDepositOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                const cents = Math.round(parseFloat(depositAmount) * 100);
                if (cents >= 5000) depositMut.mutate(cents);
              }}
              disabled={
                !depositAmount ||
                parseFloat(depositAmount) < 50 ||
                depositMut.isPending
              }
              data-testid="deposit-submit"
            >
              {depositMut.isPending ? "Processing..." : "Deposit"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
