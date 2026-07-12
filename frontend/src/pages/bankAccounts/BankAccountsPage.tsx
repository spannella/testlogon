/**
 * OBP Bank Accounts — list page (ACC-001..ACC-005)
 *
 * Shows all bank accounts for the current user with live balance.
 * Handles feature-flag off (404/503) gracefully.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Landmark,
  Plus,
  Trash2,
  ChevronRight,
  RefreshCw,
  AlertCircle,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  listAccounts,
  listBanks,
  getAccountBalance,
  createAccount,
  deleteAccount,
  type AccountOut,
  type AccountBalanceOut,
} from "@/api/endpoints/bankAccounts";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtCurrency(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: currency.toUpperCase(),
    }).format(amount);
  } catch {
    return `${currency.toUpperCase()} ${amount.toFixed(2)}`;
  }
}

function FeatureDisabled() {
  return (
    <Card className="border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-950">
      <CardContent className="flex items-center gap-3 py-6">
        <AlertCircle className="h-5 w-5 text-yellow-600" />
        <div>
          <p className="font-medium text-yellow-800 dark:text-yellow-200">
            Open Banking not enabled
          </p>
          <p className="text-sm text-yellow-700 dark:text-yellow-300">
            The bank accounts feature is currently disabled. Contact your
            administrator to enable it.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Balance sub-component ────────────────────────────────────────────────────

function AccountBalance({ accountId }: { accountId: string }) {
  const { data, isLoading } = useQuery<AccountBalanceOut>({
    queryKey: ["banking", "balance", accountId],
    queryFn: () => getAccountBalance(accountId),
    retry: false,
  });

  if (isLoading) {
    return <Skeleton className="h-5 w-24" />;
  }
  if (!data) {
    return <span className="text-muted-foreground text-sm">—</span>;
  }
  return (
    <span className="font-mono text-sm font-semibold">
      {fmtCurrency(data.current, data.currency)}
    </span>
  );
}

// ─── Account card ─────────────────────────────────────────────────────────────

function AccountCard({
  account,
  onDelete,
  deleting,
}: {
  account: AccountOut;
  onDelete: (id: string) => void;
  deleting: boolean;
}) {
  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Landmark className="h-4 w-4 shrink-0 text-muted-foreground" />
            <CardTitle className="text-base truncate">{account.label}</CardTitle>
            {account.is_default && (
              <Badge variant="secondary" className="shrink-0 text-xs">
                Default
              </Badge>
            )}
          </div>
          <Badge variant="outline" className="shrink-0 text-xs uppercase">
            {account.account_type}
          </Badge>
        </div>
        <CardDescription className="text-xs mt-1">
          {account.bank_id}
          {account.iban && (
            <span className="ml-2 font-mono">{account.iban}</span>
          )}
          {account.account_number_masked && !account.iban && (
            <span className="ml-2 font-mono">{account.account_number_masked}</span>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground mb-0.5">Balance</p>
            <AccountBalance accountId={account.account_id} />
          </div>
          <div className="flex items-center gap-1">
            {!account.is_default && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-destructive hover:text-destructive"
                disabled={deleting}
                onClick={() => onDelete(account.account_id)}
                title="Delete account"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
            <Button variant="ghost" size="icon" className="h-8 w-8" asChild>
              <Link to={`/bank/accounts/${account.account_id}`} title="View details">
                <ChevronRight className="h-4 w-4" />
              </Link>
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Create account dialog ────────────────────────────────────────────────────

interface CreateAccountFormProps {
  open: boolean;
  onClose: () => void;
  bankIds: string[];
}

function CreateAccountDialog({ open, onClose, bankIds }: CreateAccountFormProps) {
  const qc = useQueryClient();
  const [label, setLabel] = useState("");
  const [accountType, setAccountType] = useState("SAVINGS");
  const [bankId, setBankId] = useState(bankIds[0] ?? "");
  const [currency, setCurrency] = useState("usd");
  const [iban, setIban] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      createAccount({
        label: label.trim(),
        account_type: accountType,
        bank_id: bankId,
        currency: currency.trim().toLowerCase() || "usd",
        iban: iban.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Account created");
      void qc.invalidateQueries({ queryKey: ["banking", "accounts"] });
      onClose();
      setLabel("");
      setIban("");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create account"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New Bank Account</DialogTitle>
          <DialogDescription>Add a linked bank account to your profile.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 pt-2">
          <div className="space-y-1">
            <Label htmlFor="ca-label">Label</Label>
            <Input
              id="ca-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Main Savings"
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="ca-bank">Bank</Label>
            <Select value={bankId} onValueChange={setBankId}>
              <SelectTrigger id="ca-bank">
                <SelectValue placeholder="Select a bank" />
              </SelectTrigger>
              <SelectContent>
                {bankIds.map((b) => (
                  <SelectItem key={b} value={b}>
                    {b}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1">
            <Label htmlFor="ca-type">Account type</Label>
            <Select value={accountType} onValueChange={setAccountType}>
              <SelectTrigger id="ca-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="SAVINGS">Savings</SelectItem>
                <SelectItem value="CHECKING">Checking</SelectItem>
                <SelectItem value="EXTERNAL">External</SelectItem>
                <SelectItem value="INVESTMENT">Investment</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1">
            <Label htmlFor="ca-currency">Currency (ISO-4217)</Label>
            <Input
              id="ca-currency"
              value={currency}
              onChange={(e) => setCurrency(e.target.value)}
              placeholder="usd"
              maxLength={3}
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="ca-iban">IBAN (optional)</Label>
            <Input
              id="ca-iban"
              value={iban}
              onChange={(e) => setIban(e.target.value)}
              placeholder="GB29NWBK60161331926819"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={onClose} disabled={mut.isPending}>
              Cancel
            </Button>
            <Button
              onClick={() => mut.mutate()}
              disabled={mut.isPending || !label.trim() || !bankId}
            >
              {mut.isPending ? "Creating…" : "Create account"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function BankAccountsPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);

  const accountsQuery = useQuery({
    queryKey: ["banking", "accounts"],
    queryFn: listAccounts,
    retry: false,
  });

  const banksQuery = useQuery({
    queryKey: ["banking", "banks"],
    queryFn: listBanks,
    retry: false,
  });

  const deleteMut = useMutation({
    mutationFn: (accountId: string) => deleteAccount(accountId),
    onSuccess: () => {
      toast.success("Account deleted");
      void qc.invalidateQueries({ queryKey: ["banking", "accounts"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to delete account"),
  });

  // Feature-flag off: backend returns 404 (router not registered).
  const isFeatureOff =
    accountsQuery.error instanceof ApiError &&
    (accountsQuery.error.status === 404 || accountsQuery.error.status === 503);

  if (isFeatureOff) {
    return (
      <div className="p-6 max-w-4xl mx-auto space-y-6">
        <PageHeader title="Bank Accounts" description="Open Banking (ACC-001..ACC-004)" />
        <FeatureDisabled />
      </div>
    );
  }

  const accounts = accountsQuery.data?.accounts ?? [];
  const bankIds = (banksQuery.data?.banks ?? []).map((b) => b.bank_id);

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <PageHeader
        title="Bank Accounts"
        description="Manage your linked bank accounts and view balances"
        actions={
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void qc.invalidateQueries({ queryKey: ["banking"] });
              }}
              disabled={accountsQuery.isFetching}
            >
              <RefreshCw
                className={`h-4 w-4 mr-1 ${accountsQuery.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Add Account
            </Button>
          </div>
        }
      />

      {/* Loading state */}
      {accountsQuery.isLoading && (
        <div className="grid gap-4 sm:grid-cols-2">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-5 w-40" />
                <Skeleton className="h-4 w-24 mt-1" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-6 w-28" />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Error state (non-feature-flag errors) */}
      {accountsQuery.isError && !isFeatureOff && (
        <Card className="border-destructive">
          <CardContent className="flex items-center gap-3 py-6">
            <AlertCircle className="h-5 w-5 text-destructive" />
            <p className="text-sm text-destructive">
              {accountsQuery.error instanceof Error
                ? accountsQuery.error.message
                : "Failed to load accounts"}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!accountsQuery.isLoading && !accountsQuery.isError && accounts.length === 0 && (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <Landmark className="h-10 w-10 text-muted-foreground" />
            <p className="text-muted-foreground text-sm">No bank accounts yet.</p>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Add your first account
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Accounts grid */}
      {accounts.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2">
          {accounts.map((acc) => (
            <AccountCard
              key={acc.account_id}
              account={acc}
              onDelete={(id) => deleteMut.mutate(id)}
              deleting={deleteMut.isPending && deleteMut.variables === acc.account_id}
            />
          ))}
        </div>
      )}

      <CreateAccountDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        bankIds={bankIds}
      />
    </div>
  );
}
