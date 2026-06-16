/**
 * OBP Bank Account Detail — transactions list + balance + account info (ACC-002..ACC-004)
 *
 * Route: /bank/accounts/:accountId
 * Handles feature-flag off (404/503) gracefully.
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  useQuery,
  useMutation,
  useInfiniteQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  ArrowLeftRight,
  ChevronDown,
  RefreshCw,
  AlertCircle,
  Tag,
  MessageSquare,
  FileText,
  MapPin,
  TrendingUp,
  TrendingDown,
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
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/api/client";
import {
  getAccount,
  getAccountBalance,
  listTransactions,
  getTransactionMetadata,
  putNarrative,
  addTag,
  removeTag,
  addComment,
  deleteComment,
  listAccountHolders,
  type AccountOut,
  type AccountBalanceOut,
  type TransactionOut,
  type TransactionMetadataOut,
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

/** Backend returns amount as decimal string e.g. "12.50" */
function fmtTxnAmount(value: string, currency: string): string {
  const num = parseFloat(value);
  return fmtCurrency(isNaN(num) ? 0 : num, currency);
}

function fmtDate(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function fmtDateShort(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function StatusBadge({ status }: { status: string }) {
  const variant =
    status === "settled"
      ? "default"
      : status === "pending"
        ? "secondary"
        : status === "reversed"
          ? "destructive"
          : "outline";
  return (
    <Badge variant={variant} className="text-xs capitalize">
      {status}
    </Badge>
  );
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
            The bank accounts feature is currently disabled.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Balance card ─────────────────────────────────────────────────────────────

function BalanceCard({
  accountId,
}: {
  accountId: string;
}) {
  const { data: balance } = useQuery<AccountBalanceOut>({
    queryKey: ["banking", "balance", accountId],
    queryFn: () => getAccountBalance(accountId),
    retry: false,
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-muted-foreground font-normal">
          Current Balance
        </CardTitle>
      </CardHeader>
      <CardContent>
        {balance ? (
          <div>
            <p className="text-3xl font-bold font-mono">
              {fmtCurrency(balance.current, balance.currency)}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              Available: {fmtCurrency(balance.available, balance.currency)}
            </p>
          </div>
        ) : (
          <Skeleton className="h-9 w-40" />
        )}
      </CardContent>
    </Card>
  );
}

// ─── Account details card ─────────────────────────────────────────────────────

function AccountDetailsCard({ account }: { account: AccountOut }) {
  const holdersQuery = useQuery({
    queryKey: ["banking", "holders", account.account_id],
    queryFn: () => listAccountHolders(account.account_id),
    retry: false,
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Account Details</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-muted-foreground">Account ID</span>
          <span className="font-mono text-xs">{account.account_id}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Type</span>
          <span className="uppercase">{account.account_type}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Bank</span>
          <span>{account.bank_id}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Currency</span>
          <span className="uppercase">{account.currency}</span>
        </div>
        {account.iban && (
          <div className="flex justify-between">
            <span className="text-muted-foreground">IBAN</span>
            <span className="font-mono text-xs">{account.iban}</span>
          </div>
        )}
        {account.routing_number && (
          <div className="flex justify-between">
            <span className="text-muted-foreground">Routing #</span>
            <span className="font-mono text-xs">{account.routing_number}</span>
          </div>
        )}
        {account.account_number_masked && (
          <div className="flex justify-between">
            <span className="text-muted-foreground">Account #</span>
            <span className="font-mono text-xs">{account.account_number_masked}</span>
          </div>
        )}
        <div className="flex justify-between">
          <span className="text-muted-foreground">Opened</span>
          <span>{fmtDateShort(account.created_at)}</span>
        </div>

        {/* Account holders */}
        {holdersQuery.data && holdersQuery.data.holders.length > 1 && (
          <>
            <Separator className="my-2" />
            <div>
              <p className="text-muted-foreground mb-1">Account Holders</p>
              {holdersQuery.data.holders.map((h) => (
                <div key={h.user_sub} className="flex items-center justify-between py-0.5">
                  <span className="font-mono text-xs truncate">{h.user_sub}</span>
                  {h.is_primary_owner && (
                    <Badge variant="secondary" className="text-xs">Primary</Badge>
                  )}
                </div>
              ))}
            </div>
          </>
        )}

        {/* Custom attributes */}
        {account.attributes.length > 0 && (
          <>
            <Separator className="my-2" />
            <div>
              <p className="text-muted-foreground mb-1">Attributes</p>
              {account.attributes.map((attr, i) => (
                <div key={i} className="flex justify-between py-0.5">
                  <span className="text-muted-foreground">{attr.name}</span>
                  <span>{attr.value}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Transaction metadata panel ───────────────────────────────────────────────

function TransactionMetadataPanel({
  accountId,
  transactionId,
}: {
  accountId: string;
  transactionId: string;
}) {
  const qc = useQueryClient();
  const [narrativeText, setNarrativeText] = useState("");
  const [tagValue, setTagValue] = useState("");
  const [commentText, setCommentText] = useState("");

  const metaQuery = useQuery<TransactionMetadataOut>({
    queryKey: ["banking", "txn-meta", accountId, transactionId],
    queryFn: () => getTransactionMetadata(accountId, transactionId),
    retry: false,
  });

  const narrativeMut = useMutation({
    mutationFn: () => putNarrative(accountId, transactionId, narrativeText.trim()),
    onSuccess: () => {
      toast.success("Narrative saved");
      setNarrativeText("");
      void qc.invalidateQueries({
        queryKey: ["banking", "txn-meta", accountId, transactionId],
      });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to save narrative"),
  });

  const tagMut = useMutation({
    mutationFn: () => addTag(accountId, transactionId, tagValue.trim()),
    onSuccess: () => {
      toast.success("Tag added");
      setTagValue("");
      void qc.invalidateQueries({
        queryKey: ["banking", "txn-meta", accountId, transactionId],
      });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to add tag"),
  });

  const removeTagMut = useMutation({
    mutationFn: (tagId: string) => removeTag(accountId, transactionId, tagId),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ["banking", "txn-meta", accountId, transactionId],
      });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to remove tag"),
  });

  const commentMut = useMutation({
    mutationFn: () => addComment(accountId, transactionId, commentText.trim()),
    onSuccess: () => {
      toast.success("Comment added");
      setCommentText("");
      void qc.invalidateQueries({
        queryKey: ["banking", "txn-meta", accountId, transactionId],
      });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to add comment"),
  });

  const deleteCommentMut = useMutation({
    mutationFn: (commentId: string) =>
      deleteComment(accountId, transactionId, commentId),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ["banking", "txn-meta", accountId, transactionId],
      });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to delete comment"),
  });

  if (metaQuery.isLoading) {
    return <Skeleton className="h-32 w-full" />;
  }

  const meta = metaQuery.data;

  return (
    <div className="space-y-4 pt-2">
      {/* Narrative */}
      <div>
        <div className="flex items-center gap-1 mb-1">
          <FileText className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Narrative
          </span>
        </div>
        {meta?.narrative ? (
          <p className="text-sm bg-muted rounded p-2">{meta.narrative.text}</p>
        ) : (
          <p className="text-xs text-muted-foreground italic">No narrative yet</p>
        )}
        <div className="flex gap-2 mt-2">
          <Input
            placeholder="Add or update narrative…"
            value={narrativeText}
            onChange={(e) => setNarrativeText(e.target.value)}
            className="text-sm h-8"
          />
          <Button
            size="sm"
            variant="outline"
            disabled={narrativeMut.isPending || !narrativeText.trim()}
            onClick={() => narrativeMut.mutate()}
          >
            Save
          </Button>
        </div>
      </div>

      {/* Geotag */}
      {meta?.geotag && (
        <div>
          <div className="flex items-center gap-1 mb-1">
            <MapPin className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
              Location
            </span>
          </div>
          <p className="text-sm">
            {meta.geotag.lat.toFixed(5)}, {meta.geotag.lon.toFixed(5)}
            {meta.geotag.label && ` — ${meta.geotag.label}`}
          </p>
        </div>
      )}

      {/* Tags */}
      <div>
        <div className="flex items-center gap-1 mb-1">
          <Tag className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Tags
          </span>
        </div>
        <div className="flex flex-wrap gap-1 mb-2">
          {(meta?.tags ?? []).map((t) => (
            <Badge
              key={t.tag_id}
              variant="secondary"
              className="text-xs cursor-pointer hover:bg-destructive hover:text-destructive-foreground"
              onClick={() => removeTagMut.mutate(t.tag_id)}
              title="Click to remove"
            >
              {t.value}
            </Badge>
          ))}
          {(meta?.tags ?? []).length === 0 && (
            <span className="text-xs text-muted-foreground italic">No tags</span>
          )}
        </div>
        <div className="flex gap-2">
          <Input
            placeholder="Add tag…"
            value={tagValue}
            onChange={(e) => setTagValue(e.target.value)}
            className="text-sm h-8"
            onKeyDown={(e) => {
              if (e.key === "Enter" && tagValue.trim()) tagMut.mutate();
            }}
          />
          <Button
            size="sm"
            variant="outline"
            disabled={tagMut.isPending || !tagValue.trim()}
            onClick={() => tagMut.mutate()}
          >
            Add
          </Button>
        </div>
      </div>

      {/* Comments */}
      <div>
        <div className="flex items-center gap-1 mb-1">
          <MessageSquare className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Comments
          </span>
        </div>
        <div className="space-y-1 mb-2">
          {(meta?.comments ?? []).map((c) => (
            <div
              key={c.comment_id}
              className="flex items-start justify-between gap-2 bg-muted rounded p-2"
            >
              <div>
                <p className="text-sm">{c.text}</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {fmtDate(c.created_at)}
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 text-muted-foreground hover:text-destructive shrink-0"
                onClick={() => deleteCommentMut.mutate(c.comment_id)}
                title="Delete comment"
              >
                ×
              </Button>
            </div>
          ))}
          {(meta?.comments ?? []).length === 0 && (
            <span className="text-xs text-muted-foreground italic">No comments</span>
          )}
        </div>
        <div className="flex gap-2">
          <Textarea
            placeholder="Add a comment…"
            value={commentText}
            onChange={(e) => setCommentText(e.target.value)}
            className="text-sm min-h-[60px] resize-none"
          />
          <Button
            size="sm"
            variant="outline"
            className="self-end"
            disabled={commentMut.isPending || !commentText.trim()}
            onClick={() => commentMut.mutate()}
          >
            Post
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Transaction row ──────────────────────────────────────────────────────────

function TransactionRow({ txn }: { txn: TransactionOut }) {
  const [metaOpen, setMetaOpen] = useState(false);

  const amountNum = parseFloat(txn.amount.value);
  const isNegative = amountNum < 0 || txn.type.includes("debit") || txn.type.includes("charge");

  return (
    <>
      <div
        className="flex items-center gap-3 py-3 hover:bg-muted/50 rounded px-2 cursor-pointer transition-colors"
        onClick={() => setMetaOpen(true)}
      >
        <div
          className={`h-8 w-8 rounded-full flex items-center justify-center shrink-0 ${
            isNegative
              ? "bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-400"
              : "bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-400"
          }`}
        >
          {isNegative ? (
            <TrendingDown className="h-4 w-4" />
          ) : (
            <TrendingUp className="h-4 w-4" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">
            {txn.description || txn.type}
          </p>
          <div className="flex items-center gap-2 mt-0.5">
            <p className="text-xs text-muted-foreground">{fmtDateShort(txn.posted_at)}</p>
            <StatusBadge status={txn.status} />
            {txn.has_metadata && (
              <Badge variant="outline" className="text-xs">
                Note
              </Badge>
            )}
          </div>
        </div>
        <div className="text-right shrink-0">
          <p
            className={`text-sm font-mono font-semibold ${
              isNegative ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"
            }`}
          >
            {isNegative ? "−" : "+"}
            {fmtTxnAmount(txn.amount.value.replace("-", ""), txn.amount.currency)}
          </p>
          <p className="text-xs text-muted-foreground font-mono">
            {fmtTxnAmount(txn.new_balance.value.replace("-", ""), txn.new_balance.currency)}
          </p>
        </div>
      </div>

      {/* Transaction detail dialog */}
      <Dialog open={metaOpen} onOpenChange={setMetaOpen}>
        <DialogContent className="max-w-lg max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ArrowLeftRight className="h-4 w-4" />
              Transaction Details
            </DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span>ID</span>
                  <span className="font-mono text-xs">{txn.transaction_id}</span>
                </div>
                <div className="flex justify-between">
                  <span>Amount</span>
                  <span className={`font-mono font-semibold ${isNegative ? "text-red-600" : "text-green-600"}`}>
                    {isNegative ? "−" : "+"}
                    {fmtTxnAmount(txn.amount.value.replace("-", ""), txn.amount.currency)}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Balance after</span>
                  <span className="font-mono">
                    {fmtTxnAmount(txn.new_balance.value.replace("-", ""), txn.new_balance.currency)}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Type</span>
                  <span>{txn.type}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>Status</span>
                  <StatusBadge status={txn.status} />
                </div>
                <div className="flex justify-between">
                  <span>Posted</span>
                  <span>{fmtDate(txn.posted_at)}</span>
                </div>
                {txn.provider && (
                  <div className="flex justify-between">
                    <span>Provider</span>
                    <span className="capitalize">{txn.provider}</span>
                  </div>
                )}
                {txn.description && (
                  <div className="flex justify-between">
                    <span>Description</span>
                    <span className="text-right max-w-[60%]">{txn.description}</span>
                  </div>
                )}
              </div>
            </DialogDescription>
          </DialogHeader>
          <Separator />
          <TransactionMetadataPanel
            accountId={txn.account_id}
            transactionId={txn.transaction_id}
          />
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── Transactions section ─────────────────────────────────────────────────────

function TransactionsSection({ accountId }: { accountId: string }) {
  const {
    data,
    isLoading,
    isError,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["banking", "transactions", accountId],
    queryFn: ({ pageParam }: { pageParam: string | undefined }) =>
      listTransactions(accountId, { limit: 25, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.cursor ?? undefined,
  });

  const transactions = data?.pages.flatMap((p) => p.transactions) ?? [];

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[1, 2, 3, 4, 5].map((i) => (
          <Skeleton key={i} className="h-14 w-full rounded" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 text-destructive text-sm py-4">
        <AlertCircle className="h-4 w-4" />
        {error instanceof Error ? error.message : "Failed to load transactions"}
      </div>
    );
  }

  if (transactions.length === 0) {
    return (
      <div className="text-center py-10 text-muted-foreground">
        <ArrowLeftRight className="h-8 w-8 mx-auto mb-2 opacity-40" />
        <p className="text-sm">No transactions yet</p>
      </div>
    );
  }

  return (
    <div>
      <div className="divide-y">
        {transactions.map((txn) => (
          <TransactionRow key={txn.transaction_id} txn={txn} />
        ))}
      </div>
      {hasNextPage && (
        <div className="text-center pt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? (
              <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <ChevronDown className="h-4 w-4 mr-1" />
            )}
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function BankAccountDetailPage() {
  const { accountId } = useParams<{ accountId: string }>();
  const qc = useQueryClient();

  const accountQuery = useQuery<AccountOut>({
    queryKey: ["banking", "account", accountId],
    queryFn: () => getAccount(accountId!),
    enabled: !!accountId,
    retry: false,
  });

  const isFeatureOff =
    accountQuery.error instanceof ApiError &&
    (accountQuery.error.status === 404 || accountQuery.error.status === 503);

  const account = accountQuery.data;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" asChild className="shrink-0">
          <Link to="/bank/accounts">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <PageHeader
          title={account ? account.label : "Bank Account"}
          description={account ? `${account.bank_id} · ${account.currency.toUpperCase()}` : ""}
          actions={
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                void qc.invalidateQueries({ queryKey: ["banking"] })
              }
              disabled={accountQuery.isFetching}
            >
              <RefreshCw
                className={`h-4 w-4 mr-1 ${accountQuery.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </Button>
          }
        />
      </div>

      {isFeatureOff && <FeatureDisabled />}

      {accountQuery.isError && !isFeatureOff && (
        <Card className="border-destructive">
          <CardContent className="flex items-center gap-3 py-6">
            <AlertCircle className="h-5 w-5 text-destructive" />
            <p className="text-sm text-destructive">
              {accountQuery.error instanceof Error
                ? accountQuery.error.message
                : "Failed to load account"}
            </p>
          </CardContent>
        </Card>
      )}

      {accountQuery.isLoading && (
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-32 lg:col-span-1" />
          <Skeleton className="h-48 lg:col-span-2" />
        </div>
      )}

      {account && (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Left column: balance + account details */}
          <div className="lg:col-span-1 space-y-4">
            <BalanceCard accountId={account.account_id} />
            <AccountDetailsCard account={account} />
          </div>

          {/* Right column: transactions */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <ArrowLeftRight className="h-4 w-4 text-muted-foreground" />
                  <CardTitle className="text-base">Transactions</CardTitle>
                </div>
                <CardDescription className="text-xs">
                  Click any row to view details and add notes, tags, or comments
                </CardDescription>
              </CardHeader>
              <CardContent>
                <TransactionsSection accountId={account.account_id} />
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
