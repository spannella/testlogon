/**
 * PLT-004: Sandbox data import tab.
 *
 * Admin + DEV_MODE only. Bulk-seeds test customers / accounts / transactions.
 * Endpoint: POST /v1/admin/sandbox/data-import
 * Flag: OPEN_BANK_PROJECT_ENABLED + SANDBOX_IMPORT_ENABLED + DEV_MODE
 * Returns 404 when disabled.
 */

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { FlaskConical, Plus, Trash2, CheckCircle, XCircle, Upload } from "lucide-react";

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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  sandboxImport,
  type SandboxCustomerIn,
  type SandboxAccountIn,
  type SandboxTransactionIn,
  type SandboxRowError,
  type SandboxImportResult,
} from "@/api/endpoints/bankPlatform";

type EntryType = "credit" | "debit" | "adjustment";

// ─── Empty row templates ─────────────────────────────────────────────────────

function emptyCustomer(): SandboxCustomerIn {
  return { email: "", full_name: "", user_sub: "" };
}

function emptyAccount(): SandboxAccountIn {
  return { user_sub: "", initial_balance_cents: 0, currency: "usd" };
}

function emptyTransaction(): SandboxTransactionIn {
  return { user_sub: "", entry_type: "credit", amount_cents: 0, reason: "", currency: "usd" };
}

// ─── Section header helper ────────────────────────────────────────────────────

function SectionHeader({ label, count, onAdd }: { label: string; count: number; onAdd: () => void }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <span className="font-medium text-sm">{label}</span>
        <Badge variant="secondary" className="text-xs">{count}</Badge>
      </div>
      <Button type="button" variant="outline" size="sm" onClick={onAdd} className="gap-1.5">
        <Plus className="h-3.5 w-3.5" />
        Add
      </Button>
    </div>
  );
}

// ─── Result display ───────────────────────────────────────────────────────────

function ImportResultCard({ result }: { result: SandboxImportResult }) {
  return (
    <Card className={result.ok ? "border-green-500" : "border-destructive"}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          {result.ok ? (
            <CheckCircle className="h-5 w-5 text-green-500" />
          ) : (
            <XCircle className="h-5 w-5 text-destructive" />
          )}
          Import {result.ok ? "completed" : "completed with errors"}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-4 text-sm mb-3">
          <span>Customers: <strong>{result.customers_created}</strong></span>
          <span>Accounts: <strong>{result.accounts_created}</strong></span>
          <span>Transactions: <strong>{result.transactions_created}</strong></span>
        </div>
        {result.errors.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <p className="text-xs font-medium text-destructive">Errors ({result.errors.length})</p>
            {result.errors.map((err, i) => (
              <ErrorRow key={i} err={err} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ErrorRow({ err }: { err: SandboxRowError }) {
  return (
    <div className="flex items-start gap-2 rounded border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs">
      <Badge variant="destructive" className="text-xs shrink-0">{err.section}[{err.index}]</Badge>
      <span className="text-muted-foreground">
        <strong>{err.code}</strong>: {err.message}
      </span>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function SandboxTab() {
  const [customers, setCustomers] = useState<SandboxCustomerIn[]>([emptyCustomer()]);
  const [accounts, setAccounts] = useState<SandboxAccountIn[]>([]);
  const [transactions, setTransactions] = useState<SandboxTransactionIn[]>([]);
  const [result, setResult] = useState<SandboxImportResult | null>(null);
  const [isNotEnabled, setIsNotEnabled] = useState(false);

  const importMut = useMutation({
    mutationFn: () =>
      sandboxImport({
        customers: customers.filter((c) => c.email.trim()),
        accounts: accounts.filter((a) => a.user_sub.trim()),
        transactions: transactions.filter((t) => t.user_sub.trim()),
      }),
    onSuccess: (data) => {
      setResult(data);
      toast[data.ok ? "success" : "warning"](
        data.ok
          ? "Sandbox import completed."
          : `Import completed with ${data.errors.length} error(s).`,
      );
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
        setIsNotEnabled(true);
        toast.error("Sandbox import is not available (requires DEV_MODE + SANDBOX_IMPORT_ENABLED).");
      } else {
        toast.error(err.message ?? "Import failed");
      }
    },
  });

  if (isNotEnabled) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FlaskConical className="h-5 w-5" />
            Sandbox Import
          </CardTitle>
          <CardDescription>
            Sandbox import is only available in dev mode. Set{" "}
            <code className="rounded bg-muted px-1 text-xs">DEV_MODE=1</code>,{" "}
            <code className="rounded bg-muted px-1 text-xs">OPEN_BANK_PROJECT_ENABLED=1</code>, and{" "}
            <code className="rounded bg-muted px-1 text-xs">SANDBOX_IMPORT_ENABLED=1</code>.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-lg font-semibold">Sandbox Data Import</h2>
        <p className="text-sm text-muted-foreground">
          Bulk-seed test customers, accounts, and transactions (PLT-004). Admin + DEV_MODE only.
        </p>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setResult(null);
          importMut.mutate();
        }}
        className="flex flex-col gap-6"
      >
        {/* Customers */}
        <Card>
          <CardHeader className="pb-2">
            <SectionHeader
              label="Customers"
              count={customers.length}
              onAdd={() => setCustomers((c) => [...c, emptyCustomer()])}
            />
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {customers.map((c, i) => (
              <div key={i} className="grid grid-cols-3 gap-2 items-end">
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">Email *</Label>
                  <Input
                    required
                    type="email"
                    placeholder="alice@example.com"
                    value={c.email}
                    onChange={(e) =>
                      setCustomers((prev) =>
                        prev.map((x, j) => (j === i ? { ...x, email: e.target.value } : x)),
                      )
                    }
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">Full name</Label>
                  <Input
                    placeholder="Alice Smith"
                    value={c.full_name ?? ""}
                    onChange={(e) =>
                      setCustomers((prev) =>
                        prev.map((x, j) =>
                          j === i ? { ...x, full_name: e.target.value } : x,
                        ),
                      )
                    }
                  />
                </div>
                <div className="flex items-end gap-1.5">
                  <div className="flex flex-col gap-1 flex-1">
                    <Label className="text-xs">User sub (optional)</Label>
                    <Input
                      placeholder="auto-generated"
                      value={c.user_sub ?? ""}
                      onChange={(e) =>
                        setCustomers((prev) =>
                          prev.map((x, j) =>
                            j === i ? { ...x, user_sub: e.target.value } : x,
                          ),
                        )
                      }
                    />
                  </div>
                  {customers.length > 1 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() =>
                        setCustomers((prev) => prev.filter((_, j) => j !== i))
                      }
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Accounts */}
        <Card>
          <CardHeader className="pb-2">
            <SectionHeader
              label="Accounts"
              count={accounts.length}
              onAdd={() => setAccounts((a) => [...a, emptyAccount()])}
            />
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {accounts.length === 0 && (
              <p className="text-xs text-muted-foreground">No accounts. Click Add to seed an account.</p>
            )}
            {accounts.map((a, i) => (
              <div key={i} className="grid grid-cols-3 gap-2 items-end">
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">User sub *</Label>
                  <Input
                    required
                    placeholder="user_sub"
                    value={a.user_sub}
                    onChange={(e) =>
                      setAccounts((prev) =>
                        prev.map((x, j) => (j === i ? { ...x, user_sub: e.target.value } : x)),
                      )
                    }
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">Initial balance (cents)</Label>
                  <Input
                    type="number"
                    min={0}
                    placeholder="0"
                    value={a.initial_balance_cents ?? 0}
                    onChange={(e) =>
                      setAccounts((prev) =>
                        prev.map((x, j) =>
                          j === i
                            ? { ...x, initial_balance_cents: parseInt(e.target.value) || 0 }
                            : x,
                        ),
                      )
                    }
                  />
                </div>
                <div className="flex items-end gap-1.5">
                  <div className="flex flex-col gap-1 flex-1">
                    <Label className="text-xs">Currency</Label>
                    <Input
                      placeholder="usd"
                      maxLength={3}
                      value={a.currency ?? "usd"}
                      onChange={(e) =>
                        setAccounts((prev) =>
                          prev.map((x, j) =>
                            j === i ? { ...x, currency: e.target.value } : x,
                          ),
                        )
                      }
                    />
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() =>
                      setAccounts((prev) => prev.filter((_, j) => j !== i))
                    }
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Transactions */}
        <Card>
          <CardHeader className="pb-2">
            <SectionHeader
              label="Transactions"
              count={transactions.length}
              onAdd={() => setTransactions((t) => [...t, emptyTransaction()])}
            />
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {transactions.length === 0 && (
              <p className="text-xs text-muted-foreground">No transactions. Click Add to seed a ledger entry.</p>
            )}
            {transactions.map((t, i) => (
              <div key={i} className="grid grid-cols-4 gap-2 items-end">
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">User sub *</Label>
                  <Input
                    required
                    placeholder="user_sub"
                    value={t.user_sub}
                    onChange={(e) =>
                      setTransactions((prev) =>
                        prev.map((x, j) => (j === i ? { ...x, user_sub: e.target.value } : x)),
                      )
                    }
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">Type</Label>
                  <Select
                    value={t.entry_type}
                    onValueChange={(v) =>
                      setTransactions((prev) =>
                        prev.map((x, j) =>
                          j === i ? { ...x, entry_type: v as EntryType } : x,
                        ),
                      )
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="credit">Credit</SelectItem>
                      <SelectItem value="debit">Debit</SelectItem>
                      <SelectItem value="adjustment">Adjustment</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex flex-col gap-1">
                  <Label className="text-xs">Amount (cents) *</Label>
                  <Input
                    type="number"
                    min={0}
                    required
                    placeholder="1000"
                    value={t.amount_cents}
                    onChange={(e) =>
                      setTransactions((prev) =>
                        prev.map((x, j) =>
                          j === i
                            ? { ...x, amount_cents: parseInt(e.target.value) || 0 }
                            : x,
                        ),
                      )
                    }
                  />
                </div>
                <div className="flex items-end gap-1.5">
                  <div className="flex flex-col gap-1 flex-1">
                    <Label className="text-xs">Reason *</Label>
                    <Input
                      required
                      placeholder="wallet_deposit"
                      value={t.reason}
                      onChange={(e) =>
                        setTransactions((prev) =>
                          prev.map((x, j) =>
                            j === i ? { ...x, reason: e.target.value } : x,
                          ),
                        )
                      }
                    />
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() =>
                      setTransactions((prev) => prev.filter((_, j) => j !== i))
                    }
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <div className="flex justify-start">
          <Button
            type="submit"
            disabled={importMut.isPending}
            className="gap-2"
          >
            <Upload className="h-4 w-4" />
            {importMut.isPending ? "Importing…" : "Run Import"}
          </Button>
        </div>
      </form>

      {result && <ImportResultCard result={result} />}
    </div>
  );
}
