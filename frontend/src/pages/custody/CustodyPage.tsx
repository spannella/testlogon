// Crypto Custody — one responsive React page (desktop + mobile web) for the
// PRODUCTION `/me/custody/*` gateway (via the exchange edge, which HMACs to
// the custody gateway itself). Backed tabs: Balances, Deposit (address + QR),
// Withdraw (confirm step + status). The gateway-internal / officer-only
// surfaces (Activity, Deposits list, Approvals & Audit) are kept as tabs but
// render a clear "not available on this backend" empty state — no API calls.
import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Wallet,
  ArrowDownToLine,
  ArrowUpFromLine,
  ListChecks,
  ShieldCheck,
  Layers,
  ArrowLeftRight,
  Copy,
  Check,
  RefreshCw,
  Loader2,
  AlertTriangle,
  CircleCheck,
  Clock,
  Ban,
  XCircle,
  Info,
  History,
} from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import { cn } from "@/lib/utils";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import QRCode from "@/components/custody/QRCode";
import {
  getBalance,
  getDepositAddress,
  getDeposits,
  withdraw,
  mergeBalances,
  CUSTODY_ASSETS,
  type CustodyDeposit,
  type DisplayAsset,
  type WithdrawResult,
} from "@/api/endpoints/custody";
import { SubaccountsTab, TransferTab } from "./CustodyExtras";

// ─── helpers ────────────────────────────────────────────────────

function useIsMobile(bp = 767): boolean {
  const [m, setM] = useState(
    () =>
      typeof window !== "undefined" &&
      window.matchMedia(`(max-width: ${bp}px)`).matches,
  );
  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${bp}px)`);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [bp]);
  return m;
}

function num(v: string | number | undefined | null): number {
  if (v == null) return 0;
  const n = typeof v === "number" ? v : parseFloat(v);
  return Number.isFinite(n) ? n : 0;
}

function fmtAmount(v: string | number | undefined | null): string {
  const n = num(v);
  if (n === 0) return "0";
  return n.toLocaleString(undefined, { maximumFractionDigits: 8 });
}

function short(s?: string | null, head = 10, tail = 8): string {
  if (!s) return "";
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

/** Map a chain id (string or number) to a human name via the asset registry. */
function chainName(chain: string | number | undefined): string {
  if (chain == null) return "Unknown";
  const id = Number(chain);
  if (Number.isFinite(id)) {
    const hit = CUSTODY_ASSETS.find((a) => a.chainId === id);
    if (hit) return hit.chainName;
    return `Chain ${chain}`;
  }
  return String(chain);
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          toast.success("Copied to clipboard");
          setTimeout(() => setCopied(false), 1500);
        } catch {
          toast.error("Could not copy");
        }
      }}
      className="gap-1.5"
    >
      {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      {copied ? "Copied" : label}
    </Button>
  );
}

/** Shared query for the vault balance. */
function useBalanceQuery() {
  return useQuery({
    queryKey: ["custody", "balance"],
    queryFn: getBalance,
    staleTime: 15_000,
  });
}

// ─── Balances / Overview ────────────────────────────────────────

function OverviewTab({
  onDeposit,
  onWithdraw,
}: {
  onDeposit: (a: DisplayAsset) => void;
  onWithdraw: (a: DisplayAsset) => void;
}) {
  const { data, isLoading, isError, refetch, isFetching } = useBalanceQuery();

  const rows = useMemo(() => mergeBalances(data?.balances), [data]);
  const nonZero = rows.filter((a) => num(a.balance) > 0);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold">Balances</h2>
          <p className="text-sm text-muted-foreground">
            {nonZero.length} funded / {rows.length} supported assets
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <div className="text-right text-xs text-muted-foreground">
              <div>
                Vault <span className="font-mono">{short(data.vault, 8, 6)}</span>
              </div>
              <div>
                Tier <Badge variant="outline" className="text-[10px]">{data.tier}</Badge>
              </div>
            </div>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="gap-1.5"
          >
            <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {isLoading && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-28 w-full rounded-xl" />
          ))}
        </div>
      )}

      {isError && (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-10 text-center">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-sm text-muted-foreground">Could not load balances.</p>
            <Button size="sm" onClick={() => refetch()}>
              Retry
            </Button>
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {rows.map((a) => {
            const bal = num(a.balance);
            return (
              <Card
                key={`${a.symbol}-${a.chainId}-${a.token}`}
                className={cn(bal > 0 && "ring-1 ring-primary/20")}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-xs font-bold text-primary">
                        {a.symbol.slice(0, 4)}
                      </div>
                      <div>
                        <CardTitle className="text-sm">{a.name}</CardTitle>
                        <p className="text-xs text-muted-foreground">{a.network}</p>
                      </div>
                    </div>
                    <Badge variant="outline" className="text-[10px]">
                      {a.symbol}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <span className="text-xl font-semibold tabular-nums">
                      {fmtAmount(a.balance)}
                    </span>{" "}
                    <span className="text-sm text-muted-foreground">{a.symbol}</span>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="secondary"
                      className="flex-1 gap-1"
                      onClick={() => onDeposit(a)}
                      disabled={a.unknown}
                    >
                      <ArrowDownToLine className="h-3.5 w-3.5" /> Deposit
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      className="flex-1 gap-1"
                      onClick={() => onWithdraw(a)}
                      disabled={bal <= 0 || a.unknown}
                    >
                      <ArrowUpFromLine className="h-3.5 w-3.5" /> Withdraw
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Incoming transfers (deposit-scanner feed) ──────────────────

function TxHashCell({ txhash }: { txhash: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={txhash}
      className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(txhash);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          /* ignore */
        }
      }}
    >
      {short(txhash, 8, 6)}
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

function IncomingTransfers() {
  const isMobile = useIsMobile(767);
  const q = useQuery({
    queryKey: ["custody", "deposits"],
    queryFn: getDeposits,
    refetchInterval: 15_000,
    retry: false,
  });

  const deposits: CustodyDeposit[] = q.data?.deposits ?? [];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <History className="h-5 w-5 text-primary" /> Recent incoming transfers
        </CardTitle>
      </CardHeader>
      <CardContent>
        {q.isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full rounded-lg" />
            ))}
          </div>
        )}

        {!q.isLoading && q.isError && (
          <div className="flex items-start gap-2 rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <span>Deposit scanning isn&apos;t available on this backend yet.</span>
          </div>
        )}

        {!q.isLoading && !q.isError && deposits.length === 0 && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No incoming transfers detected yet — send funds to the address above.
          </p>
        )}

        {!q.isLoading && !q.isError && deposits.length > 0 && (
          isMobile ? (
            <div className="space-y-2">
              {deposits.map((d) => (
                <div
                  key={`${d.txhash}-${d.log_index}`}
                  className="rounded-lg border p-3 text-sm"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold tabular-nums">
                      {fmtAmount(d.amount)} {d.asset}
                    </span>
                    <span className="text-xs text-muted-foreground">{chainName(d.chain)}</span>
                  </div>
                  <div className="mt-1">
                    <TxHashCell txhash={d.txhash} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs uppercase text-muted-foreground">
                    <th className="py-2 pr-3 font-medium">Chain</th>
                    <th className="py-2 pr-3 font-medium">Asset</th>
                    <th className="py-2 pr-3 text-right font-medium">Amount</th>
                    <th className="py-2 font-medium">Tx</th>
                  </tr>
                </thead>
                <tbody>
                  {deposits.map((d) => (
                    <tr
                      key={`${d.txhash}-${d.log_index}`}
                      className="border-b last:border-0"
                    >
                      <td className="py-2 pr-3">{chainName(d.chain)}</td>
                      <td className="py-2 pr-3 font-medium">{d.asset}</td>
                      <td className="py-2 pr-3 text-right tabular-nums">
                        {fmtAmount(d.amount)}
                      </td>
                      <td className="py-2">
                        <TxHashCell txhash={d.txhash} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </CardContent>
    </Card>
  );
}


// ─── Deposit ────────────────────────────────────────────────────

function DepositTab({ preselect }: { preselect?: DisplayAsset | null }) {
  const { data } = useBalanceQuery();
  const assets = useMemo(
    () => mergeBalances(data?.balances).filter((a) => !a.unknown),
    [data],
  );
  const [selected, setSelected] = useState<string>("");

  useEffect(() => {
    if (preselect && !preselect.unknown) {
      setSelected(preselect.symbol);
    } else if (!selected && assets.length > 0) {
      setSelected(assets[0]!.symbol);
    }
  }, [preselect, assets, selected]);

  const chosen = assets.find((a) => a.symbol === selected);

  const addrQuery = useQuery({
    queryKey: ["custody", "deposit-address", chosen?.chainId],
    queryFn: () => getDepositAddress(chosen!.chainId),
    enabled: Boolean(chosen),
    retry: false,
    staleTime: 60_000,
  });

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowDownToLine className="h-5 w-5 text-primary" /> Receive crypto
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Asset / network</Label>
            <Select value={selected} onValueChange={setSelected}>
              <SelectTrigger>
                <SelectValue placeholder="Choose an asset" />
              </SelectTrigger>
              <SelectContent>
                {assets.map((a) => (
                  <SelectItem key={a.symbol} value={a.symbol}>
                    {a.name} ({a.symbol}) — {a.network}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {addrQuery.isLoading && <Skeleton className="h-48 w-full rounded-xl" />}

          {addrQuery.isError && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
              {(addrQuery.error as ApiError)?.detail ??
                "Deposit address unavailable for this chain."}
            </div>
          )}

          {addrQuery.data && chosen && (
            <div className="space-y-4">
              <div className="flex justify-center rounded-xl border bg-white p-4">
                <QRCode value={addrQuery.data.address} size={192} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">Deposit address</Label>
                <div className="break-all rounded-lg border bg-muted/40 p-3 font-mono text-sm">
                  {addrQuery.data.address}
                </div>
                <div className="flex flex-wrap gap-2 pt-1">
                  <CopyButton text={addrQuery.data.address} label="Copy address" />
                </div>
              </div>

              <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
                <span>
                  This is a per-chain address. Send only assets on{" "}
                  <strong>{chosen.chainName}</strong> (chain {chosen.chainId}) to
                  this address. Sending assets from another network may result in
                  permanent loss.
                </span>
              </div>

              <div className="grid grid-cols-1 gap-1 text-[11px] text-muted-foreground sm:grid-cols-3">
                <div>
                  <span className="block font-medium text-foreground/70">Family</span>
                  {addrQuery.data.family}
                </div>
                <div>
                  <span className="block font-medium text-foreground/70">Derivation</span>
                  <span className="break-all">{addrQuery.data.derivation}</span>
                </div>
                <div>
                  <span className="block font-medium text-foreground/70">Domain</span>
                  <span className="break-all">{addrQuery.data.domain}</span>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <IncomingTransfers />
    </div>
  );
}

// ─── Withdraw ───────────────────────────────────────────────────

function WithdrawResultView({ result }: { result: WithdrawResult }) {
  const status = result.status;
  if (status === "signed") {
    return (
      <div className="space-y-2 rounded-lg border border-success/40 bg-success/10 p-4">
        <div className="flex items-center gap-2 font-medium text-success">
          <CircleCheck className="h-5 w-5" /> Withdrawal signed
        </div>
        {result.withdrawal_id && (
          <p className="break-all font-mono text-xs text-muted-foreground">
            id: {result.withdrawal_id}
          </p>
        )}
        {result.signature && (
          <p className="break-all font-mono text-xs text-muted-foreground">
            sig: {short(result.signature, 14, 12)}
          </p>
        )}
        {result.digest && (
          <p className="break-all font-mono text-xs text-muted-foreground">
            digest: {short(result.digest, 14, 12)}
          </p>
        )}
      </div>
    );
  }
  if (status === "pending_approval") {
    const req = result.approvals_required;
    const have = Array.isArray(result.approvals)
      ? result.approvals.length
      : typeof result.approvals === "number"
        ? result.approvals
        : undefined;
    return (
      <div className="space-y-2 rounded-lg border border-warning/40 bg-warning/10 p-4">
        <div className="flex items-center gap-2 font-medium text-warning">
          <Clock className="h-5 w-5" /> Awaiting officer approval
        </div>
        <p className="text-sm text-muted-foreground">
          This is a governed withdrawal. A custody officer must approve it before
          it is signed and broadcast.
          {typeof req === "number" &&
            ` ${have ?? 0} of ${req} approvals collected.`}
        </p>
        {result.intent_id && (
          <p className="break-all font-mono text-xs text-muted-foreground">
            intent: {result.intent_id}
          </p>
        )}
      </div>
    );
  }
  if (status === "blocked") {
    return (
      <div className="space-y-2 rounded-lg border border-destructive/40 bg-destructive/10 p-4">
        <div className="flex items-center gap-2 font-medium text-destructive">
          <Ban className="h-5 w-5" /> Blocked by screening
        </div>
        <p className="text-sm text-muted-foreground">
          {result.detail ||
            result.reason ||
            result.error ||
            `This destination was flagged${
              result.category ? ` (${result.category})` : ""
            }. The transfer was blocked and not signed.`}
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-2 rounded-lg border border-destructive/40 bg-destructive/10 p-4">
      <div className="flex items-center gap-2 font-medium text-destructive">
        <XCircle className="h-5 w-5" />{" "}
        {status === "rejected" ? "Rejected" : "Withdrawal error"}
      </div>
      <p className="text-sm text-muted-foreground">
        {result.detail ||
          result.reason ||
          result.error ||
          "The withdrawal was rejected."}
      </p>
    </div>
  );
}

function WithdrawTab({ preselect }: { preselect?: DisplayAsset | null }) {
  const qc = useQueryClient();
  const { data } = useBalanceQuery();
  const funded = useMemo(
    () => mergeBalances(data?.balances).filter((a) => num(a.balance) > 0 && !a.unknown),
    [data],
  );

  const [selected, setSelected] = useState<string>("");
  const [amount, setAmount] = useState("");
  const [destination, setDestination] = useState("");
  const [tokenOverride, setTokenOverride] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [result, setResult] = useState<WithdrawResult | null>(null);

  useEffect(() => {
    if (preselect && !preselect.unknown) setSelected(preselect.symbol);
    else if (!selected && funded.length > 0) setSelected(funded[0]!.symbol);
  }, [preselect, funded, selected]);

  const chosen = funded.find((a) => a.symbol === selected);
  const balance = num(chosen?.balance);
  const isErc20 = Boolean(chosen && chosen.token !== "native");
  const effectiveToken =
    (showAdvanced && tokenOverride.trim()) || chosen?.token || "native";

  const amt = num(amount);
  const amountError =
    amount.trim() === ""
      ? ""
      : amt <= 0
        ? "Amount must be greater than 0."
        : amt > balance
          ? "Amount exceeds your available balance."
          : "";
  const destError =
    destination.trim() === ""
      ? ""
      : destination.trim().length < 8
        ? "Destination address looks too short."
        : "";
  const canSubmit =
    Boolean(chosen) &&
    amt > 0 &&
    amt <= balance &&
    destination.trim().length >= 8;

  const mutation = useMutation({
    mutationFn: () =>
      withdraw({
        chain: String(chosen!.chainId),
        to: destination.trim(),
        amount: String(amt),
        token: effectiveToken,
      }),
    onSuccess: (res) => {
      setResult(res);
      setConfirmOpen(false);
      qc.invalidateQueries({ queryKey: ["custody", "balance"] });
      if (res.status === "signed") toast.success("Withdrawal signed");
      else if (res.status === "pending_approval")
        toast.message("Withdrawal awaiting approval");
      else if (res.status === "blocked")
        toast.error("Withdrawal blocked by screening");
      else toast.error("Withdrawal rejected");
    },
    onError: (err) => {
      setConfirmOpen(false);
      toast.error(err instanceof ApiError ? err.detail : "Withdrawal failed");
    },
  });

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowUpFromLine className="h-5 w-5 text-primary" /> Send crypto
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Asset</Label>
            <Select
              value={selected}
              onValueChange={(v) => {
                setSelected(v);
                setResult(null);
                setTokenOverride("");
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder="Choose a funded asset" />
              </SelectTrigger>
              <SelectContent>
                {funded.length === 0 && (
                  <SelectItem value="__none" disabled>
                    No funded assets
                  </SelectItem>
                )}
                {funded.map((a) => (
                  <SelectItem key={a.symbol} value={a.symbol}>
                    {a.name} ({a.symbol}) — {fmtAmount(a.balance)} available
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label>Amount</Label>
              {chosen && (
                <button
                  type="button"
                  className="text-xs text-primary hover:underline"
                  onClick={() => setAmount(String(balance))}
                >
                  Max: {fmtAmount(balance)} {chosen.symbol}
                </button>
              )}
            </div>
            <Input
              inputMode="decimal"
              placeholder="0.00"
              value={amount}
              onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
            />
            {amountError && <p className="text-xs text-destructive">{amountError}</p>}
          </div>

          <div className="space-y-1.5">
            <Label>Destination address</Label>
            <Input
              placeholder={`${chosen?.symbol ?? ""} address`}
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              className="font-mono text-sm"
            />
            {destError && <p className="text-xs text-destructive">{destError}</p>}
          </div>

          {chosen && (
            <div className="rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
              <div className="flex justify-between">
                <span>Chain</span>
                <span className="font-medium text-foreground">
                  {chosen.chainName} (chain {chosen.chainId})
                </span>
              </div>
              <div className="mt-1 flex justify-between">
                <span>Token</span>
                <span className="font-mono text-foreground">
                  {isErc20 ? short(effectiveToken, 8, 6) : "native"}
                </span>
              </div>
            </div>
          )}

          {isErc20 && (
            <div className="space-y-1.5">
              <button
                type="button"
                className="text-xs text-primary hover:underline"
                onClick={() => setShowAdvanced((v) => !v)}
              >
                {showAdvanced ? "Hide" : "Advanced:"} token contract override
              </button>
              {showAdvanced && (
                <Input
                  placeholder={chosen?.token}
                  value={tokenOverride}
                  onChange={(e) => setTokenOverride(e.target.value)}
                  className="font-mono text-xs"
                />
              )}
            </div>
          )}

          <Button
            className="w-full gap-1.5"
            disabled={!canSubmit}
            onClick={() => {
              setResult(null);
              setConfirmOpen(true);
            }}
          >
            <ArrowUpFromLine className="h-4 w-4" /> Review withdrawal
          </Button>
        </CardContent>
      </Card>

      {result && <WithdrawResultView result={result} />}

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm withdrawal</DialogTitle>
            <DialogDescription>
              Review the details carefully — crypto transfers can't be reversed.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Asset</span>
              <span className="font-medium">
                {chosen?.name} ({chosen?.symbol})
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Chain</span>
              <span className="font-medium">
                {chosen?.chainName} ({chosen?.chainId})
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Amount</span>
              <span className="font-medium tabular-nums">
                {fmtAmount(amt)} {chosen?.symbol}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Token</span>
              <span className="font-mono text-xs">
                {isErc20 ? short(effectiveToken, 10, 8) : "native"}
              </span>
            </div>
            <Separator />
            <div className="space-y-1">
              <span className="text-muted-foreground">Destination</span>
              <div className="break-all font-mono text-xs">{destination.trim()}</div>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setConfirmOpen(false)}
              disabled={mutation.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
              className="gap-1.5"
            >
              {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Confirm & send
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Degraded (gateway-internal / officer-only) tabs ────────────

function NotAvailable({
  icon,
  title,
  line,
}: {
  icon: JSX.Element;
  title: string;
  line: string;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
          {icon}
        </div>
        <div className="space-y-1">
          <p className="font-medium">{title}</p>
          <p className="mx-auto max-w-md text-sm text-muted-foreground">{line}</p>
        </div>
        <Badge variant="outline" className="gap-1.5">
          <Info className="h-3 w-3" /> Not available on this backend
        </Badge>
      </CardContent>
    </Card>
  );
}

// ─── Page ───────────────────────────────────────────────────────

type TabKey =
  | "overview"
  | "deposit"
  | "withdraw"
  | "subaccounts"
  | "transfer"
  | "activity"
  | "approvals";

export default function CustodyPage() {
  const isMobile = useIsMobile(767);

  const [tab, setTab] = useState<TabKey>("overview");
  const [depositAsset, setDepositAsset] = useState<DisplayAsset | null>(null);
  const [withdrawAsset, setWithdrawAsset] = useState<DisplayAsset | null>(null);

  const tabs: { key: TabKey; label: string; short: string; icon: JSX.Element }[] =
    useMemo(
      () => [
        {
          key: "overview" as const,
          label: "Balances",
          short: "Balances",
          icon: <Wallet className="h-4 w-4" />,
        },
        {
          key: "deposit" as const,
          label: "Deposit",
          short: "Deposit",
          icon: <ArrowDownToLine className="h-4 w-4" />,
        },
        {
          key: "withdraw" as const,
          label: "Withdraw",
          short: "Withdraw",
          icon: <ArrowUpFromLine className="h-4 w-4" />,
        },
        {
          key: "subaccounts" as const,
          label: "Sub-accounts",
          short: "Subaccts",
          icon: <Layers className="h-4 w-4" />,
        },
        {
          key: "transfer" as const,
          label: "Transfer",
          short: "Transfer",
          icon: <ArrowLeftRight className="h-4 w-4" />,
        },
        {
          key: "activity" as const,
          label: "Activity",
          short: "Activity",
          icon: <ListChecks className="h-4 w-4" />,
        },
        {
          key: "approvals" as const,
          label: "Approvals & Audit",
          short: "Approvals",
          icon: <ShieldCheck className="h-4 w-4" />,
        },
      ],
      [],
    );

  return (
    <div className="mx-auto w-full max-w-6xl p-4 md:p-6">
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
          <Wallet className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight md:text-2xl">Custody</h1>
          <p className="text-sm text-muted-foreground">
            Hold, receive and send crypto from your custodial vault.
          </p>
        </div>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
        <TabsList
          className={cn(
            "mb-4 w-full",
            isMobile
              ? "flex justify-start gap-1 overflow-x-auto"
              : "inline-flex",
          )}
        >
          {tabs.map((t) => (
            <TabsTrigger
              key={t.key}
              value={t.key}
              className={cn(
                "gap-1.5",
                isMobile && "flex-none shrink-0 px-2.5",
              )}
            >
              {t.icon}
              <span className={cn(isMobile && "sr-only")}>{t.label}</span>
              {isMobile && <span className="text-[11px]">{t.short}</span>}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab
            onDeposit={(a) => {
              setDepositAsset(a);
              setTab("deposit");
            }}
            onWithdraw={(a) => {
              setWithdrawAsset(a);
              setTab("withdraw");
            }}
          />
        </TabsContent>
        <TabsContent value="deposit">
          <DepositTab preselect={depositAsset} />
        </TabsContent>
        <TabsContent value="withdraw">
          <WithdrawTab preselect={withdrawAsset} />
        </TabsContent>
        <TabsContent value="subaccounts">
          <SubaccountsTab />
        </TabsContent>
        <TabsContent value="transfer">
          <TransferTab />
        </TabsContent>
        <TabsContent value="activity">
          <NotAvailable
            icon={<ListChecks className="h-6 w-6" />}
            title="Transfer history isn't exposed here"
            line="Deposit and withdrawal history is tracked inside the custody gateway and isn't served by the /me/custody API. Your live balances above reflect completed transfers."
          />
        </TabsContent>
        <TabsContent value="approvals">
          <NotAvailable
            icon={<ShieldCheck className="h-6 w-6" />}
            title="Approvals & audit are officer-only"
            line="The governed-withdrawal approval queue and hash-chained audit trail are internal custody-officer tools and aren't available on the account-facing /me/custody API."
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
