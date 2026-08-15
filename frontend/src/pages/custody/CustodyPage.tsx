// Crypto Custody — one responsive React page (desktop + mobile web) for the
// testlogon `/ui/custody/*` backend: balances, deposit (address + QR),
// withdraw (with confirm step + status), activity (live-polled), and an
// officer/admin-only Approvals + hash-chained Audit tab.
import { useEffect, useMemo, useState } from "react";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Wallet,
  ArrowDownToLine,
  ArrowUpFromLine,
  ListChecks,
  ShieldCheck,
  Copy,
  Check,
  RefreshCw,
  Loader2,
  AlertTriangle,
  CircleCheck,
  Clock,
  Ban,
  XCircle,
  ScrollText,
} from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { cn } from "@/lib/utils";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Progress } from "@/components/ui/progress";

import QRCode from "@/components/custody/QRCode";
import {
  listCustodyAssets,
  getDepositAddress,
  listCustodyDeposits,
  createWithdrawal,
  listWithdrawals,
  getWithdrawal,
  listApprovals,
  approveWithdrawal,
  releaseWithdrawal,
  getCustodyAudit,
  verifyCustodyAudit,
  type CustodyAsset,
  type Withdrawal,
  type WithdrawalCreateResult,
  type WithdrawalStatus,
} from "@/api/endpoints/custody";

// ─── helpers ────────────────────────────────────────────────────

function useIsMobile(bp = 767): boolean {
  const [m, setM] = useState(
    () => typeof window !== "undefined" && window.matchMedia(`(max-width: ${bp}px)`).matches,
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

const TERMINAL: WithdrawalStatus[] = ["blocked", "rejected", "settled"];
function isTerminal(s: WithdrawalStatus): boolean {
  return TERMINAL.includes(s);
}

function statusBadge(status: WithdrawalStatus | string) {
  const map: Record<string, { variant: "default" | "secondary" | "destructive" | "success" | "warning" | "outline"; label: string; icon: JSX.Element }> = {
    screening: { variant: "secondary", label: "Screening", icon: <Loader2 className="h-3 w-3 animate-spin" /> },
    pending_approval: { variant: "warning", label: "Pending approval", icon: <Clock className="h-3 w-3" /> },
    signed: { variant: "success", label: "Signed", icon: <CircleCheck className="h-3 w-3" /> },
    broadcast: { variant: "default", label: "Broadcast", icon: <ArrowUpFromLine className="h-3 w-3" /> },
    settled: { variant: "success", label: "Settled", icon: <Check className="h-3 w-3" /> },
    blocked: { variant: "destructive", label: "Blocked", icon: <Ban className="h-3 w-3" /> },
    rejected: { variant: "destructive", label: "Rejected", icon: <XCircle className="h-3 w-3" /> },
  };
  const cfg = map[status] ?? { variant: "outline" as const, label: String(status), icon: <Clock className="h-3 w-3" /> };
  return (
    <Badge variant={cfg.variant} className="gap-1 whitespace-nowrap">
      {cfg.icon}
      {cfg.label}
    </Badge>
  );
}

function short(s?: string | null, head = 10, tail = 8): string {
  if (!s) return "";
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
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

function approvalsCount(w: Withdrawal): number {
  if (typeof w.approvals_count === "number") return w.approvals_count;
  if (Array.isArray(w.approvals)) return w.approvals.length;
  return 0;
}

// ─── Balances / Overview ────────────────────────────────────────

function OverviewTab({
  onDeposit,
  onWithdraw,
}: {
  onDeposit: (a: CustodyAsset) => void;
  onWithdraw: (a: CustodyAsset) => void;
}) {
  const { data: assets, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["custody", "assets"],
    queryFn: listCustodyAssets,
    staleTime: 15_000,
  });

  const nonZero = (assets ?? []).filter((a) => num(a.balance) > 0);
  const totalAssets = (assets ?? []).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Balances</h2>
          <p className="text-sm text-muted-foreground">
            {nonZero.length} funded / {totalAssets} supported assets
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} className="gap-1.5">
          <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
          Refresh
        </Button>
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
            <Button size="sm" onClick={() => refetch()}>Retry</Button>
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && totalAssets === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No custody assets are available for your account yet.
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && totalAssets > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {(assets ?? []).map((a) => {
            const bal = num(a.balance);
            return (
              <Card key={`${a.asset}-${a.chain}`} className={cn(bal > 0 && "ring-1 ring-primary/20")}>
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
                    <Badge variant="outline" className="text-[10px]">{a.symbol}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <span className="text-xl font-semibold tabular-nums">{fmtAmount(a.balance)}</span>{" "}
                    <span className="text-sm text-muted-foreground">{a.symbol}</span>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant="secondary" className="flex-1 gap-1" onClick={() => onDeposit(a)} disabled={!a.address_available}>
                      <ArrowDownToLine className="h-3.5 w-3.5" /> Deposit
                    </Button>
                    <Button size="sm" variant="secondary" className="flex-1 gap-1" onClick={() => onWithdraw(a)} disabled={bal <= 0}>
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

// ─── Deposit ────────────────────────────────────────────────────

function DepositTab({ preselect }: { preselect?: CustodyAsset | null }) {
  const { data: assets } = useQuery({
    queryKey: ["custody", "assets"],
    queryFn: listCustodyAssets,
    staleTime: 15_000,
  });
  const withAddr = (assets ?? []).filter((a) => a.address_available);
  const [selected, setSelected] = useState<string>("");

  useEffect(() => {
    if (preselect) {
      setSelected(`${preselect.asset}::${preselect.chain}`);
    } else if (!selected && withAddr.length > 0) {
      const first = withAddr[0]!;
      setSelected(`${first.asset}::${first.chain}`);
    }
  }, [preselect, withAddr, selected]);

  const [asset = "", chain = ""] = selected.split("::");
  const chosen = (assets ?? []).find((a) => a.asset === asset && a.chain === chain);

  const addrQuery = useQuery({
    queryKey: ["custody", "deposit-address", asset, chain],
    queryFn: () => getDepositAddress(asset, chain),
    enabled: Boolean(asset && chain),
    retry: false,
  });

  const depositsQuery = useQuery({
    queryKey: ["custody", "deposits"],
    queryFn: listCustodyDeposits,
    staleTime: 10_000,
  });

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
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
                {withAddr.map((a) => (
                  <SelectItem key={`${a.asset}::${a.chain}`} value={`${a.asset}::${a.chain}`}>
                    {a.name} ({a.symbol}) — {a.network}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {addrQuery.isLoading && <Skeleton className="h-48 w-full rounded-xl" />}

          {addrQuery.isError && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
              {(addrQuery.error as ApiError)?.detail ?? "Deposit address unavailable for this asset."}
            </div>
          )}

          {addrQuery.data && (
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

              {addrQuery.data.memo && (
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Memo / tag (required)</Label>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 break-all rounded-lg border bg-muted/40 p-2 font-mono text-sm">
                      {addrQuery.data.memo}
                    </div>
                    <CopyButton text={addrQuery.data.memo} label="Copy memo" />
                  </div>
                </div>
              )}

              <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
                <span>
                  Send only <strong>{chosen?.symbol ?? asset}</strong> on the{" "}
                  <strong>{addrQuery.data.network}</strong> network to this address. Sending any other
                  asset or using another network may result in permanent loss.
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent deposits</CardTitle>
        </CardHeader>
        <CardContent>
          {depositsQuery.isLoading && <Skeleton className="h-24 w-full" />}
          {!depositsQuery.isLoading && (depositsQuery.data ?? []).length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">No deposits yet.</p>
          )}
          {(depositsQuery.data ?? []).length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead className="text-right">Amount</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Conf.</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(depositsQuery.data ?? []).map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-medium">{d.asset}</TableCell>
                    <TableCell className="text-right tabular-nums">{fmtAmount(d.amount)}</TableCell>
                    <TableCell>
                      <Badge variant={d.status === "confirmed" || d.status === "credited" ? "success" : "secondary"}>
                        {d.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{d.confirmations}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Withdraw ───────────────────────────────────────────────────

function WithdrawResultView({ result }: { result: WithdrawalCreateResult }) {
  const status = result.status;
  if (status === "signed") {
    return (
      <div className="space-y-2 rounded-lg border border-success/40 bg-success/10 p-4">
        <div className="flex items-center gap-2 font-medium text-success">
          <CircleCheck className="h-5 w-5" /> Withdrawal signed
        </div>
        {result.signature && (
          <p className="break-all font-mono text-xs text-muted-foreground">sig: {short(result.signature, 14, 12)}</p>
        )}
        {result.digest && (
          <p className="break-all font-mono text-xs text-muted-foreground">digest: {short(result.digest, 14, 12)}</p>
        )}
      </div>
    );
  }
  if (status === "pending_approval") {
    const req = result.approvals_required ?? 2;
    const have = Array.isArray(result.approvals) ? result.approvals.length : num(result.approvals);
    return (
      <div className="space-y-2 rounded-lg border border-warning/40 bg-warning/10 p-4">
        <div className="flex items-center gap-2 font-medium text-warning">
          <Clock className="h-5 w-5" /> Awaiting officer approval
        </div>
        <p className="text-sm text-muted-foreground">
          {have} of {req} approvals collected. A custody officer must approve before this transfer is signed.
        </p>
        <Progress value={req > 0 ? (have / req) * 100 : 0} className="h-2" />
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
          {result.detail || result.error || `This destination was flagged${result.category ? ` (${result.category})` : ""}. The transfer was blocked and not signed.`}
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-2 rounded-lg border border-destructive/40 bg-destructive/10 p-4">
      <div className="flex items-center gap-2 font-medium text-destructive">
        <XCircle className="h-5 w-5" /> Rejected
      </div>
      <p className="text-sm text-muted-foreground">{result.detail || result.error || "The withdrawal was rejected."}</p>
    </div>
  );
}

function WithdrawTab({ preselect }: { preselect?: CustodyAsset | null }) {
  const qc = useQueryClient();
  const { data: assets } = useQuery({
    queryKey: ["custody", "assets"],
    queryFn: listCustodyAssets,
    staleTime: 15_000,
  });
  const funded = (assets ?? []).filter((a) => num(a.balance) > 0);

  const [selected, setSelected] = useState<string>("");
  const [amount, setAmount] = useState("");
  const [destination, setDestination] = useState("");
  const [memo, setMemo] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [result, setResult] = useState<WithdrawalCreateResult | null>(null);

  useEffect(() => {
    if (preselect) setSelected(`${preselect.asset}::${preselect.chain}`);
    else if (!selected && funded.length > 0) { const first = funded[0]!; setSelected(`${first.asset}::${first.chain}`); }
  }, [preselect, funded, selected]);

  const [asset = "", chain = ""] = selected.split("::");
  const chosen = (assets ?? []).find((a) => a.asset === asset && a.chain === chain);
  const balance = num(chosen?.balance);

  const amt = num(amount);
  const amountError =
    amount.trim() === ""
      ? ""
      : amt <= 0
        ? "Amount must be greater than 0."
        : amt > balance
          ? "Amount exceeds your available balance."
          : "";
  const destError = destination.trim() === "" ? "" : destination.trim().length < 8 ? "Destination address looks too short." : "";
  const canSubmit = Boolean(asset) && amt > 0 && amt <= balance && destination.trim().length >= 8;

  const mutation = useMutation({
    mutationFn: () =>
      createWithdrawal({
        asset,
        chain,
        amount: String(amt),
        destination: destination.trim(),
        memo: memo.trim() || undefined,
      }),
    onSuccess: (res) => {
      setResult(res);
      setConfirmOpen(false);
      qc.invalidateQueries({ queryKey: ["custody", "withdrawals"] });
      qc.invalidateQueries({ queryKey: ["custody", "assets"] });
      if (res.status === "signed") toast.success("Withdrawal signed");
      else if (res.status === "pending_approval") toast.message("Withdrawal awaiting approval");
      else if (res.status === "blocked") toast.error("Withdrawal blocked by screening");
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
            <Select value={selected} onValueChange={(v) => { setSelected(v); setResult(null); }}>
              <SelectTrigger>
                <SelectValue placeholder="Choose a funded asset" />
              </SelectTrigger>
              <SelectContent>
                {funded.length === 0 && <SelectItem value="__none" disabled>No funded assets</SelectItem>}
                {funded.map((a) => (
                  <SelectItem key={`${a.asset}::${a.chain}`} value={`${a.asset}::${a.chain}`}>
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

          <div className="space-y-1.5">
            <Label>Memo / tag (optional)</Label>
            <Input placeholder="Only if the network requires it" value={memo} onChange={(e) => setMemo(e.target.value)} />
          </div>

          <Button className="w-full gap-1.5" disabled={!canSubmit} onClick={() => { setResult(null); setConfirmOpen(true); }}>
            <ArrowUpFromLine className="h-4 w-4" /> Review withdrawal
          </Button>
        </CardContent>
      </Card>

      {result && <WithdrawResultView result={result} />}

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm withdrawal</DialogTitle>
            <DialogDescription>Review the details carefully — crypto transfers can't be reversed.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <div className="flex justify-between"><span className="text-muted-foreground">Asset</span><span className="font-medium">{chosen?.name} ({chosen?.symbol})</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Network</span><span className="font-medium">{chosen?.network}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Amount</span><span className="font-medium tabular-nums">{fmtAmount(amt)} {chosen?.symbol}</span></div>
            <Separator />
            <div className="space-y-1">
              <span className="text-muted-foreground">Destination</span>
              <div className="break-all font-mono text-xs">{destination.trim()}</div>
            </div>
            {memo.trim() && (
              <div className="flex justify-between"><span className="text-muted-foreground">Memo</span><span className="font-mono text-xs">{memo.trim()}</span></div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={mutation.isPending}>Cancel</Button>
            <Button onClick={() => mutation.mutate()} disabled={mutation.isPending} className="gap-1.5">
              {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Confirm & send
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Activity / History ─────────────────────────────────────────

function WithdrawalDetailDrawer({ id, open, onClose }: { id: string | null; open: boolean; onClose: () => void }) {
  const [now, setNow] = useState(Date.now());
  const detail = useQuery({
    queryKey: ["custody", "withdrawal", id],
    queryFn: () => getWithdrawal(id as string),
    enabled: Boolean(id) && open,
    refetchInterval: (q) => {
      const w = q.state.data as Withdrawal | undefined;
      return w && !isTerminal(w.status) ? 4000 : false;
    },
  });
  const w = detail.data;

  useEffect(() => {
    if (!open) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [open]);

  const timelockRemaining = w?.timelock_until_ms ? Math.max(0, w.timelock_until_ms - now) : 0;

  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Withdrawal detail</SheetTitle>
          <SheetDescription>{id}</SheetDescription>
        </SheetHeader>
        {detail.isLoading && <Skeleton className="mt-4 h-40 w-full" />}
        {w && (
          <div className="mt-4 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Status</span>
              {statusBadge(w.status)}
            </div>
            <Separator />
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-muted-foreground">Asset</span><span className="font-medium">{w.asset}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Network</span><span className="font-medium">{w.network ?? w.chain_ref ?? w.chain}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Amount</span><span className="font-medium tabular-nums">{fmtAmount(w.amount)}</span></div>
              <div className="space-y-0.5">
                <span className="text-muted-foreground">Recipient</span>
                <div className="break-all font-mono text-xs">{w.recipient ?? w.destination}</div>
              </div>
            </div>

            {(w.approvals_required ?? 0) > 0 && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Approvals</span>
                  <span className="font-medium">{approvalsCount(w)} / {w.approvals_required}</span>
                </div>
                <Progress value={(approvalsCount(w) / (w.approvals_required || 1)) * 100} className="h-2" />
                {Array.isArray(w.approvals) && w.approvals.length > 0 && (
                  <p className="text-xs text-muted-foreground">by {w.approvals.map((a) => short(a, 6, 4)).join(", ")}</p>
                )}
              </div>
            )}

            {timelockRemaining > 0 && (
              <div className="flex items-center gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm text-warning">
                <Clock className="h-4 w-4" />
                Timelocked — releasable in {Math.ceil(timelockRemaining / 1000)}s
              </div>
            )}

            {w.signature && (
              <div className="space-y-0.5 rounded-lg border bg-muted/30 p-3">
                <span className="text-xs text-muted-foreground">Signature</span>
                <div className="break-all font-mono text-xs">{w.signature}</div>
              </div>
            )}
            {w.digest && (
              <div className="space-y-0.5 rounded-lg border bg-muted/30 p-3">
                <span className="text-xs text-muted-foreground">Digest</span>
                <div className="break-all font-mono text-xs">{w.digest}</div>
              </div>
            )}
            {(w.error || w.category) && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                {w.category ? `[${w.category}] ` : ""}{w.error}
              </div>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

function ActivityTab() {
  const qc = useQueryClient();
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["custody", "withdrawals"],
    queryFn: listWithdrawals,
    refetchInterval: (q) => {
      const rows = (q.state.data as Withdrawal[] | undefined) ?? [];
      return rows.some((r) => !isTerminal(r.status)) ? 5000 : false;
    },
  });
  const [openId, setOpenId] = useState<string | null>(null);

  // Keep the list fresh when a detail drawer advances a status.
  useEffect(() => {
    if (!openId) qc.invalidateQueries({ queryKey: ["custody", "withdrawals"] });
  }, [openId, qc]);

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Withdrawal activity</h2>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} className="gap-1.5">
          <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} /> Refresh
        </Button>
      </div>
      <Card>
        <CardContent className="p-0">
          {isLoading && <div className="p-4"><Skeleton className="h-32 w-full" /></div>}
          {!isLoading && rows.length === 0 && (
            <p className="py-12 text-center text-sm text-muted-foreground">No withdrawals yet.</p>
          )}
          {rows.length > 0 && (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead className="text-right">Amount</TableHead>
                    <TableHead className="hidden md:table-cell">Recipient</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-16" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((w) => (
                    <TableRow key={w.id} className="cursor-pointer" onClick={() => setOpenId(w.id)}>
                      <TableCell className="font-medium">{w.asset}</TableCell>
                      <TableCell className="text-right tabular-nums">{fmtAmount(w.amount)}</TableCell>
                      <TableCell className="hidden font-mono text-xs md:table-cell">{short(w.recipient ?? w.destination)}</TableCell>
                      <TableCell>{statusBadge(w.status)}</TableCell>
                      <TableCell className="text-right"><Button variant="ghost" size="sm">View</Button></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
      <WithdrawalDetailDrawer id={openId} open={Boolean(openId)} onClose={() => setOpenId(null)} />
    </div>
  );
}

// ─── Approvals + Audit (officer/admin) ──────────────────────────

function ApprovalsTab() {
  const qc = useQueryClient();
  const approvals = useQuery({
    queryKey: ["custody", "approvals"],
    queryFn: listApprovals,
    refetchInterval: 8000,
  });

  const approveM = useMutation({
    mutationFn: (id: string) => approveWithdrawal(id),
    onSuccess: (res) => {
      toast.success(`Approved — ${typeof res.approvals === "number" ? res.approvals : (res.approvals?.length ?? 0)}/${res.approvals_required}`);
      qc.invalidateQueries({ queryKey: ["custody", "approvals"] });
      qc.invalidateQueries({ queryKey: ["custody", "withdrawals"] });
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.detail : "Approve failed"),
  });

  const releaseM = useMutation({
    mutationFn: (id: string) => releaseWithdrawal(id),
    onSuccess: () => {
      toast.success("Released & signed");
      qc.invalidateQueries({ queryKey: ["custody", "approvals"] });
      qc.invalidateQueries({ queryKey: ["custody", "withdrawals"] });
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 425) toast.error("Timelocked — cannot release yet");
      else if (err instanceof ApiError && err.status === 409) toast.error("Not enough approvals to release");
      else toast.error(err instanceof ApiError ? err.detail : "Release failed");
    },
  });

  const audit = useQuery({
    queryKey: ["custody", "audit"],
    queryFn: getCustodyAudit,
    staleTime: 10_000,
  });

  const verifyM = useMutation({
    mutationFn: verifyCustodyAudit,
    onSuccess: (res) => {
      if (res.ok) toast.success(`Audit chain verified — ${res.entries} entries intact`);
      else toast.error("Audit chain verification FAILED");
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.detail : "Verify failed"),
  });

  const rows = approvals.data ?? [];

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Approval queue</h2>
        <Card>
          <CardContent className="p-0">
            {approvals.isLoading && <div className="p-4"><Skeleton className="h-24 w-full" /></div>}
            {!approvals.isLoading && rows.length === 0 && (
              <p className="py-10 text-center text-sm text-muted-foreground">Nothing awaiting approval.</p>
            )}
            {rows.length > 0 && (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset</TableHead>
                      <TableHead className="text-right">Amount</TableHead>
                      <TableHead className="hidden md:table-cell">Recipient</TableHead>
                      <TableHead>Approvals</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((w) => {
                      const busy = (approveM.isPending && approveM.variables === w.id) || (releaseM.isPending && releaseM.variables === w.id);
                      return (
                        <TableRow key={w.id}>
                          <TableCell className="font-medium">{w.asset}</TableCell>
                          <TableCell className="text-right tabular-nums">{fmtAmount(w.amount)}</TableCell>
                          <TableCell className="hidden font-mono text-xs md:table-cell">{short(w.recipient ?? w.destination)}</TableCell>
                          <TableCell className="tabular-nums">{approvalsCount(w)}/{w.approvals_required ?? "?"}</TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-2">
                              <Button size="sm" variant="outline" disabled={busy} onClick={() => approveM.mutate(w.id)}>Approve</Button>
                              <Button size="sm" disabled={busy} onClick={() => releaseM.mutate(w.id)}>Release</Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-lg font-semibold"><ScrollText className="h-5 w-5" /> Audit trail</h2>
          <Button size="sm" variant="outline" onClick={() => verifyM.mutate()} disabled={verifyM.isPending} className="gap-1.5">
            {verifyM.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            Verify chain
          </Button>
        </div>
        <Card>
          <CardContent className="p-0">
            {audit.isLoading && <div className="p-4"><Skeleton className="h-24 w-full" /></div>}
            {!audit.isLoading && (audit.data?.entries ?? []).length === 0 && (
              <p className="py-10 text-center text-sm text-muted-foreground">No audit entries.</p>
            )}
            {(audit.data?.entries ?? []).length > 0 && (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12">#</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead className="hidden md:table-cell">Detail</TableHead>
                      <TableHead className="hidden sm:table-cell">Time</TableHead>
                      <TableHead>Hash</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(audit.data?.entries ?? []).map((e) => (
                      <TableRow key={e.seq}>
                        <TableCell className="tabular-nums text-muted-foreground">{e.seq}</TableCell>
                        <TableCell className="font-medium">{e.action}</TableCell>
                        <TableCell className="hidden max-w-xs truncate text-xs text-muted-foreground md:table-cell">{e.detail}</TableCell>
                        <TableCell className="hidden whitespace-nowrap text-xs text-muted-foreground sm:table-cell">{new Date(e.ts_ms).toLocaleString()}</TableCell>
                        <TableCell className="font-mono text-xs">{short(e.hash, 8, 6)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Page ───────────────────────────────────────────────────────

type TabKey = "overview" | "deposit" | "withdraw" | "activity" | "approvals";

export default function CustodyPage() {
  const isMobile = useIsMobile(767);
  const role = useAuthStore((s) => s.role);
  const isAdmin = useAuthStore((s) => s.isAdmin);
  const isOfficer = isAdmin || role === "admin" || role === "root";

  const [tab, setTab] = useState<TabKey>("overview");
  const [depositAsset, setDepositAsset] = useState<CustodyAsset | null>(null);
  const [withdrawAsset, setWithdrawAsset] = useState<CustodyAsset | null>(null);

  const tabs: { key: TabKey; label: string; short: string; icon: JSX.Element }[] = useMemo(() => {
    const base: { key: TabKey; label: string; short: string; icon: JSX.Element }[] = [
      { key: "overview" as const, label: "Balances", short: "Balances", icon: <Wallet className="h-4 w-4" /> },
      { key: "deposit" as const, label: "Deposit", short: "Deposit", icon: <ArrowDownToLine className="h-4 w-4" /> },
      { key: "withdraw" as const, label: "Withdraw", short: "Withdraw", icon: <ArrowUpFromLine className="h-4 w-4" /> },
      { key: "activity" as const, label: "Activity", short: "Activity", icon: <ListChecks className="h-4 w-4" /> },
    ];
    if (isOfficer) {
      base.push({ key: "approvals" as const, label: "Approvals & Audit", short: "Approvals", icon: <ShieldCheck className="h-4 w-4" /> });
    }
    return base;
  }, [isOfficer]);

  return (
    <div className="mx-auto w-full max-w-6xl p-4 md:p-6">
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
          <Wallet className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight md:text-2xl">Custody</h1>
          <p className="text-sm text-muted-foreground">Hold, receive and send crypto from your custodial wallet.</p>
        </div>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
        <TabsList className={cn("mb-4 w-full", isMobile ? "grid grid-cols-4 gap-1" : "inline-flex", isMobile && isOfficer && "grid-cols-5")}>
          {tabs.map((t) => (
            <TabsTrigger key={t.key} value={t.key} className="gap-1.5">
              {t.icon}
              <span className={cn(isMobile && "sr-only")}>{t.label}</span>
              {isMobile && <span className="text-[10px]">{t.short}</span>}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab
            onDeposit={(a) => { setDepositAsset(a); setTab("deposit"); }}
            onWithdraw={(a) => { setWithdrawAsset(a); setTab("withdraw"); }}
          />
        </TabsContent>
        <TabsContent value="deposit">
          <DepositTab preselect={depositAsset} />
        </TabsContent>
        <TabsContent value="withdraw">
          <WithdrawTab preselect={withdrawAsset} />
        </TabsContent>
        <TabsContent value="activity">
          <ActivityTab />
        </TabsContent>
        {isOfficer && (
          <TabsContent value="approvals">
            <ApprovalsTab />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
