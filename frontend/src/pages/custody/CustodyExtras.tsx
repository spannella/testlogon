// Custody gap-closing surfaces: Sub-accounts + Transfers.
// Both wire to NEW exchange-edge routes that 404 until the edge deploys, so
// every query/mutation degrades gracefully to an "unavailable" state
// (retry:false) and every simulated (stub:true) response is surfaced honestly
// with a "simulated / not settled" badge so a user never mistakes a no-op for
// a real settled transfer.
import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Layers,
  Plus,
  ArrowLeftRight,
  Loader2,
  Info,
  AlertTriangle,
  CircleCheck,
  RefreshCw,
  Wallet,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  getSubaccounts,
  createSubaccount,
  transferBetweenSubaccounts,
  custodyTradingTransfer,
  CUSTODY_ASSETS,
  type Subaccount,
  type TransferResult,
} from "@/api/endpoints/custody";

// ─── small shared bits ──────────────────────────────────────────

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

function isUnavailable(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 501);
}

function UnavailableCard({ line }: { line: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-14 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Info className="h-6 w-6" />
        </div>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">{line}</p>
        <Badge variant="outline" className="gap-1.5">
          <Info className="h-3 w-3" /> Not available on this backend yet
        </Badge>
      </CardContent>
    </Card>
  );
}

/** Honest "this move is simulated, not settled" badge for stub responses. */
function SimulatedBadge() {
  return (
    <Badge
      variant="outline"
      className="gap-1 border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
    >
      <AlertTriangle className="h-3 w-3" /> Simulated · not settled
    </Badge>
  );
}

function TransferResultView({ result }: { result: TransferResult }) {
  const stub = result.stub === true;
  return (
    <div
      className={cn(
        "space-y-2 rounded-lg border p-4",
        stub
          ? "border-amber-500/40 bg-amber-500/5"
          : "border-success/40 bg-success/10",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-2 font-medium">
          <CircleCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          Transfer accepted
        </span>
        {stub && <SimulatedBadge />}
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {result.from != null && (
          <div className="col-span-2 flex justify-between">
            <dt>From</dt>
            <dd className="font-mono text-foreground">{String(result.from)}</dd>
          </div>
        )}
        {result.to != null && (
          <div className="col-span-2 flex justify-between">
            <dt>To</dt>
            <dd className="font-mono text-foreground">{String(result.to)}</dd>
          </div>
        )}
        {result.direction != null && (
          <div className="flex justify-between">
            <dt>Direction</dt>
            <dd className="text-foreground">{String(result.direction)}</dd>
          </div>
        )}
        {result.asset != null && (
          <div className="flex justify-between">
            <dt>Asset</dt>
            <dd className="text-foreground">{String(result.asset)}</dd>
          </div>
        )}
        {result.amount != null && (
          <div className="flex justify-between">
            <dt>Amount</dt>
            <dd className="tabular-nums text-foreground">
              {fmtAmount(result.amount as number | string)}
            </dd>
          </div>
        )}
        {result.trading_credited != null && (
          <div className="flex justify-between">
            <dt>Trading credited</dt>
            <dd className="text-foreground">
              {result.trading_credited ? "yes" : "no"}
            </dd>
          </div>
        )}
      </dl>
      {result.note && (
        <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          {result.note}
        </p>
      )}
    </div>
  );
}

// ─── shared subaccounts query ───────────────────────────────────

function useSubaccountsQuery() {
  return useQuery({
    queryKey: ["custody", "subaccounts"],
    queryFn: getSubaccounts,
    retry: false,
    staleTime: 15_000,
  });
}

// ─── Sub-accounts tab ───────────────────────────────────────────

export function SubaccountsTab() {
  const isMobile = useIsMobile();
  const qc = useQueryClient();
  const q = useSubaccountsQuery();
  const [label, setLabel] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const subs: Subaccount[] = q.data?.subaccounts ?? [];

  const sanitized = label.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 48);
  const labelError =
    label.trim() !== "" && sanitized === ""
      ? "Label must contain letters, numbers, - or _."
      : "";

  const create = useMutation({
    mutationFn: () => createSubaccount(sanitized),
    onSuccess: (sa) => {
      toast.success(`Sub-account "${sa.label ?? sanitized}" created`);
      setLabel("");
      qc.invalidateQueries({ queryKey: ["custody", "subaccounts"] });
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.detail : "Could not create sub-account");
    },
  });

  if (!q.isLoading && q.isError && isUnavailable(q.error)) {
    return (
      <UnavailableCard line="Sub-account vaults aren't served by this backend yet. Once the exchange edge is deployed, you'll be able to create and manage named vaults under your custody account here." />
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <Layers className="h-5 w-5 text-primary" /> Sub-accounts
            </CardTitle>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              onClick={() => q.refetch()}
              disabled={q.isFetching}
            >
              <RefreshCw className={cn("h-4 w-4", q.isFetching && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {q.data?.default_vault && (
            <button
              type="button"
              onClick={() => setSelected(null)}
              className={cn(
                "flex w-full rounded-lg border p-3 text-left transition",
                isMobile
                  ? "flex-col gap-1"
                  : "items-center justify-between",
                selected === null ? "ring-1 ring-primary/40" : "hover:bg-muted/40",
              )}
            >
              <span className="flex items-center gap-2">
                <Wallet className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">Base vault</span>
                <Badge variant="outline" className="text-[10px]">default</Badge>
              </span>
              <span className="break-all font-mono text-xs text-muted-foreground">
                {q.data.default_vault}
              </span>
            </button>
          )}

          {q.isLoading && (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full rounded-lg" />
              ))}
            </div>
          )}

          {!q.isLoading && q.isError && (
            <div className="flex items-start gap-2 rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Could not load sub-accounts. Please try again.</span>
            </div>
          )}

          {!q.isLoading && !q.isError && subs.length === 0 && (
            <p className="py-4 text-center text-sm text-muted-foreground">
              No named sub-accounts yet — create one below to organise balances.
            </p>
          )}

          {!q.isLoading &&
            !q.isError &&
            subs.map((s) => {
              const bal = s.balances ?? {};
              const funded = Object.entries(bal).filter(([, v]) => num(v) > 0);
              return (
                <button
                  key={s.id ?? s.label}
                  type="button"
                  onClick={() => setSelected(s.label)}
                  className={cn(
                    "flex w-full flex-col gap-1 rounded-lg border p-3 text-left transition",
                    selected === s.label
                      ? "ring-1 ring-primary/40"
                      : "hover:bg-muted/40",
                  )}
                >
                  <div
                    className={cn(
                      "flex gap-2",
                      isMobile
                        ? "flex-col"
                        : "items-center justify-between",
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <Layers className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm font-medium">{s.label}</span>
                      {s.tier && (
                        <Badge variant="outline" className="text-[10px]">{s.tier}</Badge>
                      )}
                    </span>
                    {s.vault && (
                      <span className="break-all font-mono text-xs text-muted-foreground">
                        {s.vault}
                      </span>
                    )}
                  </div>
                  {funded.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 pt-0.5">
                      {funded.map(([asset, v]) => (
                        <span
                          key={asset}
                          className="rounded bg-muted px-1.5 py-0.5 text-[11px] tabular-nums text-muted-foreground"
                        >
                          {fmtAmount(v)} {asset}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-[11px] text-muted-foreground">No balances</span>
                  )}
                </button>
              );
            })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Plus className="h-5 w-5 text-primary" /> Create sub-account
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="sub-label">Label</Label>
            <Input
              id="sub-label"
              placeholder="e.g. trading, savings, desk-2"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={64}
            />
            {labelError ? (
              <p className="text-xs text-destructive">{labelError}</p>
            ) : (
              sanitized !== label &&
              sanitized !== "" && (
                <p className="text-xs text-muted-foreground">
                  Will be created as <span className="font-mono">{sanitized}</span>
                </p>
              )
            )}
          </div>
          <Button
            className="w-full gap-1.5"
            disabled={sanitized === "" || create.isPending}
            onClick={() => create.mutate()}
          >
            {create.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Plus className="h-4 w-4" />
            )}
            Create sub-account
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Transfer tab ───────────────────────────────────────────────

type TransferMode = "bridge" | "internal";

export function TransferTab() {
  const [mode, setMode] = useState<TransferMode>("bridge");

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <div className="grid grid-cols-2 gap-1 rounded-lg border bg-muted/30 p-1">
        <button
          type="button"
          onClick={() => setMode("bridge")}
          className={cn(
            "rounded-md px-3 py-1.5 text-sm font-medium transition",
            mode === "bridge"
              ? "bg-background shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          Custody ↔ Trading
        </button>
        <button
          type="button"
          onClick={() => setMode("internal")}
          className={cn(
            "rounded-md px-3 py-1.5 text-sm font-medium transition",
            mode === "internal"
              ? "bg-background shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          Between sub-accounts
        </button>
      </div>

      {mode === "bridge" ? <BridgeTransfer /> : <InternalTransfer />}
    </div>
  );
}

// ─── (a) custody <-> trading bridge ─────────────────────────────

function BridgeTransfer() {
  const [direction, setDirection] = useState<"to_trading" | "to_custody">("to_trading");
  const [assetSymbol, setAssetSymbol] = useState<string>(CUSTODY_ASSETS[0]!.symbol);
  const [amount, setAmount] = useState("");
  const [result, setResult] = useState<TransferResult | null>(null);

  const asset = CUSTODY_ASSETS.find((a) => a.symbol === assetSymbol);
  // The bridge credit path is keyed by an engine asset id (int). We map the
  // registry chainId as the engine asset id proxy (asset id 0 = no-op).
  const engineAssetId = asset ? asset.chainId : 0;

  const amt = num(amount);
  const amtError =
    amount.trim() === ""
      ? ""
      : amt <= 0
        ? "Amount must be greater than 0."
        : !Number.isInteger(amt)
          ? "Bridge amount must be a whole number."
          : "";
  const canSubmit = amt > 0 && Number.isInteger(amt);

  const mutation = useMutation({
    mutationFn: () =>
      custodyTradingTransfer({ direction, asset: engineAssetId, amount: amt }),
    onSuccess: (res) => {
      setResult(res);
      if (res.stub) toast.message("Transfer accepted (simulated)");
      else toast.success("Transfer accepted");
    },
    onError: (err) => {
      if (isUnavailable(err)) {
        toast.error("Custody ↔ trading bridge isn't available on this backend yet");
      } else {
        toast.error(err instanceof ApiError ? err.detail : "Transfer failed");
      }
    },
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-5 w-5 text-primary" /> Custody ↔ Trading
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-1 rounded-lg border bg-muted/30 p-1">
            <button
              type="button"
              onClick={() => {
                setDirection("to_trading");
                setResult(null);
              }}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm font-medium transition",
                direction === "to_trading"
                  ? "bg-background shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              To trading
            </button>
            <button
              type="button"
              onClick={() => {
                setDirection("to_custody");
                setResult(null);
              }}
              className={cn(
                "rounded-md px-3 py-1.5 text-sm font-medium transition",
                direction === "to_custody"
                  ? "bg-background shadow-sm"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              To custody
            </button>
          </div>

          <div className="space-y-1.5">
            <Label>Asset</Label>
            <Select value={assetSymbol} onValueChange={setAssetSymbol}>
              <SelectTrigger>
                <SelectValue placeholder="Choose an asset" />
              </SelectTrigger>
              <SelectContent>
                {CUSTODY_ASSETS.map((a) => (
                  <SelectItem key={a.symbol} value={a.symbol}>
                    {a.name} ({a.symbol})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label>Amount</Label>
            <Input
              inputMode="numeric"
              placeholder="0"
              value={amount}
              onChange={(e) => setAmount(e.target.value.replace(/[^0-9]/g, ""))}
            />
            {amtError && <p className="text-xs text-destructive">{amtError}</p>}
          </div>

          <div className="flex items-start gap-2 rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              The custody vault and the exchange spot ledger are separate systems.
              This bridge is a best-effort, non-atomic operation and is reported as
              simulated until the atomic bridge is wired end-to-end.
            </span>
          </div>

          <Button
            className="w-full gap-1.5"
            disabled={!canSubmit || mutation.isPending}
            onClick={() => {
              setResult(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ArrowLeftRight className="h-4 w-4" />
            )}
            {direction === "to_trading" ? "Move to trading" : "Move to custody"}
          </Button>
        </CardContent>
      </Card>

      {result && <TransferResultView result={result} />}
    </div>
  );
}

// ─── (b) between sub-accounts ───────────────────────────────────

const BASE = "__base__";

function InternalTransfer() {
  const isMobile = useIsMobile();
  const q = useSubaccountsQuery();
  const subs: Subaccount[] = q.data?.subaccounts ?? [];

  const [fromLabel, setFromLabel] = useState<string>(BASE);
  const [toLabel, setToLabel] = useState<string>(BASE);
  const [assetSymbol, setAssetSymbol] = useState<string>(CUSTODY_ASSETS[0]!.symbol);
  const [amount, setAmount] = useState("");
  const [result, setResult] = useState<TransferResult | null>(null);

  const options = useMemo(
    () => [{ value: BASE, label: "Base vault (default)" }, ...subs.map((s) => ({ value: s.label, label: s.label }))],
    [subs],
  );

  const amt = num(amount);
  const sameError = fromLabel === toLabel ? "From and To must differ." : "";
  const amtError =
    amount.trim() === "" ? "" : amt <= 0 ? "Amount must be greater than 0." : "";
  const canSubmit = amt > 0 && fromLabel !== toLabel;

  const mutation = useMutation({
    mutationFn: () =>
      transferBetweenSubaccounts({
        from_label: fromLabel === BASE ? "" : fromLabel,
        to_label: toLabel === BASE ? "" : toLabel,
        asset: assetSymbol,
        amount: amt,
      }),
    onSuccess: (res) => {
      setResult(res);
      if (res.stub) toast.message("Transfer accepted (simulated)");
      else toast.success("Transfer accepted");
    },
    onError: (err) => {
      if (isUnavailable(err)) {
        toast.error("Sub-account transfers aren't available on this backend yet");
      } else {
        toast.error(err instanceof ApiError ? err.detail : "Transfer failed");
      }
    },
  });

  if (!q.isLoading && q.isError && isUnavailable(q.error)) {
    return (
      <UnavailableCard line="Sub-account transfers aren't served by this backend yet. Once the exchange edge is deployed, you'll be able to move assets between your own vaults here." />
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-5 w-5 text-primary" /> Between sub-accounts
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className={cn("grid gap-3", isMobile ? "grid-cols-1" : "grid-cols-2")}>
            <div className="space-y-1.5">
              <Label>From</Label>
              <Select value={fromLabel} onValueChange={(v) => { setFromLabel(v); setResult(null); }}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {options.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>To</Label>
              <Select value={toLabel} onValueChange={(v) => { setToLabel(v); setResult(null); }}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {options.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {sameError && <p className="text-xs text-destructive">{sameError}</p>}

          <div className="space-y-1.5">
            <Label>Asset</Label>
            <Select value={assetSymbol} onValueChange={setAssetSymbol}>
              <SelectTrigger>
                <SelectValue placeholder="Choose an asset" />
              </SelectTrigger>
              <SelectContent>
                {CUSTODY_ASSETS.map((a) => (
                  <SelectItem key={a.symbol} value={a.symbol}>
                    {a.name} ({a.symbol})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label>Amount</Label>
            <Input
              inputMode="decimal"
              placeholder="0.00"
              value={amount}
              onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
            />
            {amtError && <p className="text-xs text-destructive">{amtError}</p>}
          </div>

          <div className="flex items-start gap-2 rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              The custody gateway has no vault↔vault move route, so this transfer
              is validated but performs no balance change — it is reported as
              simulated so it can never mint or destroy funds.
            </span>
          </div>

          <Button
            className="w-full gap-1.5"
            disabled={!canSubmit || mutation.isPending}
            onClick={() => {
              setResult(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ArrowLeftRight className="h-4 w-4" />
            )}
            Transfer
          </Button>
        </CardContent>
      </Card>

      {result && <TransferResultView result={result} />}
    </div>
  );
}
