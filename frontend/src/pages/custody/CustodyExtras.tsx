// Custody gap-closing surfaces: Sub-accounts + Transfers.
// These wire to exchange-edge routes that 404 until the edge deploys, so every
// query/mutation degrades gracefully to an "unavailable" state (retry:false).
// The custody<->trading bridge (fund/settle x spot/margin) and the vault<->vault
// transfer are now REAL (atomic, reversal-on-failure) — no "simulated" framing.
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
  fundSpot,
  settleSpot,
  fundMargin,
  settleMargin,
  CUSTODY_ASSETS,
  type Subaccount,
  type SubaccountTransferResult,
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

  const all: Subaccount[] = q.data?.subaccounts ?? [];
  // The base vault is the entry with an empty label; named ones have a label.
  const baseVault = all.find((s) => !s.label || s.label.trim() === "");
  const named = all.filter((s) => s.label && s.label.trim() !== "");

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
          {baseVault && (
            <button
              type="button"
              onClick={() => setSelected(null)}
              className={cn(
                "flex w-full rounded-lg border p-3 text-left transition",
                isMobile ? "flex-col gap-1" : "items-center justify-between",
                selected === null ? "ring-1 ring-primary/40" : "hover:bg-muted/40",
              )}
            >
              <span className="flex items-center gap-2">
                <Wallet className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">Base vault</span>
                <Badge variant="outline" className="text-[10px]">default</Badge>
              </span>
              <span className="break-all font-mono text-xs text-muted-foreground">
                {baseVault.vault}
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

          {!q.isLoading && !q.isError && named.length === 0 && (
            <p className="py-4 text-center text-sm text-muted-foreground">
              No named sub-accounts yet — create one below to organise balances.
            </p>
          )}

          {!q.isLoading &&
            !q.isError &&
            named.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => setSelected(s.label)}
                className={cn(
                  "flex w-full flex-col gap-1 rounded-lg border p-3 text-left transition",
                  selected === s.label ? "ring-1 ring-primary/40" : "hover:bg-muted/40",
                )}
              >
                <div
                  className={cn(
                    "flex gap-2",
                    isMobile ? "flex-col" : "items-center justify-between",
                  )}
                >
                  <span className="flex items-center gap-2">
                    <Layers className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">{s.label}</span>
                  </span>
                  {s.vault && (
                    <span className="break-all font-mono text-xs text-muted-foreground">
                      {s.vault}
                    </span>
                  )}
                </div>
              </button>
            ))}
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

// ─── (a) custody <-> trading bridge (fund/settle x spot/margin) ──

type BridgeAction = "fund-spot" | "settle-spot" | "fund-margin" | "settle-margin";

interface BridgeResultView {
  ok: boolean;
  amount?: string | number;
  me_amount?: string | number;
  spot?: unknown;
  margin?: unknown;
  reason?: string;
}

const BRIDGE_ACTIONS: { value: BridgeAction; label: string; verb: string }[] = [
  { value: "fund-spot", label: "Custody → Spot", verb: "Fund spot" },
  { value: "settle-spot", label: "Spot → Custody", verb: "Settle spot" },
  { value: "fund-margin", label: "Custody → Margin", verb: "Fund margin" },
  { value: "settle-margin", label: "Margin → Custody", verb: "Settle margin" },
];

function reasonText(reason?: string): string {
  if (!reason) return "Transfer failed";
  if (reason === "insufficient_spot_available") return "Insufficient spot available";
  return reason.replace(/_/g, " ");
}

function BridgeTransfer() {
  const [action, setAction] = useState<BridgeAction>("fund-spot");
  const [assetSymbol, setAssetSymbol] = useState<string>(CUSTODY_ASSETS[0]!.symbol);
  const [amount, setAmount] = useState("");
  const [result, setResult] = useState<BridgeResultView | null>(null);

  const amt = num(amount);
  const amtError =
    amount.trim() === "" ? "" : amt <= 0 ? "Amount must be greater than 0." : "";
  const canSubmit = amt > 0;

  const mutation = useMutation({
    mutationFn: async (): Promise<BridgeResultView> => {
      const req = { token: assetSymbol, amount: amount.trim() };
      switch (action) {
        case "fund-spot": {
          const r = await fundSpot(req);
          return { ok: r.funded === true, amount: r.amount, me_amount: r.me_amount, spot: r.spot };
        }
        case "settle-spot": {
          const r = await settleSpot(req);
          return { ok: r.settled === true, amount: r.amount, me_amount: r.me_amount, spot: r.spot, reason: r.reason };
        }
        case "fund-margin": {
          const r = await fundMargin(req);
          return { ok: r.funded === true, amount: r.amount, me_amount: r.me_amount, margin: r.margin, reason: r.reason };
        }
        case "settle-margin": {
          const r = await settleMargin(req);
          return { ok: r.settled === true, amount: r.amount, me_amount: r.me_amount, margin: r.margin, reason: r.reason };
        }
      }
    },
    onSuccess: (res) => {
      setResult(res);
      if (res.ok) toast.success("Transfer settled");
      else toast.error(reasonText(res.reason));
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 422) {
        const reason = (err.body as { reason?: string } | undefined)?.reason;
        setResult({ ok: false, reason });
        toast.error(reasonText(reason));
      } else if (isUnavailable(err)) {
        toast.error("Custody ↔ trading bridge isn't available on this backend yet");
      } else {
        toast.error(err instanceof ApiError ? err.detail : "Transfer failed");
      }
    },
  });

  const current = BRIDGE_ACTIONS.find((a) => a.value === action)!;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-5 w-5 text-primary" /> Custody ↔ Trading
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Action</Label>
            <Select
              value={action}
              onValueChange={(v) => {
                setAction(v as BridgeAction);
                setResult(null);
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {BRIDGE_ACTIONS.map((a) => (
                  <SelectItem key={a.value} value={a.value}>
                    {a.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
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
              inputMode="decimal"
              placeholder="0.00"
              value={amount}
              onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
            />
            {amtError && <p className="text-xs text-destructive">{amtError}</p>}
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
            {current.verb}
          </Button>
        </CardContent>
      </Card>

      {result && <BridgeResultCard result={result} symbol={assetSymbol} />}
    </div>
  );
}

function BridgeResultCard({ result, symbol }: { result: BridgeResultView; symbol: string }) {
  if (!result.ok) {
    return (
      <div className="space-y-1 rounded-lg border border-destructive/40 bg-destructive/5 p-4">
        <span className="flex items-center gap-2 font-medium">
          <AlertTriangle className="h-5 w-5 text-destructive" />
          {reasonText(result.reason)}
        </span>
      </div>
    );
  }
  return (
    <div className="space-y-2 rounded-lg border border-success/40 bg-success/10 p-4">
      <span className="flex items-center gap-2 font-medium">
        <CircleCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
        Transfer settled
      </span>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {result.amount != null && (
          <div className="flex justify-between">
            <dt>Amount</dt>
            <dd className="tabular-nums text-foreground">
              {fmtAmount(result.amount)} {symbol}
            </dd>
          </div>
        )}
        {result.me_amount != null && (
          <div className="flex justify-between">
            <dt>Engine amount</dt>
            <dd className="tabular-nums text-foreground">{fmtAmount(result.me_amount)}</dd>
          </div>
        )}
        {result.spot != null && (
          <div className="col-span-2 flex justify-between">
            <dt>Spot</dt>
            <dd className="break-all text-foreground">{String(result.spot)}</dd>
          </div>
        )}
        {result.margin != null && (
          <div className="col-span-2 flex justify-between">
            <dt>Margin</dt>
            <dd className="break-all text-foreground">{String(result.margin)}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

// ─── (b) between sub-accounts (REAL atomic move) ────────────────

const BASE = "__base__";

function InternalTransfer() {
  const isMobile = useIsMobile();
  const q = useSubaccountsQuery();
  const named: Subaccount[] = (q.data?.subaccounts ?? []).filter(
    (s) => s.label && s.label.trim() !== "",
  );

  const [fromLabel, setFromLabel] = useState<string>(BASE);
  const [toLabel, setToLabel] = useState<string>(BASE);
  const [assetSymbol, setAssetSymbol] = useState<string>(CUSTODY_ASSETS[0]!.symbol);
  const [amount, setAmount] = useState("");
  const [result, setResult] = useState<SubaccountTransferResult | null>(null);

  const options = useMemo(
    () => [
      { value: BASE, label: "Base vault (default)" },
      ...named.map((s) => ({ value: s.label, label: s.label })),
    ],
    [named],
  );

  const amt = num(amount);
  const sameError = fromLabel === toLabel ? "From and To must differ." : "";
  const amtError =
    amount.trim() === "" ? "" : amt <= 0 ? "Amount must be greater than 0." : "";
  const canSubmit = amt > 0 && fromLabel !== toLabel;

  const mutation = useMutation({
    mutationFn: () =>
      transferBetweenSubaccounts({
        from_label: fromLabel === BASE ? undefined : fromLabel,
        to_label: toLabel === BASE ? undefined : toLabel,
        asset: assetSymbol,
        amount: amount.trim(),
      }),
    onSuccess: (res) => {
      setResult(res);
      toast.success("Transfer settled");
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

      {result && (
        <div className="space-y-2 rounded-lg border border-success/40 bg-success/10 p-4">
          <span className="flex items-center gap-2 font-medium">
            <CircleCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
            Transfer settled
          </span>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <dt>Asset</dt>
              <dd className="text-foreground">{String(result.asset)}</dd>
            </div>
            <div className="flex justify-between">
              <dt>Amount</dt>
              <dd className="tabular-nums text-foreground">{fmtAmount(result.amount)}</dd>
            </div>
            <div className="col-span-2 flex justify-between">
              <dt>From</dt>
              <dd className="font-mono text-foreground">{String(result.from)}</dd>
            </div>
            <div className="flex justify-between pl-4">
              <dt>New balance</dt>
              <dd className="tabular-nums text-foreground">{fmtAmount(result.from_balance)}</dd>
            </div>
            <div className="col-span-2 flex justify-between">
              <dt>To</dt>
              <dd className="font-mono text-foreground">{String(result.to)}</dd>
            </div>
            <div className="flex justify-between pl-4">
              <dt>New balance</dt>
              <dd className="tabular-nums text-foreground">{fmtAmount(result.to_balance)}</dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  );
}
