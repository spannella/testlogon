// Custody Staking — real gateway-backed yield staking surface for the
// `/me/staking/*` routes (served via the exchange edge, which HMACs to the
// custody gateway itself). Three reads/writes:
//   GET  /me/staking/providers  → available yield providers
//   GET  /me/staking/positions  → the caller's positions (principal/rewards/total)
//   POST /me/staking/stake      → stake an amount with a provider
// Every route MAY 404/403 (not custody-gated / not deployed) → degrade
// gracefully to a clear "not available on this backend" state. principal/
// rewards/total are decimal STRING amounts.
import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Sprout,
  RefreshCw,
  Loader2,
  Info,
  AlertTriangle,
  CircleCheck,
  Coins,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  getStakingProviders,
  getStakingPositions,
  stake,
  type StakingProvider,
  type StakingPosition,
} from "@/api/endpoints/custody";

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

/** True when an error is a 404/403 — the "not available on this backend" case. */
function isUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 404 || err.status === 403;
  const msg = (err as Error)?.message ?? "";
  return /\b40[34]\b/.test(msg);
}

function StatusBadge({ status }: { status?: string }) {
  const s = (status ?? "").toLowerCase();
  const ok = s === "active" || s === "staked" || s === "bonded";
  const pending = s === "pending" || s === "activating" || s === "unbonding";
  return (
    <Badge
      variant="outline"
      className={cn(
        "text-[10px] capitalize",
        ok && "border-emerald-500/40 text-emerald-600 dark:text-emerald-400",
        pending && "border-amber-500/40 text-amber-600 dark:text-amber-400",
      )}
    >
      {status || "unknown"}
    </Badge>
  );
}

function NotAvailable({ line }: { line: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Sprout className="h-6 w-6" />
        </div>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">{line}</p>
        <Badge variant="outline" className="gap-1.5">
          <Info className="h-3 w-3" /> Not available on this backend
        </Badge>
      </CardContent>
    </Card>
  );
}

// ─── Positions ──────────────────────────────────────────────────

function PositionsSection({
  positions,
  vault,
  isLoading,
  isError,
  error,
  refetch,
  isFetching,
}: {
  positions: StakingPosition[];
  vault?: string;
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  refetch: () => void;
  isFetching: boolean;
}) {
  const isMobile = useIsMobile(767);

  const totals = useMemo(() => {
    let principal = 0;
    let rewards = 0;
    let total = 0;
    for (const p of positions) {
      principal += num(p.principal);
      rewards += num(p.rewards);
      total += num(p.total);
    }
    return { principal, rewards, total };
  }, [positions]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold">Your staking positions</h2>
          <p className="text-sm text-muted-foreground">
            {positions.length} position{positions.length === 1 ? "" : "s"}
            {vault ? (
              <>
                {" "}
                · vault <span className="font-mono">{vault}</span>
              </>
            ) : null}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={refetch}
          disabled={isFetching}
          className="gap-1.5"
        >
          <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full rounded-xl" />
          ))}
        </div>
      )}

      {!isLoading && isError && isUnavailable(error) && (
        <NotAvailable line="Staking positions aren't available on this backend yet — the custody staking surface isn't deployed or your account isn't custody-gated." />
      )}

      {!isLoading && isError && !isUnavailable(error) && (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-10 text-center">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-sm text-muted-foreground">
              Could not load staking positions.
            </p>
            <Button size="sm" onClick={refetch}>
              Retry
            </Button>
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && positions.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            You have no staking positions yet — stake an asset below to start
            earning yield.
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && positions.length > 0 && (
        <>
          {isMobile ? (
            <div className="space-y-2">
              {positions.map((p) => (
                <Card key={p.position_id}>
                  <CardContent className="space-y-2 p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold">{p.asset}</span>
                        <span className="text-xs text-muted-foreground">
                          {p.provider}
                        </span>
                      </div>
                      <StatusBadge status={p.status} />
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div>
                        <div className="text-muted-foreground">Principal</div>
                        <div className="font-medium tabular-nums">
                          {fmtAmount(p.principal)}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Rewards</div>
                        <div className="font-medium tabular-nums text-emerald-600 dark:text-emerald-400">
                          {fmtAmount(p.rewards)}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Total</div>
                        <div className="font-semibold tabular-nums">
                          {fmtAmount(p.total)}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="overflow-x-auto p-0">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs uppercase text-muted-foreground">
                      <th className="px-4 py-2 font-medium">Provider</th>
                      <th className="px-4 py-2 font-medium">Asset</th>
                      <th className="px-4 py-2 font-medium">Chain</th>
                      <th className="px-4 py-2 text-right font-medium">
                        Principal
                      </th>
                      <th className="px-4 py-2 text-right font-medium">
                        Rewards
                      </th>
                      <th className="px-4 py-2 text-right font-medium">Total</th>
                      <th className="px-4 py-2 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {positions.map((p) => (
                      <tr
                        key={p.position_id}
                        className="border-b last:border-0"
                      >
                        <td className="px-4 py-2 font-medium">{p.provider}</td>
                        <td className="px-4 py-2">{p.asset}</td>
                        <td className="px-4 py-2 text-muted-foreground">
                          {p.chain}
                        </td>
                        <td className="px-4 py-2 text-right tabular-nums">
                          {fmtAmount(p.principal)}
                        </td>
                        <td className="px-4 py-2 text-right tabular-nums text-emerald-600 dark:text-emerald-400">
                          {fmtAmount(p.rewards)}
                        </td>
                        <td className="px-4 py-2 text-right font-semibold tabular-nums">
                          {fmtAmount(p.total)}
                        </td>
                        <td className="px-4 py-2">
                          <StatusBadge status={p.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot>
                    <tr className="border-t bg-muted/30 text-xs">
                      <td className="px-4 py-2 font-medium" colSpan={3}>
                        Totals
                      </td>
                      <td className="px-4 py-2 text-right font-medium tabular-nums">
                        {fmtAmount(totals.principal)}
                      </td>
                      <td className="px-4 py-2 text-right font-medium tabular-nums text-emerald-600 dark:text-emerald-400">
                        {fmtAmount(totals.rewards)}
                      </td>
                      <td className="px-4 py-2 text-right font-semibold tabular-nums">
                        {fmtAmount(totals.total)}
                      </td>
                      <td className="px-4 py-2" />
                    </tr>
                  </tfoot>
                </table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

// ─── Providers + stake form ─────────────────────────────────────

function StakeSection({
  providers,
  isLoading,
  isError,
  error,
  refetchPositions,
}: {
  providers: StakingProvider[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  refetchPositions: () => void;
}) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string>("");
  const [amount, setAmount] = useState("");

  useEffect(() => {
    if (!selected && providers.length > 0) setSelected(providers[0]!.id);
  }, [providers, selected]);

  const chosen = providers.find((p) => p.id === selected);
  const amt = num(amount);
  const amountError =
    amount.trim() === "" ? "" : amt <= 0 ? "Amount must be greater than 0." : "";
  const canSubmit = Boolean(chosen) && amt > 0;

  const mutation = useMutation({
    mutationFn: () => stake({ provider: chosen!.id, amount: String(amount).trim() }),
    onSuccess: (res) => {
      const ok =
        !res.status ||
        res.status === "ok" ||
        res.status === "staked" ||
        res.status === "ack" ||
        res.status === "active";
      if (ok) {
        toast.success("Stake submitted");
        setAmount("");
        qc.invalidateQueries({ queryKey: ["custody", "staking", "positions"] });
        refetchPositions();
      } else {
        toast.error(res.detail || res.error || res.reason || "Stake rejected");
      }
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Stake failed"),
  });

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      {/* Providers list */}
      <Card className="lg:col-span-3">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Coins className="h-5 w-5 text-primary" /> Available providers
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading && (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full rounded-lg" />
              ))}
            </div>
          )}

          {!isLoading && isError && isUnavailable(error) && (
            <div className="flex items-start gap-2 rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
              <Info className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                Staking providers aren't available on this backend yet.
              </span>
            </div>
          )}

          {!isLoading && isError && !isUnavailable(error) && (
            <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Could not load providers.</span>
            </div>
          )}

          {!isLoading && !isError && providers.length === 0 && (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No staking providers are offered right now.
            </p>
          )}

          {!isLoading && !isError && providers.length > 0 && (
            <div className="space-y-2">
              {providers.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setSelected(p.id)}
                  className={cn(
                    "flex w-full items-center justify-between rounded-lg border p-3 text-left transition",
                    selected === p.id
                      ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                      : "hover:bg-muted/40",
                  )}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{p.id}</span>
                      <Badge variant="outline" className="text-[10px] capitalize">
                        {p.kind}
                      </Badge>
                    </div>
                    <p className="truncate font-mono text-[11px] text-muted-foreground">
                      {p.contract}
                    </p>
                  </div>
                  <div className="ml-2 shrink-0 text-right text-xs">
                    <div className="font-semibold">{p.asset}</div>
                    <div className="text-muted-foreground">chain {p.chain}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Stake form */}
      <Card className="lg:col-span-2">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Sprout className="h-5 w-5 text-primary" /> Stake
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Provider</Label>
            <Select value={selected} onValueChange={setSelected}>
              <SelectTrigger>
                <SelectValue placeholder="Choose a provider" />
              </SelectTrigger>
              <SelectContent>
                {providers.length === 0 && (
                  <SelectItem value="__none" disabled>
                    No providers available
                  </SelectItem>
                )}
                {providers.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.id} — {p.asset} ({p.kind})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label>Amount{chosen ? ` (${chosen.asset})` : ""}</Label>
            <Input
              inputMode="decimal"
              placeholder="0.00"
              value={amount}
              onChange={(e) =>
                setAmount(e.target.value.replace(/[^0-9.]/g, ""))
              }
            />
            {amountError && (
              <p className="text-xs text-destructive">{amountError}</p>
            )}
          </div>

          {chosen && (
            <div className="rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
              <div className="flex justify-between">
                <span>Asset</span>
                <span className="font-medium text-foreground">
                  {chosen.asset}
                </span>
              </div>
              <div className="mt-1 flex justify-between">
                <span>Chain</span>
                <span className="font-medium text-foreground">
                  {chosen.chain}
                </span>
              </div>
              <Separator className="my-2" />
              <div className="flex justify-between">
                <span>Contract</span>
                <span className="break-all font-mono text-foreground/80">
                  {chosen.contract}
                </span>
              </div>
            </div>
          )}

          <Button
            className="w-full gap-1.5"
            disabled={!canSubmit || mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Sprout className="h-4 w-4" />
            )}
            Stake
          </Button>

          {mutation.isSuccess && (
            <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/5 p-2 text-xs text-emerald-700 dark:text-emerald-300">
              <CircleCheck className="h-4 w-4" /> Stake submitted — see your
              positions above.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Dashboard ──────────────────────────────────────────────────

export default function StakingDashboard() {
  const positionsQ = useQuery({
    queryKey: ["custody", "staking", "positions"],
    queryFn: getStakingPositions,
    retry: false,
    staleTime: 15_000,
  });

  const providersQ = useQuery({
    queryKey: ["custody", "staking", "providers"],
    queryFn: getStakingProviders,
    retry: false,
    staleTime: 60_000,
  });

  const positions = positionsQ.data?.positions ?? [];
  const providers = providersQ.data?.providers ?? [];

  // If BOTH reads are unavailable (404/403), the whole surface isn't deployed.
  const bothUnavailable =
    positionsQ.isError &&
    providersQ.isError &&
    isUnavailable(positionsQ.error) &&
    isUnavailable(providersQ.error);

  if (bothUnavailable) {
    return (
      <NotAvailable line="Custody staking isn't available on this backend yet — the /me/staking surface isn't deployed or your account isn't custody-gated." />
    );
  }

  return (
    <div className="space-y-6">
      <PositionsSection
        positions={positions}
        vault={positionsQ.data?.vault}
        isLoading={positionsQ.isLoading}
        isError={positionsQ.isError}
        error={positionsQ.error}
        refetch={() => positionsQ.refetch()}
        isFetching={positionsQ.isFetching}
      />
      <StakeSection
        providers={providers}
        isLoading={providersQ.isLoading}
        isError={providersQ.isError}
        error={providersQ.error}
        refetchPositions={() => positionsQ.refetch()}
      />
    </div>
  );
}
