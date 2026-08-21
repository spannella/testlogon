import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { ArrowLeft, Boxes, Plus, Trash2, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
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
import { useSymbols } from "@/hooks/useMarketData";
import {
  useCreateStrategy,
  useUpdateStrategy,
  usePublishStrategy,
  useStrategy,
} from "@/hooks/useStrategies";
import type {
  RebalanceCadence,
  RedemptionType,
  StrategyKind,
  CreateStrategyRequest,
} from "@/api/endpoints/strategies";
import { strategyAckMessage } from "@/api/endpoints/strategies";
import {
  validateWeights,
  formatBps,
  pctToBps,
  bpsToPct,
  type StrategyLeg,
} from "@/lib/strategies";
import { PooledNavNote } from "./PendingBackend";

/** A leg row in the editor: symbol + weight-percent string (bps derived). */
interface LegRow {
  symbol_id: number | null;
  weightPct: string;
}

const REBALANCE_OPTIONS: { value: RebalanceCadence; label: string }[] = [
  { value: "none", label: "No rebalance (buy & hold)" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
  { value: "threshold", label: "On drift threshold" },
];

function dollarsToCents(s: string): number {
  const n = Number(s);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 100) : 0;
}
function centsToDollars(cents: number | undefined): string {
  return cents && cents > 0 ? String(cents / 100) : "";
}

export default function StrategyBuilderPage() {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isEdit = !!id;

  const symbolsQ = useSymbols();
  const symbols = symbolsQ.data?.symbols ?? [];
  const symbolName = (sid: number | null) =>
    sid == null ? "Select symbol" : symbols.find((s) => s.symbol_id === sid)?.symbol ?? `#${sid}`;

  const existing = useStrategy(id);
  const create = useCreateStrategy();
  const update = useUpdateStrategy(id);
  const publish = usePublishStrategy(id);

  // -- Form state ------------------------------------------------------
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState<StrategyKind>("basket");
  const [legs, setLegs] = useState<LegRow[]>([{ symbol_id: null, weightPct: "" }]);
  const [rebalance, setRebalance] = useState<RebalanceCadence>("none");
  const [thresholdPct, setThresholdPct] = useState("5");
  const [minInvest, setMinInvest] = useState("100");
  const [maxAum, setMaxAum] = useState("");
  const [mgmtFeePct, setMgmtFeePct] = useState("2");
  const [perfFeePct, setPerfFeePct] = useState("20");
  const [highWaterMark, setHighWaterMark] = useState(true);
  const [redemptionType, setRedemptionType] = useState<RedemptionType>("instant");
  const [noticeDays, setNoticeDays] = useState("7");
  const [lockupDays, setLockupDays] = useState("0");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);

  // Hydrate the form once when editing an existing draft.
  useEffect(() => {
    if (!isEdit || hydrated || !existing.data) return;
    const s = existing.data;
    setName(s.name);
    setDescription(s.description ?? "");
    setKind(s.kind);
    setLegs(
      s.legs?.length
        ? s.legs.map((l) => ({ symbol_id: l.symbol_id, weightPct: String(bpsToPct(l.weight_bps)) }))
        : [{ symbol_id: null, weightPct: "" }],
    );
    setRebalance(s.rebalance);
    setThresholdPct(s.threshold_bps != null ? String(bpsToPct(s.threshold_bps)) : "5");
    setMinInvest(centsToDollars(s.min_investment_cents));
    setMaxAum(centsToDollars(s.max_aum_cents));
    setMgmtFeePct(String(bpsToPct(s.mgmt_fee_bps)));
    setPerfFeePct(String(bpsToPct(s.perf_fee_bps)));
    setHighWaterMark(s.high_water_mark);
    setRedemptionType(s.redemption?.type ?? "instant");
    setNoticeDays(String(s.redemption?.notice_days ?? 7));
    setLockupDays(String(s.redemption?.lockup_days ?? 0));
    setHydrated(true);
  }, [isEdit, hydrated, existing.data]);

  // -- Derived ---------------------------------------------------------
  const modelLegs: StrategyLeg[] = useMemo(
    () =>
      legs
        .filter((l) => l.symbol_id != null && Number(l.weightPct) > 0)
        .map((l) => ({ symbol_id: l.symbol_id as number, weight_bps: pctToBps(Number(l.weightPct)) })),
    [legs],
  );
  const weightCheck = useMemo(() => validateWeights(modelLegs, 1), [modelLegs]);

  const mgmtFeeBps = pctToBps(Number(mgmtFeePct), 100);
  const perfFeeBps = pctToBps(Number(perfFeePct), 100);
  const minInvestCents = dollarsToCents(minInvest);
  const maxAumCents = dollarsToCents(maxAum);

  const errors = useMemo(() => {
    const e: string[] = [];
    if (!name.trim()) e.push("Name is required.");
    if (!weightCheck.hasLegs) e.push("Add at least one basket leg.");
    if (weightCheck.hasDuplicateSymbol) e.push("Each symbol can appear only once.");
    if (weightCheck.hasLegs && !weightCheck.valid && !weightCheck.hasDuplicateSymbol) {
      e.push("Leg weights must total exactly 100%.");
    }
    if (!(minInvestCents > 0)) e.push("Minimum investment must be greater than $0.");
    if (Number(mgmtFeePct) < 0 || Number(mgmtFeePct) > 100) e.push("Management fee must be 0–100%.");
    if (Number(perfFeePct) < 0 || Number(perfFeePct) > 100) e.push("Performance fee must be 0–100%.");
    if (redemptionType === "notice" && !(Number(noticeDays) > 0)) {
      e.push("Notice period must be at least 1 day.");
    }
    return e;
  }, [name, weightCheck, minInvestCents, mgmtFeePct, perfFeePct, redemptionType, noticeDays]);

  const busy = create.isPending || update.isPending || publish.isPending;
  const canSubmit = errors.length === 0 && !busy;

  // -- Leg editor helpers ---------------------------------------------
  const setLeg = (i: number, patch: Partial<LegRow>) =>
    setLegs((prev) => prev.map((l, idx) => (idx === i ? { ...l, ...patch } : l)));
  const addLeg = () => setLegs((prev) => [...prev, { symbol_id: null, weightPct: "" }]);
  const removeLeg = (i: number) =>
    setLegs((prev) => (prev.length > 1 ? prev.filter((_, idx) => idx !== i) : prev));
  const equalWeight = () => {
    const active = legs.filter((l) => l.symbol_id != null);
    if (active.length === 0) return;
    const per = Math.floor(10000 / active.length) / 100; // percent, 2dp
    let assigned = 0;
    setLegs((prev) =>
      prev.map((l) => {
        if (l.symbol_id == null) return l;
        assigned += 1;
        // Give the last active leg the remainder so it totals ~100.
        const isLast = assigned === active.length;
        const pct = isLast ? Math.round((100 - per * (active.length - 1)) * 100) / 100 : per;
        return { ...l, weightPct: String(pct) };
      }),
    );
  };

  // -- Build the request body -----------------------------------------
  const buildBody = (): CreateStrategyRequest => ({
    name: name.trim(),
    description: description.trim(),
    kind,
    legs: modelLegs,
    rebalance,
    threshold_bps: rebalance === "threshold" ? pctToBps(Number(thresholdPct), 100) : undefined,
    min_investment_cents: minInvestCents,
    max_aum_cents: maxAumCents,
    mgmt_fee_bps: mgmtFeeBps,
    perf_fee_bps: perfFeeBps,
    high_water_mark: highWaterMark,
    redemption: {
      type: redemptionType,
      notice_days: redemptionType === "notice" ? Number(noticeDays) : undefined,
      lockup_days: Number(lockupDays) > 0 ? Number(lockupDays) : undefined,
    },
  });

  const saveDraft = async () => {
    try {
      const body = buildBody();
      const saved = isEdit ? await update.mutateAsync(body) : await create.mutateAsync(body);
      toast.success(isEdit ? "Draft saved." : "Draft created.");
      navigate(`/strategies/${encodeURIComponent(saved.strategy_id)}`);
    } catch (err) {
      const msg = strategyAckMessage((err as { body?: never })?.body as never);
      if (msg) toast.error(msg);
    }
  };

  const doPublish = async () => {
    try {
      // Persist any edits first, then publish. On create-then-publish, use the
      // returned id for the publish call by routing through the saved strategy.
      const body = buildBody();
      const saved = isEdit ? await update.mutateAsync(body) : await create.mutateAsync(body);
      if (isEdit) {
        await publish.mutateAsync();
      }
      setConfirmOpen(false);
      toast.success(isEdit ? "Strategy published." : "Draft created — open it to publish.");
      navigate(`/strategies/${encodeURIComponent(saved.strategy_id)}`);
    } catch (err) {
      const msg = strategyAckMessage((err as { body?: never })?.body as never);
      if (msg) toast.error(msg);
    }
  };

  const totalPct = bpsToPct(weightCheck.totalBps);

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="icon">
          <Link to="/strategies" aria-label="Back to strategies">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div className="flex items-center gap-2">
          <Boxes className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">
            {isEdit ? "Edit strategy" : "Create a strategy"}
          </h1>
        </div>
      </div>

      <PooledNavNote />

      {/* Identity */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Basics</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="s-name">Name</Label>
            <Input
              id="s-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Blue-chip crypto basket"
              maxLength={80}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="s-desc">Description</Label>
            <Textarea
              id="s-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="A market-cap-weighted basket of the top three majors, rebalanced monthly."
              maxLength={500}
              rows={3}
            />
          </div>
          <div className="space-y-1.5">
            <Label>Kind</Label>
            <Select value={kind} onValueChange={(v) => setKind(v as StrategyKind)}>
              <SelectTrigger data-testid="kind-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="basket">Static basket (fixed target weights)</SelectItem>
                <SelectItem value="rule">Rule-based (weights + a simple rule set)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Basket legs */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Basket legs</CardTitle>
          <div className="flex items-center gap-2">
            <Button type="button" variant="outline" size="sm" onClick={equalWeight}>
              Equal-weight
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={addLeg} data-testid="add-leg">
              <Plus className="mr-1 h-4 w-4" /> Add leg
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {legs.map((leg, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className="flex-1">
                <Select
                  value={leg.symbol_id != null ? String(leg.symbol_id) : undefined}
                  onValueChange={(v) => setLeg(i, { symbol_id: Number(v) })}
                >
                  <SelectTrigger data-testid="leg-symbol">
                    <SelectValue placeholder="Select symbol">{symbolName(leg.symbol_id)}</SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {symbols.map((s) => (
                      <SelectItem key={s.symbol_id} value={String(s.symbol_id)}>
                        {s.symbol}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="relative w-28">
                <Input
                  type="number"
                  min={0}
                  max={100}
                  step={0.5}
                  value={leg.weightPct}
                  onChange={(e) => setLeg(i, { weightPct: e.target.value })}
                  placeholder="Weight"
                  className="pr-6 text-right"
                  data-testid="leg-weight"
                />
                <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-xs text-muted-foreground">
                  %
                </span>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={() => removeLeg(i)}
                disabled={legs.length <= 1}
                aria-label="Remove leg"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          ))}

          <Separator />

          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Total weight</span>
              <span
                className={
                  weightCheck.valid
                    ? "font-semibold tabular-nums text-emerald-600 dark:text-emerald-400"
                    : "font-semibold tabular-nums text-amber-600 dark:text-amber-400"
                }
                data-testid="weight-total"
              >
                {totalPct.toLocaleString(undefined, { maximumFractionDigits: 2 })}% / 100%
              </span>
            </div>
            <Progress value={Math.min(100, totalPct)} />
            {weightCheck.hasDuplicateSymbol && (
              <p className="flex items-center gap-1 text-xs text-rose-600 dark:text-rose-400">
                <AlertTriangle className="h-3 w-3" /> A symbol is used more than once.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Rebalance */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Rebalance</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Cadence</Label>
              <Select value={rebalance} onValueChange={(v) => setRebalance(v as RebalanceCadence)}>
                <SelectTrigger data-testid="rebalance-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {REBALANCE_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {rebalance === "threshold" && (
              <div className="space-y-1.5">
                <Label htmlFor="s-threshold">Drift threshold %</Label>
                <Input
                  id="s-threshold"
                  type="number"
                  min={0.5}
                  max={100}
                  step={0.5}
                  value={thresholdPct}
                  onChange={(e) => setThresholdPct(e.target.value)}
                />
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Terms + fees */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Terms &amp; fees</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="s-min">Minimum investment ($)</Label>
              <Input
                id="s-min"
                type="number"
                min={1}
                step={1}
                value={minInvest}
                onChange={(e) => setMinInvest(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="s-cap">Max total AUM ($, blank = uncapped)</Label>
              <Input
                id="s-cap"
                type="number"
                min={0}
                step={1000}
                value={maxAum}
                onChange={(e) => setMaxAum(e.target.value)}
                placeholder="Uncapped"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="s-mgmt">Management fee (% of AUM / yr)</Label>
              <Input
                id="s-mgmt"
                type="number"
                min={0}
                max={100}
                step={0.25}
                value={mgmtFeePct}
                onChange={(e) => setMgmtFeePct(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">{formatBps(mgmtFeeBps)} annual on AUM.</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="s-perf">Performance fee (% of profit)</Label>
              <Input
                id="s-perf"
                type="number"
                min={0}
                max={100}
                step={1}
                value={perfFeePct}
                onChange={(e) => setPerfFeePct(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">{formatBps(perfFeeBps)} of gains.</p>
            </div>
          </div>

          <div className="flex items-center justify-between rounded-lg border bg-muted/30 p-3">
            <div>
              <p className="text-sm font-medium">High-water mark</p>
              <p className="text-xs text-muted-foreground">
                Performance fee only on new profit above the prior peak.
              </p>
            </div>
            <Switch checked={highWaterMark} onCheckedChange={setHighWaterMark} aria-label="High-water mark" />
          </div>
        </CardContent>
      </Card>

      {/* Redemption */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Redemption policy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Redemptions</Label>
            <Select value={redemptionType} onValueChange={(v) => setRedemptionType(v as RedemptionType)}>
              <SelectTrigger data-testid="redemption-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="instant">Instant (redeem at NAV any time)</SelectItem>
                <SelectItem value="notice">Notice period required</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {redemptionType === "notice" && (
              <div className="space-y-1.5">
                <Label htmlFor="s-notice">Notice period (days)</Label>
                <Input
                  id="s-notice"
                  type="number"
                  min={1}
                  step={1}
                  value={noticeDays}
                  onChange={(e) => setNoticeDays(e.target.value)}
                />
              </div>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="s-lockup">Initial lock-up (days, 0 = none)</Label>
              <Input
                id="s-lockup"
                type="number"
                min={0}
                step={1}
                value={lockupDays}
                onChange={(e) => setLockupDays(e.target.value)}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {errors.length > 0 && (
        <ul className="list-inside list-disc space-y-0.5 rounded-lg border border-rose-300/50 bg-rose-50 p-3 text-xs text-rose-700 dark:border-rose-500/30 dark:bg-rose-950/40 dark:text-rose-300">
          {errors.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}

      <div className="flex flex-wrap gap-3">
        <Button variant="outline" onClick={saveDraft} disabled={busy} data-testid="save-draft">
          {busy ? "Saving…" : isEdit ? "Save draft" : "Create draft"}
        </Button>
        <Button onClick={() => setConfirmOpen(true)} disabled={!canSubmit} data-testid="publish-open">
          Publish…
        </Button>
      </div>

      {/* Money-safety publish confirm. */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Publish this strategy?</DialogTitle>
            <DialogDescription>
              Publishing opens the fund for real investment at NAV. Investors will subscribe under
              these terms — review them carefully.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <Row label="Name" value={name || "—"} />
            <Row label="Legs" value={`${modelLegs.length} (weights ${totalPct.toFixed(0)}%)`} />
            <Row label="Minimum investment" value={`$${(minInvestCents / 100).toLocaleString()}`} />
            <Row label="Max AUM" value={maxAumCents > 0 ? `$${(maxAumCents / 100).toLocaleString()}` : "Uncapped"} />
            <Row label="Management fee" value={`${formatBps(mgmtFeeBps)} / yr`} />
            <Row label="Performance fee" value={`${formatBps(perfFeeBps)}${highWaterMark ? " (HWM)" : ""}`} />
            <Row
              label="Redemptions"
              value={redemptionType === "notice" ? `${noticeDays}-day notice` : "Instant"}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={doPublish} disabled={busy} data-testid="publish-confirm">
              {busy ? "Publishing…" : "Publish"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium tabular-nums">{value}</span>
    </div>
  );
}
