import { useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, BellRing, Boxes, FlaskConical, Pencil, Rocket, Lock } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAuthStore } from "@/stores/authStore";
import { useSymbols } from "@/hooks/useMarketData";
import {
  useStrategy,
  useStrategyNav,
  useStrategyHoldings,
  useStrategyPosition,
  useStrategyFees,
  useInvestStrategy,
  useRedeemStrategy,
  usePublishStrategy,
} from "@/hooks/useStrategies";
import type { Strategy, StrategyStatus } from "@/api/endpoints/strategies";
import {
  formatBps,
  formatCents,
  canInvest,
  capacityFilledFraction,
  unitsForInvestment,
  proceedsForUnits,
  type InvestBlockReason,
} from "@/lib/strategies";
import { PendingBackend, PooledNavNote } from "./PendingBackend";

const STATUS_VARIANT: Record<StrategyStatus, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  paper: "secondary",
  published: "default",
  closed: "destructive",
};

function shortSub(sub: string | undefined): string {
  if (!sub) return "—";
  return sub.length > 12 ? `${sub.slice(0, 6)}…${sub.slice(-4)}` : sub;
}

const BLOCK_COPY: Record<InvestBlockReason, string> = {
  amount_non_positive: "Enter an amount to invest.",
  below_min: "Amount is below the fund's minimum investment.",
  over_capacity: "Amount exceeds the fund's remaining capacity.",
};

export default function StrategyDetailPage() {
  const { id } = useParams<{ id: string }>();
  const userId = useAuthStore((s) => s.userId);

  const strategyQ = useStrategy(id);
  const navQ = useStrategyNav(id);
  const holdingsQ = useStrategyHoldings(id);
  const positionQ = useStrategyPosition(id);
  const feesQ = useStrategyFees(id);
  const symbolsQ = useSymbols();

  const invest = useInvestStrategy(id);
  const redeem = useRedeemStrategy(id);
  const publish = usePublishStrategy(id);

  const strategy: Strategy | undefined = strategyQ.data;
  const isCreator = !!strategy && !!userId && strategy.creator_sub === userId;
  const isDraft = strategy?.status === "draft";
  const isPublished = strategy?.status === "published";

  const symName = (sid: number) =>
    symbolsQ.data?.symbols.find((s) => s.symbol_id === sid)?.symbol ?? `#${sid}`;

  const [tab, setTab] = useState("overview");
  const [investAmt, setInvestAmt] = useState("");
  const [investConfirm, setInvestConfirm] = useState(false);
  const [redeemUnits, setRedeemUnits] = useState("");
  const [redeemConfirm, setRedeemConfirm] = useState(false);
  const [publishConfirm, setPublishConfirm] = useState(false);

  // -- NAV / capacity --------------------------------------------------
  const navCents = navQ.data?.nav_per_unit ?? strategy?.nav_per_unit ?? 0;
  const aumCents = navQ.data?.aum_cents ?? strategy?.aum_cents ?? 0;
  const capCents = strategy?.max_aum_cents ?? 0;
  const capFilled = capacityFilledFraction(aumCents, capCents);

  // -- Invest math + validation ---------------------------------------
  const investCents = useMemo(() => {
    const n = Number(investAmt);
    return Number.isFinite(n) && n > 0 ? Math.round(n * 100) : 0;
  }, [investAmt]);
  const investCheck = useMemo(
    () => canInvest(investCents, strategy?.min_investment_cents ?? 0, aumCents, capCents),
    [investCents, strategy?.min_investment_cents, aumCents, capCents],
  );
  const estUnits = useMemo(() => unitsForInvestment(investCents, navCents), [investCents, navCents]);

  // -- Redeem math -----------------------------------------------------
  const position = positionQ.data;
  const redeemUnitsN = Number(redeemUnits);
  const redeemProceeds = useMemo(
    () => proceedsForUnits(redeemUnitsN > 0 ? redeemUnitsN : 0, position?.nav_per_unit ?? navCents),
    [redeemUnitsN, position?.nav_per_unit, navCents],
  );
  const redeemTooMany = position != null && redeemUnitsN > position.units;

  const doInvest = async () => {
    try {
      const res = await invest.mutateAsync({ amount_cents: investCents });
      setInvestConfirm(false);
      setInvestAmt("");
      toast.success(`Invested — received ${res.units.toLocaleString(undefined, { maximumFractionDigits: 4 })} units at ${formatCents(res.nav_per_unit)}.`);
    } catch {
      /* hook toasts */
    }
  };

  const doRedeem = async () => {
    try {
      const res = await redeem.mutateAsync({ units: redeemUnitsN });
      setRedeemConfirm(false);
      setRedeemUnits("");
      toast.success(`Redemption submitted — proceeds ${formatCents(res.proceeds_cents)}.`);
    } catch {
      /* hook toasts */
    }
  };

  const doPublish = async () => {
    try {
      await publish.mutateAsync();
      setPublishConfirm(false);
      toast.success("Strategy published.");
    } catch {
      /* hook toasts */
    }
  };

  const header = useMemo(() => {
    if (strategyQ.isLoading) return <Skeleton className="h-9 w-64" />;
    if (!strategy) return <h1 className="text-2xl font-bold tracking-tight">Strategy</h1>;
    return (
      <div className="flex flex-wrap items-center gap-2">
        <Boxes className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold tracking-tight">{strategy.name}</h1>
        <Badge variant={STATUS_VARIANT[strategy.status] ?? "outline"}>{strategy.status}</Badge>
        {isCreator && <Badge variant="outline">Creator view</Badge>}
      </div>
    );
  }, [strategyQ.isLoading, strategy, isCreator]);

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="icon">
            <Link to="/strategies" aria-label="Back to strategies">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          {header}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to={`/markets/price-alerts?kind=strategy&id=${encodeURIComponent(id ?? "")}`}>
              <BellRing className="mr-1 h-4 w-4" /> Set NAV alert
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to={`/strategies/${encodeURIComponent(id ?? "")}/backtest`}>
              <FlaskConical className="mr-1 h-4 w-4" /> Paper &amp; backtest
            </Link>
          </Button>
          {isCreator && isDraft && (
            <>
              <Button asChild variant="outline" size="sm">
                <Link to={`/strategies/${encodeURIComponent(id ?? "")}/edit`}>
                  <Pencil className="mr-1 h-4 w-4" /> Edit
                </Link>
              </Button>
              <Button size="sm" onClick={() => setPublishConfirm(true)} data-testid="detail-publish">
                <Rocket className="mr-1 h-4 w-4" /> Publish
              </Button>
            </>
          )}
        </div>
      </div>

      {strategyQ.isError ? (
        <PendingBackend label="This strategy" />
      ) : (
        <>
          <PooledNavNote />

          {strategy && (
            <Card>
              <CardContent className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
                <Stat label="NAV / unit" value={navCents > 0 ? formatCents(navCents) : "—"} />
                <Stat label="AUM" value={aumCents > 0 ? formatCents(aumCents) : "—"} />
                <Stat label="Investors" value={strategy.investor_count != null ? String(strategy.investor_count) : "—"} />
                <Stat
                  label="Since inception"
                  value={
                    strategy.inception_return_bps != null
                      ? `${strategy.inception_return_bps >= 0 ? "+" : ""}${formatBps(strategy.inception_return_bps)}`
                      : "—"
                  }
                />
              </CardContent>
            </Card>
          )}

          {strategy?.description && (
            <p className="text-sm text-muted-foreground">{strategy.description}</p>
          )}

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="invest">Invest</TabsTrigger>
              <TabsTrigger value="position">My position</TabsTrigger>
              {isCreator && <TabsTrigger value="fees">Fee accrual</TabsTrigger>}
            </TabsList>

            {/* Overview: holdings + fee schedule */}
            <TabsContent value="overview" className="space-y-4 pt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Holdings / composition</CardTitle>
                </CardHeader>
                <CardContent>
                  {holdingsQ.isLoading ? (
                    <Skeleton className="h-24 w-full" />
                  ) : holdingsQ.isError ? (
                    strategy && strategy.legs?.length ? (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Symbol</TableHead>
                            <TableHead className="text-right">Target weight</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {strategy.legs.map((l) => (
                            <TableRow key={l.symbol_id}>
                              <TableCell className="font-medium">{symName(l.symbol_id)}</TableCell>
                              <TableCell className="text-right tabular-nums">{formatBps(l.weight_bps)}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : (
                      <PendingBackend label="Live holdings" />
                    )
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Symbol</TableHead>
                          <TableHead className="text-right">Weight</TableHead>
                          <TableHead className="text-right">Value</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(holdingsQ.data?.legs ?? []).map((l) => (
                          <TableRow key={l.symbol_id}>
                            <TableCell className="font-medium">{symName(l.symbol_id)}</TableCell>
                            <TableCell className="text-right tabular-nums">{formatBps(l.weight_bps)}</TableCell>
                            <TableCell className="text-right tabular-nums">{formatCents(l.value_cents)}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Fee schedule &amp; terms</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  {strategy && (
                    <>
                      <Row label="Management fee (annual, on AUM)" value={formatBps(strategy.mgmt_fee_bps)} />
                      <Row
                        label="Performance fee (on profit)"
                        value={`${formatBps(strategy.perf_fee_bps)}${strategy.high_water_mark ? " · high-water mark" : ""}`}
                      />
                      <Row label="Minimum investment" value={formatCents(strategy.min_investment_cents)} />
                      <Row
                        label="Maximum AUM (capacity)"
                        value={strategy.max_aum_cents > 0 ? formatCents(strategy.max_aum_cents) : "Uncapped"}
                      />
                      <Row
                        label="Redemptions"
                        value={
                          strategy.redemption?.type === "notice"
                            ? `${strategy.redemption.notice_days ?? 0}-day notice`
                            : "Instant (at NAV)"
                        }
                      />
                      {(strategy.redemption?.lockup_days ?? 0) > 0 && (
                        <Row label="Initial lock-up" value={`${strategy.redemption.lockup_days} days`} />
                      )}
                      <Row label="Rebalance" value={strategy.rebalance} />
                      <Row label="Creator" value={shortSub(strategy.creator_sub)} />
                    </>
                  )}
                  {capCents > 0 && (
                    <div className="pt-2">
                      <div className="mb-1 flex justify-between text-xs text-muted-foreground">
                        <span>Capacity used</span>
                        <span className="tabular-nums">{Math.round(capFilled * 100)}%</span>
                      </div>
                      <Progress value={capFilled * 100} />
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Invest */}
            <TabsContent value="invest" className="pt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Invest at NAV</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {!isPublished && (
                    <p className="flex items-center gap-2 rounded-md border border-amber-300/50 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-300">
                      <Lock className="h-3.5 w-3.5" /> This fund is not open for investment yet (status: {strategy?.status}).
                    </p>
                  )}
                  <div className="space-y-1.5">
                    <Label htmlFor="invest-amt">Amount to invest ($)</Label>
                    <Input
                      id="invest-amt"
                      type="number"
                      min={0}
                      step={10}
                      value={investAmt}
                      onChange={(e) => setInvestAmt(e.target.value)}
                      placeholder={strategy ? String((strategy.min_investment_cents ?? 0) / 100) : "0"}
                      disabled={!isPublished}
                      data-testid="invest-amount"
                    />
                    <div className="flex flex-wrap justify-between gap-2 text-xs text-muted-foreground">
                      <span>Minimum {formatCents(strategy?.min_investment_cents ?? 0)}</span>
                      <span>
                        Capacity left{" "}
                        {Number.isFinite(investCheck.capacityRemainingCents)
                          ? formatCents(investCheck.capacityRemainingCents)
                          : "uncapped"}
                      </span>
                    </div>
                  </div>

                  {investCents > 0 && (
                    <div className="rounded-lg border bg-muted/30 p-3 text-sm">
                      <Row label="NAV / unit" value={navCents > 0 ? formatCents(navCents) : "—"} />
                      <Row
                        label="Estimated units"
                        value={navCents > 0 ? estUnits.toLocaleString(undefined, { maximumFractionDigits: 4 }) : "—"}
                      />
                    </div>
                  )}

                  {investCents > 0 && !investCheck.ok && investCheck.reason && (
                    <p className="text-xs text-rose-600 dark:text-rose-400">{BLOCK_COPY[investCheck.reason]}</p>
                  )}

                  <Button
                    className="w-full"
                    disabled={!isPublished || !investCheck.ok || invest.isPending}
                    onClick={() => setInvestConfirm(true)}
                    data-testid="invest-review"
                  >
                    Review &amp; invest
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            {/* My position + redeem */}
            <TabsContent value="position" className="pt-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">My position</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {positionQ.isLoading ? (
                    <Skeleton className="h-24 w-full" />
                  ) : positionQ.isError ? (
                    <PendingBackend label="Your position" />
                  ) : !position || position.units <= 0 ? (
                    <p className="text-sm text-muted-foreground">You have no position in this fund yet.</p>
                  ) : (
                    <>
                      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                        <Stat label="Units" value={position.units.toLocaleString(undefined, { maximumFractionDigits: 4 })} />
                        <Stat label="NAV / unit" value={formatCents(position.nav_per_unit)} />
                        <Stat label="Invested" value={formatCents(position.invested_cents)} />
                        <Stat label="Current value" value={formatCents(position.current_value_cents)} />
                        <Stat
                          label="Unrealized P&L"
                          value={`${position.unrealized_pnl_cents >= 0 ? "+" : ""}${formatCents(position.unrealized_pnl_cents)}`}
                          tone={position.unrealized_pnl_cents >= 0 ? "pos" : "neg"}
                        />
                        <Stat label="Fees paid" value={formatCents(position.fees_paid_cents)} />
                      </div>

                      <Separator />

                      <div className="space-y-1.5">
                        <Label htmlFor="redeem-units">Redeem units</Label>
                        <Input
                          id="redeem-units"
                          type="number"
                          min={0}
                          step={1}
                          value={redeemUnits}
                          onChange={(e) => setRedeemUnits(e.target.value)}
                          placeholder={String(position.units)}
                          data-testid="redeem-units"
                        />
                        <div className="flex justify-between text-xs text-muted-foreground">
                          <span>
                            {strategy?.redemption?.type === "notice"
                              ? `Redemptions require ${strategy.redemption.notice_days ?? 0} days' notice.`
                              : "Instant redemption at NAV."}
                          </span>
                          <span className="tabular-nums">Est. {formatCents(redeemProceeds)}</span>
                        </div>
                        {redeemTooMany && (
                          <p className="text-xs text-rose-600 dark:text-rose-400">
                            You only hold {position.units.toLocaleString(undefined, { maximumFractionDigits: 4 })} units.
                          </p>
                        )}
                      </div>
                      <Button
                        variant="outline"
                        disabled={!(redeemUnitsN > 0) || redeemTooMany || redeem.isPending}
                        onClick={() => setRedeemConfirm(true)}
                        data-testid="redeem-review"
                      >
                        Review redemption
                      </Button>
                    </>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Creator fee accrual */}
            {isCreator && (
              <TabsContent value="fees" className="pt-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Fee accrual (creator)</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {feesQ.isLoading ? (
                      <Skeleton className="h-20 w-full" />
                    ) : feesQ.isError ? (
                      <PendingBackend label="Fee accrual" />
                    ) : feesQ.data ? (
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                        <Stat label="Management accrued" value={formatCents(feesQ.data.mgmt_accrued_cents)} />
                        <Stat label="Performance accrued" value={formatCents(feesQ.data.perf_accrued_cents)} />
                        <Stat label="High-water mark" value={formatCents(feesQ.data.high_water_mark)} />
                      </div>
                    ) : (
                      <PendingBackend label="Fee accrual" />
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            )}
          </Tabs>
        </>
      )}

      {/* Invest money-safety confirm */}
      <Dialog open={investConfirm} onOpenChange={setInvestConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm investment</DialogTitle>
            <DialogDescription>
              You are subscribing real capital to a pooled NAV fund. Units are issued at the current NAV.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <Row label="Amount" value={formatCents(investCents)} />
            <Row label="NAV / unit" value={navCents > 0 ? formatCents(navCents) : "—"} />
            <Row label="Estimated units" value={estUnits.toLocaleString(undefined, { maximumFractionDigits: 4 })} />
            <Separator />
            <Row label="Management fee" value={`${formatBps(strategy?.mgmt_fee_bps ?? 0)} / yr`} />
            <Row label="Performance fee" value={formatBps(strategy?.perf_fee_bps ?? 0)} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setInvestConfirm(false)} disabled={invest.isPending}>
              Cancel
            </Button>
            <Button onClick={doInvest} disabled={invest.isPending} data-testid="invest-confirm">
              {invest.isPending ? "Investing…" : `Invest ${formatCents(investCents)}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Redeem confirm */}
      <Dialog open={redeemConfirm} onOpenChange={setRedeemConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm redemption</DialogTitle>
            <DialogDescription>
              {strategy?.redemption?.type === "notice"
                ? `This fund settles redemptions after a ${strategy.redemption.notice_days ?? 0}-day notice period.`
                : "Units are redeemed at the current NAV."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <Row label="Units" value={redeemUnitsN.toLocaleString(undefined, { maximumFractionDigits: 4 })} />
            <Row label="NAV / unit" value={formatCents(position?.nav_per_unit ?? navCents)} />
            <Separator />
            <Row label="Estimated proceeds" value={formatCents(redeemProceeds)} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRedeemConfirm(false)} disabled={redeem.isPending}>
              Cancel
            </Button>
            <Button onClick={doRedeem} disabled={redeem.isPending} data-testid="redeem-confirm">
              {redeem.isPending ? "Redeeming…" : "Redeem"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Publish confirm (creator) */}
      <Dialog open={publishConfirm} onOpenChange={setPublishConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Publish this strategy?</DialogTitle>
            <DialogDescription>
              Publishing opens the fund for real investment at NAV under its current terms.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPublishConfirm(false)} disabled={publish.isPending}>
              Cancel
            </Button>
            <Button onClick={doPublish} disabled={publish.isPending} data-testid="publish-confirm-detail">
              {publish.isPending ? "Publishing…" : "Publish"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "pos" | "neg" }) {
  const cls =
    tone === "pos"
      ? "text-emerald-600 dark:text-emerald-400"
      : tone === "neg"
        ? "text-rose-600 dark:text-rose-400"
        : "";
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-0.5 font-semibold tabular-nums ${cls}`}>{value}</p>
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
