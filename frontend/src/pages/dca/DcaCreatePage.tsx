import { useMemo, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { CalendarClock, Wallet, ArrowLeft, CalendarCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { getWallet } from "@/api/endpoints/billing";
import { useCreateDcaPlan } from "@/hooks/useDca";
import type { DcaFrequency, DcaTarget, DcaPlan } from "@/lib/dca";
import {
  MIN_AMOUNT_CENTS,
  DOW_LABELS,
  formatCents,
  validatePlan,
  upcomingRuns,
  frequencyLabel,
  msToSec,
  ordinal,
} from "@/lib/dca";
import { TargetPicker, ServerRunnerNote } from "./DcaShared";

/** Parse a "$" dollar string into integer cents (NaN-safe). */
function dollarsToCents(v: string): number {
  const n = Number.parseFloat(v.replace(/[^0-9.]/g, ""));
  if (!Number.isFinite(n)) return NaN;
  return Math.round(n * 100);
}

/** A datetime-local input value (yyyy-MM-ddThh:mm) -> epoch seconds, or 0. */
function localToSec(v: string): number {
  if (!v) return 0;
  const ms = new Date(v).getTime();
  return Number.isFinite(ms) ? msToSec(ms) : 0;
}

/** Default the start field to "now" in the datetime-local format. */
function nowLocal(): string {
  const d = new Date();
  d.setSeconds(0, 0);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}`;
}

const ERROR_TEXT: Record<string, string> = {
  no_target: "Choose a target to buy.",
  amount_below_min: `Amount must be at least ${formatCents(MIN_AMOUNT_CENTS)}.`,
  invalid_frequency: "Choose a valid frequency.",
  invalid_day_of_week: "Choose a day of the week.",
  invalid_day_of_month: "Choose a day of the month (1–28).",
  end_before_start: "The end must be after the start.",
  budget_below_amount: "The total budget must cover at least one buy.",
};

export default function DcaCreatePage() {
  const navigate = useNavigate();
  const create = useCreateDcaPlan();
  const walletQ = useQuery({ queryKey: ["ui", "billing", "wallet"], queryFn: getWallet, retry: false });

  const [target, setTarget] = useState<DcaTarget | null>(null);
  const [amountStr, setAmountStr] = useState("");
  const [frequency, setFrequency] = useState<DcaFrequency>("weekly");
  const [dayOfWeek, setDayOfWeek] = useState(1); // Monday
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [startStr, setStartStr] = useState(nowLocal());
  const [endStr, setEndStr] = useState("");
  const [budgetStr, setBudgetStr] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const amountCents = dollarsToCents(amountStr);
  const startSec = localToSec(startStr);
  const endSec = endStr ? localToSec(endStr) : undefined;
  const budgetCents = budgetStr ? dollarsToCents(budgetStr) : undefined;

  const draft = useMemo(
    () => ({
      target,
      amount_cents: amountCents,
      frequency,
      day_of_week: frequency === "weekly" ? dayOfWeek : undefined,
      day_of_month: frequency === "monthly" ? dayOfMonth : undefined,
      start_ts: startSec,
      end_ts: endSec,
      total_budget_cents: budgetCents,
    }),
    [target, amountCents, frequency, dayOfWeek, dayOfMonth, startSec, endSec, budgetCents],
  );

  const validation = validatePlan(draft);

  // Schedule preview — project the next 5 runs from the draft.
  const preview = useMemo(() => {
    if (!validation.valid || !target) return [];
    const previewPlan: DcaPlan = {
      plan_id: "preview",
      target,
      amount_cents: amountCents,
      frequency,
      day_of_week: frequency === "weekly" ? dayOfWeek : undefined,
      day_of_month: frequency === "monthly" ? dayOfMonth : undefined,
      start_ts: startSec,
      end_ts: endSec,
      total_budget_cents: budgetCents,
      funding: "usd_wallet",
      status: "active",
      next_run_ts: startSec,
      spent_cents: 0,
      buys_count: 0,
      created_ts: msToSec(Date.now()),
    };
    return upcomingRuns(previewPlan, Date.now(), 5);
  }, [validation.valid, target, amountCents, frequency, dayOfWeek, dayOfMonth, startSec, endSec, budgetCents]);

  const walletCents = walletQ.data?.wallet_balance_cents;
  const insufficientForFirst =
    walletCents != null && Number.isFinite(amountCents) && amountCents > walletCents;

  function submit() {
    if (!target || !validation.valid) return;
    create.mutate(
      {
        target,
        amount_cents: amountCents,
        frequency,
        day_of_week: frequency === "weekly" ? dayOfWeek : undefined,
        day_of_month: frequency === "monthly" ? dayOfMonth : undefined,
        start_ts: startSec,
        end_ts: endSec,
        total_budget_cents: budgetCents,
      },
      {
        onSuccess: () => {
          toast.success("Recurring buy scheduled.");
          navigate("/dca");
        },
        onSettled: () => setConfirmOpen(false),
      },
    );
  }

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="sm">
          <Link to="/dca">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Link>
        </Button>
      </div>

      <div className="flex items-center gap-2">
        <CalendarClock className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight">New recurring buy</h1>
          <p className="text-sm text-muted-foreground">
            Schedule a dollar-cost-average buy funded from your USD cash wallet.
          </p>
        </div>
      </div>

      <ServerRunnerNote />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">1 · What to buy</CardTitle>
        </CardHeader>
        <CardContent>
          <TargetPicker value={target} onChange={setTarget} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">2 · How much &amp; how often</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="dca-amount">Amount per buy (USD)</Label>
            <Input
              id="dca-amount"
              inputMode="decimal"
              placeholder="50.00"
              value={amountStr}
              onChange={(e) => setAmountStr(e.target.value)}
              data-testid="dca-amount"
            />
            <p className="text-xs text-muted-foreground">
              Minimum {formatCents(MIN_AMOUNT_CENTS)} per buy.
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>Frequency</Label>
              <Select value={frequency} onValueChange={(v) => setFrequency(v as DcaFrequency)}>
                <SelectTrigger data-testid="dca-frequency">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                  <SelectItem value="monthly">Monthly</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {frequency === "weekly" && (
              <div className="space-y-1.5">
                <Label>Day of week</Label>
                <Select value={String(dayOfWeek)} onValueChange={(v) => setDayOfWeek(Number(v))}>
                  <SelectTrigger data-testid="dca-dow">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DOW_LABELS.map((d, i) => (
                      <SelectItem key={d} value={String(i)}>
                        {d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {frequency === "monthly" && (
              <div className="space-y-1.5">
                <Label>Day of month</Label>
                <Select value={String(dayOfMonth)} onValueChange={(v) => setDayOfMonth(Number(v))}>
                  <SelectTrigger data-testid="dca-dom">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
                      <SelectItem key={d} value={String(d)}>
                        {ordinal(d)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">Capped at the 28th so every month runs.</p>
              </div>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="dca-start">Start</Label>
            <Input
              id="dca-start"
              type="datetime-local"
              value={startStr}
              onChange={(e) => setStartStr(e.target.value)}
              data-testid="dca-start"
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">3 · Optional limits</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="dca-end">End date (optional)</Label>
            <Input
              id="dca-end"
              type="datetime-local"
              value={endStr}
              onChange={(e) => setEndStr(e.target.value)}
              data-testid="dca-end"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="dca-budget">Total budget (optional, USD)</Label>
            <Input
              id="dca-budget"
              inputMode="decimal"
              placeholder="No cap"
              value={budgetStr}
              onChange={(e) => setBudgetStr(e.target.value)}
              data-testid="dca-budget"
            />
            <p className="text-xs text-muted-foreground">
              The plan completes once this much has been spent.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <CalendarCheck className="h-4 w-4" /> Schedule preview
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!validation.valid ? (
            <ul className="space-y-1 text-sm text-muted-foreground">
              {validation.errors.map((e) => (
                <li key={e}>· {ERROR_TEXT[e] ?? e}</li>
              ))}
            </ul>
          ) : preview.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              This plan has no upcoming runs (check the end date / budget).
            </p>
          ) : (
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">
                {frequencyLabel(frequency, dayOfWeek, dayOfMonth)} · {formatCents(amountCents)} of{" "}
                <span className="font-medium text-foreground">{target?.label}</span>. Next{" "}
                {preview.length} buys:
              </p>
              <ol className="space-y-1" data-testid="dca-preview">
                {preview.map((ms, i) => (
                  <li key={ms} className="flex items-center justify-between tabular-nums">
                    <span>
                      {i + 1}.{" "}
                      {new Date(ms).toLocaleString(undefined, {
                        dateStyle: "medium",
                        timeStyle: "short",
                      })}
                    </span>
                    <span className="text-muted-foreground">{formatCents(amountCents)}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center gap-2 rounded-md border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
        <Wallet className="h-3.5 w-3.5 shrink-0" />
        {walletQ.isError ? (
          <span>
            USD cash wallet balance unavailable.{" "}
            <Link to="/custody/cash" className="font-medium text-primary underline-offset-4 hover:underline">
              Add cash
            </Link>
          </span>
        ) : walletCents != null ? (
          <span>
            USD cash wallet: <span className="font-medium text-foreground">{formatCents(walletCents)}</span>
            {insufficientForFirst ? " — below the first buy amount." : ""}{" "}
            <Link to="/custody/cash" className="font-medium text-primary underline-offset-4 hover:underline">
              Add cash
            </Link>
          </span>
        ) : (
          <span>Buys draw from your USD cash wallet.</span>
        )}
      </div>

      <div className="flex justify-end gap-2">
        <Button asChild variant="ghost">
          <Link to="/dca">Cancel</Link>
        </Button>
        <Button
          onClick={() => setConfirmOpen(true)}
          disabled={!validation.valid || create.isPending}
          data-testid="dca-submit"
        >
          Schedule recurring buy
        </Button>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Schedule this recurring buy?"
        description={
          target
            ? `${frequencyLabel(frequency, dayOfWeek, dayOfMonth)}, ${formatCents(
                amountCents,
              )} of ${target.label} will be bought automatically server-side, debiting your USD cash wallet each time${
                budgetCents ? ` until ${formatCents(budgetCents)} is spent` : ""
              }. You can pause or cancel any time.`
            : undefined
        }
        confirmLabel="Schedule"
        loading={create.isPending}
        onConfirm={submit}
      />
    </div>
  );
}
