/**
 * Hotel Cancellation Policy Editor — HTL-034
 *
 * Route: hotels/policies/:hotelId  (optionally hotels/policies for list view)
 *
 * Lets an admin configure the default cancellation policy for a hotel:
 *   - Free-cancellation window (days before check-in)
 *   - Penalty percentage OR fixed penalty cents
 *   - No-show fee cents
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF). Gracefully shows a
 * "Hotel PMS not enabled" state when the backend returns 404.
 * Money is stored as integer cents; displayed as formatted currency.
 */

import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ShieldCheck,
  Hotel,
  Save,
  RotateCcw,
  AlertTriangle,
  Loader2,
  Info,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getCancellationPolicy,
  upsertCancellationPolicy,
  type CancellationPolicyIn,
  type CancellationPolicyOut,
} from "@/api/endpoints/hotelReports";
import { PageHeader } from "@/components/shared/PageHeader";
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
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// ─── Currency helper ──────────────────────────────────────────────────────────

function centsToDisplay(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function displayToCents(value: string): number {
  const n = parseFloat(value.replace(/[^0-9.-]/g, ""));
  if (isNaN(n) || n < 0) return 0;
  return Math.round(n * 100);
}

// ─── Field state helpers ──────────────────────────────────────────────────────

interface FormState {
  free_until_days_before: string;
  penalty_pct: string;
  penalty_fixed_display: string; // display value in dollars
  no_show_fee_display: string;   // display value in dollars
}

function policyToForm(p: CancellationPolicyOut): FormState {
  return {
    free_until_days_before: String(p.free_until_days_before),
    penalty_pct: String(p.penalty_pct),
    penalty_fixed_display:
      p.penalty_fixed_cents > 0
        ? (p.penalty_fixed_cents / 100).toFixed(2)
        : "",
    no_show_fee_display:
      p.no_show_fee_cents > 0
        ? (p.no_show_fee_cents / 100).toFixed(2)
        : "",
  };
}

const EMPTY_FORM: FormState = {
  free_until_days_before: "0",
  penalty_pct: "0",
  penalty_fixed_display: "",
  no_show_fee_display: "",
};

// ─── Disabled / not-enabled state ────────────────────────────────────────────

function NotEnabledState() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <AlertTriangle className="h-12 w-12 text-amber-500" />
      <h2 className="text-xl font-semibold text-muted-foreground">
        Hotel PMS not enabled
      </h2>
      <p className="max-w-md text-sm text-muted-foreground">
        The Hotel PMS feature is currently disabled on this platform. Enable{" "}
        <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
          HOTEL_PMS_ENABLED
        </code>{" "}
        to manage cancellation policies.
      </p>
      <Button variant="outline" asChild>
        <Link to="/hotels/setup">Back to Hotels</Link>
      </Button>
    </div>
  );
}

// ─── Policy summary card ──────────────────────────────────────────────────────

function PolicySummaryCard({ policy }: { policy: CancellationPolicyOut }) {
  const fmtDate = (ts: number) =>
    ts ? new Date(ts * 1000).toLocaleString() : "—";

  return (
    <Card className="border-dashed bg-muted/30">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          Saved Policy
        </CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
        <div>
          <p className="text-xs text-muted-foreground">Free window</p>
          <p className="font-medium">{policy.free_until_days_before} days</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Penalty %</p>
          <p className="font-medium">{policy.penalty_pct}%</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Fixed penalty</p>
          <p className="font-medium">
            {policy.penalty_fixed_cents > 0
              ? centsToDisplay(policy.penalty_fixed_cents)
              : "—"}
          </p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">No-show fee</p>
          <p className="font-medium">
            {policy.no_show_fee_cents > 0
              ? centsToDisplay(policy.no_show_fee_cents)
              : "—"}
          </p>
        </div>
        <div className="col-span-2 mt-1">
          <p className="text-xs text-muted-foreground">Last updated</p>
          <p className="font-medium">{fmtDate(policy.updated_at)}</p>
        </div>
        <div className="col-span-2 mt-1">
          <Badge variant="secondary" className="text-xs">
            scope: {policy.scope}
          </Badge>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function CancellationPolicyPage() {
  const { hotelId } = useParams<{ hotelId: string }>();
  const qc = useQueryClient();

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [isFormDirty, setIsFormDirty] = useState(false);

  // ── Fetch existing policy ──────────────────────────────────────────────────

  const {
    data: policy,
    isLoading,
    error,
    isError,
  } = useQuery<CancellationPolicyOut, ApiError>({
    queryKey: ["hotel-cancel-policy", hotelId],
    queryFn: () => getCancellationPolicy(hotelId!, "default"),
    enabled: !!hotelId,
    retry: (failureCount, err) => {
      // Never retry on feature-off (404) or "not found yet" (404)
      if (err instanceof ApiError && err.status === 404) return false;
      return failureCount < 2;
    },
  });

  // Populate form once data arrives
  useEffect(() => {
    if (policy && !isFormDirty) {
      setForm(policyToForm(policy));
    }
  }, [policy, isFormDirty]);

  // ── Save mutation ──────────────────────────────────────────────────────────

  const saveMutation = useMutation<
    CancellationPolicyOut,
    ApiError,
    CancellationPolicyIn
  >({
    mutationFn: (body) =>
      upsertCancellationPolicy(hotelId!, body, "default"),
    onSuccess: (saved) => {
      qc.setQueryData(["hotel-cancel-policy", hotelId], saved);
      setIsFormDirty(false);
      toast.success("Cancellation policy saved");
    },
    onError: (err) => {
      toast.error(err.message || "Failed to save policy");
    },
  });

  // ── Form handlers ──────────────────────────────────────────────────────────

  function setField(field: keyof FormState, value: string) {
    setForm((prev) => ({ ...prev, [field]: value }));
    setIsFormDirty(true);
  }

  function handleReset() {
    if (policy) {
      setForm(policyToForm(policy));
    } else {
      setForm(EMPTY_FORM);
    }
    setIsFormDirty(false);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const free_until = parseInt(form.free_until_days_before, 10) || 0;
    const pct = parseInt(form.penalty_pct, 10) || 0;
    const fixedCents = form.penalty_fixed_display.trim()
      ? displayToCents(form.penalty_fixed_display)
      : 0;
    const noShowCents = form.no_show_fee_display.trim()
      ? displayToCents(form.no_show_fee_display)
      : 0;

    if (free_until < 0) {
      toast.error("Free window cannot be negative");
      return;
    }
    if (pct < 0 || pct > 100) {
      toast.error("Penalty % must be between 0 and 100");
      return;
    }

    saveMutation.mutate({
      free_until_days_before: free_until,
      penalty_pct: pct,
      penalty_fixed_cents: fixedCents,
      no_show_fee_cents: noShowCents,
    });
  }

  // ── Feature off — 404 with "Hotel PMS" message ─────────────────────────────

  const featureOff =
    isError &&
    error instanceof ApiError &&
    error.status === 404 &&
    (error.detail?.toLowerCase().includes("pms") ||
      error.detail?.toLowerCase().includes("enabled"));

  if (featureOff) {
    return (
      <div className="p-6">
        <NotEnabledState />
      </div>
    );
  }

  // ── Hotel id missing guard ─────────────────────────────────────────────────

  if (!hotelId) {
    return (
      <div className="flex flex-col items-center gap-4 py-16 text-center">
        <Hotel className="h-10 w-10 text-muted-foreground" />
        <p className="text-muted-foreground">
          No hotel selected. Go to{" "}
          <Link to="/hotels/setup" className="underline">
            Hotels
          </Link>{" "}
          and pick a hotel to configure its cancellation policy.
        </p>
      </div>
    );
  }

  const policyNotFound =
    isError && error instanceof ApiError && error.status === 404;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Cancellation Policy"
        description={
          hotelId
            ? `Configure the default cancellation policy for hotel ${hotelId}`
            : "Configure cancellation policy"
        }
        actions={<ShieldCheck className="h-6 w-6 text-muted-foreground" />}
      />

      {/* Back nav */}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Link
          to="/hotels/setup"
          className="hover:text-foreground hover:underline"
        >
          Hotels
        </Link>
        <span>/</span>
        <Link
          to={`/hotels/setup/${hotelId}`}
          className="hover:text-foreground hover:underline"
        >
          {hotelId}
        </Link>
        <span>/</span>
        <span className="text-foreground">Cancellation Policy</span>
      </div>

      {/* Current saved policy summary */}
      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading current policy…
        </div>
      )}

      {policy && <PolicySummaryCard policy={policy} />}

      {policyNotFound && !featureOff && (
        <div className="flex items-center gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
          <Info className="h-4 w-4 flex-shrink-0" />
          No cancellation policy has been saved for this hotel yet. Fill in the
          form below to create one.
        </div>
      )}

      {/* Editor form */}
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="text-base">Edit Policy</CardTitle>
          <CardDescription>
            All monetary values are in USD. Fixed penalty and percentage penalty
            are both stored — the backend applies the fixed penalty if non-zero,
            otherwise the percentage.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Free window */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5">
                <Label htmlFor="free-days">Free cancellation window (days)</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
                  </TooltipTrigger>
                  <TooltipContent side="right" className="max-w-xs text-xs">
                    Guests can cancel for free up to this many days before
                    check-in. Set to 0 for no free window (penalty always
                    applies).
                  </TooltipContent>
                </Tooltip>
              </div>
              <Input
                id="free-days"
                type="number"
                min={0}
                step={1}
                value={form.free_until_days_before}
                onChange={(e) =>
                  setField("free_until_days_before", e.target.value)
                }
                className="w-32"
                placeholder="0"
              />
            </div>

            <Separator />

            {/* Penalty section */}
            <fieldset className="space-y-4">
              <legend className="text-sm font-medium">
                Penalty (if cancelled outside free window)
              </legend>

              {/* Pct */}
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5">
                  <Label htmlFor="penalty-pct">Penalty percentage (%)</Label>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Info className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent side="right" className="max-w-xs text-xs">
                      % of the reservation total charged as a penalty. Ignored
                      when a fixed penalty is set.
                    </TooltipContent>
                  </Tooltip>
                </div>
                <div className="flex items-center gap-2">
                  <Input
                    id="penalty-pct"
                    type="number"
                    min={0}
                    max={100}
                    step={1}
                    value={form.penalty_pct}
                    onChange={(e) => setField("penalty_pct", e.target.value)}
                    className="w-24"
                    placeholder="0"
                  />
                  <span className="text-sm text-muted-foreground">%</span>
                </div>
              </div>

              {/* Fixed */}
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5">
                  <Label htmlFor="penalty-fixed">
                    Fixed penalty (USD, leave blank for none)
                  </Label>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Info className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent side="right" className="max-w-xs text-xs">
                      A flat fee charged instead of the percentage penalty.
                      Leave blank to use percentage only.
                    </TooltipContent>
                  </Tooltip>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">$</span>
                  <Input
                    id="penalty-fixed"
                    type="number"
                    min={0}
                    step={0.01}
                    value={form.penalty_fixed_display}
                    onChange={(e) =>
                      setField("penalty_fixed_display", e.target.value)
                    }
                    className="w-36"
                    placeholder="0.00"
                  />
                </div>
                {form.penalty_fixed_display.trim() &&
                  parseFloat(form.penalty_fixed_display) > 0 && (
                    <p className="text-xs text-muted-foreground">
                      ={" "}
                      {centsToDisplay(
                        displayToCents(form.penalty_fixed_display),
                      )}{" "}
                      (
                      {displayToCents(form.penalty_fixed_display).toLocaleString()}{" "}
                      cents)
                    </p>
                  )}
              </div>
            </fieldset>

            <Separator />

            {/* No-show fee */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5">
                <Label htmlFor="no-show-fee">
                  No-show fee (USD, leave blank for none)
                </Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
                  </TooltipTrigger>
                  <TooltipContent side="right" className="max-w-xs text-xs">
                    Charged when the guest fails to check in without cancelling.
                    Separate from the cancellation penalty.
                  </TooltipContent>
                </Tooltip>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">$</span>
                <Input
                  id="no-show-fee"
                  type="number"
                  min={0}
                  step={0.01}
                  value={form.no_show_fee_display}
                  onChange={(e) =>
                    setField("no_show_fee_display", e.target.value)
                  }
                  className="w-36"
                  placeholder="0.00"
                />
              </div>
              {form.no_show_fee_display.trim() &&
                parseFloat(form.no_show_fee_display) > 0 && (
                  <p className="text-xs text-muted-foreground">
                    ={" "}
                    {centsToDisplay(
                      displayToCents(form.no_show_fee_display),
                    )}{" "}
                    (
                    {displayToCents(form.no_show_fee_display).toLocaleString()}{" "}
                    cents)
                  </p>
                )}
            </div>

            <Separator />

            {/* Action buttons */}
            <div className="flex items-center gap-3 pt-1">
              <Button
                type="submit"
                disabled={saveMutation.isPending}
                className="gap-2"
              >
                {saveMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Save Policy
              </Button>

              <Button
                type="button"
                variant="outline"
                onClick={handleReset}
                disabled={!isFormDirty || saveMutation.isPending}
                className="gap-2"
              >
                <RotateCcw className="h-4 w-4" />
                Reset
              </Button>

              {isFormDirty && (
                <Badge variant="outline" className="text-xs text-amber-600">
                  Unsaved changes
                </Badge>
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      {/* KPI link */}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">View hotel performance →</span>
        <Link
          to={`/hotels/reports/${hotelId}`}
          className="font-medium text-primary underline-offset-2 hover:underline"
        >
          KPI Dashboard
        </Link>
      </div>
    </div>
  );
}
