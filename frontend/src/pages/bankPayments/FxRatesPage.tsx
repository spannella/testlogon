/**
 * OBP PAY-004 — FX Rate Quotes & Currency Conversion
 *
 * Feature-flagged: gracefully shows "not enabled" state on 404.
 * Read-only for users; admin set-rate form shown to admin/root.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeftRight, RefreshCw, AlertCircle } from "lucide-react";

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
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  getFxRate,
  convertFx,
  type FxRateOut,
  type FxConvertOut,
} from "@/api/endpoints/bankPayments";

// Common currency pairs to show at a glance
const QUICK_PAIRS = [
  { source: "usd", target: "eur" },
  { source: "usd", target: "gbp" },
  { source: "eur", target: "usd" },
  { source: "gbp", target: "usd" },
  { source: "usd", target: "jpy" },
];

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function fmtCents(cents: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: currency.toUpperCase(),
      minimumFractionDigits: 2,
    }).format(cents / 100);
  } catch {
    return `${(cents / 100).toFixed(2)} ${currency.toUpperCase()}`;
  }
}

function RateCard({ source, target }: { source: string; target: string }) {
  const query = useQuery({
    queryKey: ["fx-rate", source, target],
    queryFn: () => getFxRate(source, target),
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
    staleTime: 60_000,
  });

  const rate = query.data as FxRateOut | undefined;

  return (
    <div className="rounded-lg border p-3 text-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono font-medium uppercase">
          {source}/{target}
        </span>
        {query.isLoading && <Skeleton className="h-4 w-16" />}
        {rate && (
          <span className="font-semibold tabular-nums">{rate.rate.toFixed(6)}</span>
        )}
        {query.isError && (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </div>
      {rate && (
        <p className="text-xs text-muted-foreground mt-1">
          as of {fmtTs(rate.as_of)} · {rate.source}
        </p>
      )}
    </div>
  );
}

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-sm font-medium">FX Rates not enabled</p>
      <p className="text-xs max-w-sm">
        This feature requires the Open Banking Project and Payments flags.
        Contact your administrator to enable PAY-004.
      </p>
    </div>
  );
}

export default function FxRatesPage() {
  const qc = useQueryClient();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  // Converter state
  const [amountStr, setAmountStr] = useState("100");
  const [fromCurrency, setFromCurrency] = useState("usd");
  const [toCurrency, setToCurrency] = useState("eur");
  const [convertResult, setConvertResult] = useState<FxConvertOut | null>(null);
  const [convertError, setConvertError] = useState<string | null>(null);

  // Rate lookup state
  const [lookupSource, setLookupSource] = useState("");
  const [lookupTarget, setLookupTarget] = useState("");
  const [lookedUpRate, setLookedUpRate] = useState<FxRateOut | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // Feature gate check via first quick pair
  const gateQuery = useQuery({
    queryKey: ["fx-rate", "usd", "eur"],
    queryFn: () => getFxRate("usd", "eur"),
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
  });

  // The probe hits GET /ui/fx/rates/usd/eur. A 404 can mean EITHER the feature
  // is gated off ("not found") OR the feature is enabled but no usd/eur rate is
  // configured ("fx_rate_missing"). Only the former should render the
  // feature-disabled state — otherwise an enabled feature with no seeded rate
  // would be wrongly reported as off.
  const isRateMissing =
    gateQuery.error instanceof ApiError &&
    gateQuery.error.detail === "fx_rate_missing";
  const isDisabled =
    gateQuery.isError &&
    gateQuery.error instanceof ApiError &&
    (gateQuery.error.status === 404 || gateQuery.error.status === 503) &&
    !isRateMissing;

  const convertMut = useMutation({
    mutationFn: () => {
      const cents = Math.round(parseFloat(amountStr) * 100);
      return convertFx(cents, fromCurrency.toLowerCase(), toCurrency.toLowerCase());
    },
    onSuccess: (data) => {
      setConvertResult(data);
      setConvertError(null);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : "Conversion failed";
      setConvertError(msg);
      setConvertResult(null);
    },
  });

  const lookupMut = useMutation({
    mutationFn: () =>
      getFxRate(lookupSource.toLowerCase().trim(), lookupTarget.toLowerCase().trim()),
    onSuccess: (data) => {
      setLookedUpRate(data);
      setLookupError(null);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : "Rate not found";
      setLookupError(msg);
      setLookedUpRate(null);
    },
  });

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="FX Rates"
        description="Live foreign exchange rates and currency conversion."
        actions={
          !isDisabled && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => qc.invalidateQueries({ queryKey: ["fx-rate"] })}
            >
              <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh rates
            </Button>
          )
        }
      />

      {isDisabled && <FeatureDisabled />}

      {!isDisabled && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Quick-look rate cards */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Market rates</CardTitle>
              <CardDescription>Common currency pairs.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {QUICK_PAIRS.map((p) => (
                  <RateCard key={`${p.source}/${p.target}`} source={p.source} target={p.target} />
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Converter */}
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <ArrowLeftRight className="h-4 w-4" /> Currency converter
                </CardTitle>
                <CardDescription>Convert an amount at the current rate.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="space-y-1">
                  <Label>Amount</Label>
                  <Input
                    type="number"
                    min="0.01"
                    step="0.01"
                    placeholder="100.00"
                    value={amountStr}
                    onChange={(e) => {
                      setAmountStr(e.target.value);
                      setConvertResult(null);
                    }}
                    data-testid="fx-amount"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label>From</Label>
                    <Input
                      placeholder="usd"
                      value={fromCurrency}
                      onChange={(e) => {
                        setFromCurrency(e.target.value);
                        setConvertResult(null);
                      }}
                      data-testid="fx-from"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>To</Label>
                    <Input
                      placeholder="eur"
                      value={toCurrency}
                      onChange={(e) => {
                        setToCurrency(e.target.value);
                        setConvertResult(null);
                      }}
                      data-testid="fx-to"
                    />
                  </div>
                </div>
                <Button
                  className="w-full"
                  onClick={() => convertMut.mutate()}
                  disabled={
                    convertMut.isPending ||
                    !amountStr ||
                    parseFloat(amountStr) <= 0 ||
                    !fromCurrency.trim() ||
                    !toCurrency.trim()
                  }
                  data-testid="fx-convert-btn"
                >
                  {convertMut.isPending ? "Converting…" : "Convert"}
                </Button>
                {convertResult && (
                  <div className="rounded-lg bg-muted/50 p-3 space-y-1 text-sm" data-testid="fx-result">
                    <div className="font-semibold text-base">
                      {fmtCents(convertResult.source_amount_cents, convertResult.source_currency)}
                      {" → "}
                      {fmtCents(convertResult.target_amount_cents, convertResult.target_currency)}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Rate: {convertResult.rate.toFixed(6)}
                      {" · "}As of: {fmtTs(convertResult.as_of)}
                    </p>
                  </div>
                )}
                {convertError && (
                  <p className="text-sm text-destructive" data-testid="fx-convert-error">{convertError}</p>
                )}
              </CardContent>
            </Card>

            {/* Rate lookup */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Rate lookup</CardTitle>
                <CardDescription>Look up any currency pair.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label>Source currency</Label>
                    <Input
                      placeholder="gbp"
                      value={lookupSource}
                      onChange={(e) => { setLookupSource(e.target.value); setLookedUpRate(null); }}
                      data-testid="fx-lookup-source"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>Target currency</Label>
                    <Input
                      placeholder="jpy"
                      value={lookupTarget}
                      onChange={(e) => { setLookupTarget(e.target.value); setLookedUpRate(null); }}
                      data-testid="fx-lookup-target"
                    />
                  </div>
                </div>
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => lookupMut.mutate()}
                  disabled={lookupMut.isPending || !lookupSource.trim() || !lookupTarget.trim()}
                  data-testid="fx-lookup-btn"
                >
                  {lookupMut.isPending ? "Looking up…" : "Look up rate"}
                </Button>
                {lookedUpRate && (
                  <div className="rounded-lg border p-3 text-sm" data-testid="fx-lookup-result">
                    <div className="flex items-center justify-between">
                      <span className="font-mono uppercase">{lookedUpRate.pair}</span>
                      <span className="font-semibold tabular-nums">{lookedUpRate.rate.toFixed(6)}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {lookedUpRate.source} · {fmtTs(lookedUpRate.as_of)}
                    </p>
                  </div>
                )}
                {lookupError && (
                  <p className="text-sm text-destructive" data-testid="fx-lookup-error">{lookupError}</p>
                )}
              </CardContent>
            </Card>

            {/* Admin rate setter */}
            {isAdmin && (
              <AdminRateSetter onSet={() => qc.invalidateQueries({ queryKey: ["fx-rate"] })} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function AdminRateSetter({ onSet }: { onSet: () => void }) {
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [rate, setRate] = useState("");

  const setRateMut = useMutation({
    mutationFn: async () => {
      // Admin endpoint: POST /ui/admin/fx/rates
      const { api } = await import("@/api/client");
      return api.post("/ui/admin/fx/rates", {
        source_currency: source.toLowerCase().trim(),
        target_currency: target.toLowerCase().trim(),
        rate: parseFloat(rate),
        source: "admin",
      });
    },
    onSuccess: () => {
      toast.success("Rate updated");
      setSource("");
      setTarget("");
      setRate("");
      onSet();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to set rate"),
  });

  return (
    <Card className="border-amber-200 bg-amber-50/30 dark:bg-amber-950/10">
      <CardHeader>
        <CardTitle className="text-sm text-amber-800 dark:text-amber-400">
          Admin: Set rate
        </CardTitle>
        <CardDescription>Override an exchange rate (admin/root only).</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-3 gap-2">
          <div className="space-y-1">
            <Label>From</Label>
            <Input
              placeholder="usd"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              data-testid="admin-fx-source"
            />
          </div>
          <div className="space-y-1">
            <Label>To</Label>
            <Input
              placeholder="eur"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              data-testid="admin-fx-target"
            />
          </div>
          <div className="space-y-1">
            <Label>Rate</Label>
            <Input
              type="number"
              min="0.000001"
              step="any"
              placeholder="0.9234"
              value={rate}
              onChange={(e) => setRate(e.target.value)}
              data-testid="admin-fx-rate"
            />
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setRateMut.mutate()}
          disabled={
            setRateMut.isPending ||
            !source.trim() ||
            !target.trim() ||
            !rate ||
            parseFloat(rate) <= 0
          }
          data-testid="admin-fx-set-btn"
        >
          {setRateMut.isPending ? "Setting…" : "Set rate"}
        </Button>
      </CardContent>
    </Card>
  );
}
