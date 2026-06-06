import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import { PageHeader } from "@/components/shared/PageHeader";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  getCallRate,
  setCallRate,
  updateCallRate,
  deleteCallRate,
  type CallRate,
  type CallRateIn,
} from "@/api/endpoints/callBilling";
import { useAuthStore } from "@/stores/authStore";

const QUERY_KEY = ["call-rate", "own"] as const;

const rateSchema = z.object({
  rateDollarsPerMinute: z.number().min(1).max(100),
  minBalanceMinutes: z.number().int().min(1).max(60),
  maxDurationMinutes: z.number().int().min(1).max(480),
  enabled: z.boolean(),
});

type RateFormValues = z.infer<typeof rateSchema>;

export default function CallRateSettings() {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();

  const { data: existing, isLoading } = useQuery<CallRate | null>({
    queryKey: QUERY_KEY,
    queryFn: async () => {
      try {
        return await getCallRate(userId ?? "");
      } catch {
        // No rate configured yet (404) — treat as "not set".
        return null;
      }
    },
    enabled: !!userId,
    retry: false,
  });

  const hasRate = !!existing?.rate_cents_per_minute;

  const form = useForm<RateFormValues>({
    resolver: zodResolver(rateSchema),
    values: existing
      ? {
          rateDollarsPerMinute: existing.rate_cents_per_minute / 100,
          minBalanceMinutes: existing.min_balance_minutes,
          maxDurationMinutes: existing.max_duration_minutes,
          enabled: existing.enabled,
        }
      : {
          rateDollarsPerMinute: 1.0,
          minBalanceMinutes: 5,
          maxDurationMinutes: 120,
          enabled: true,
        },
  });

  const saveMutation = useMutation({
    mutationFn: (values: RateFormValues) => {
      const body: CallRateIn = {
        rate_cents_per_minute: Math.round(values.rateDollarsPerMinute * 100),
        enabled: values.enabled,
        min_balance_minutes: values.minBalanceMinutes,
        max_duration_minutes: values.maxDurationMinutes,
      };
      return hasRate ? updateCallRate(body) : setCallRate(body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-rate"] });
      toast.success("Call rate saved.");
    },
    onError: () => toast.error("Failed to save call rate."),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteCallRate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["call-rate"] });
      toast.success("Paid calls disabled.");
    },
    onError: () => toast.error("Failed to disable paid calls."),
  });

  if (isLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading…</div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Call Rate Settings"
        description="Configure your per-minute rate for paid calls."
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Pay-Per-Minute Rate</CardTitle>
          <CardDescription>
            Callers will see this rate before initiating a call and will be
            charged per minute. The platform retains a fee; the remainder is
            credited to your wallet.
          </CardDescription>
        </CardHeader>
        <Separator />
        <CardContent className="space-y-4 pt-4">
          <form
            onSubmit={form.handleSubmit((v) => saveMutation.mutate(v))}
            className="space-y-4"
          >
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <Label htmlFor="rate">Rate ($/min)</Label>
                <Input
                  id="rate"
                  type="number"
                  step="0.01"
                  min="1"
                  max="100"
                  data-testid="rate-input"
                  {...form.register("rateDollarsPerMinute", {
                    valueAsNumber: true,
                  })}
                />
                {form.formState.errors.rateDollarsPerMinute && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.rateDollarsPerMinute.message}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <Label htmlFor="minBalance">Min balance (minutes)</Label>
                <Input
                  id="minBalance"
                  type="number"
                  min="1"
                  max="60"
                  data-testid="min-balance-input"
                  {...form.register("minBalanceMinutes", {
                    valueAsNumber: true,
                  })}
                />
                {form.formState.errors.minBalanceMinutes && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.minBalanceMinutes.message}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <Label htmlFor="maxDuration">Max duration (minutes)</Label>
                <Input
                  id="maxDuration"
                  type="number"
                  min="1"
                  max="480"
                  data-testid="max-duration-input"
                  {...form.register("maxDurationMinutes", {
                    valueAsNumber: true,
                  })}
                />
                {form.formState.errors.maxDurationMinutes && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.maxDurationMinutes.message}
                  </p>
                )}
              </div>

              <div className="flex items-center gap-3 pt-5">
                <Switch
                  id="enabled"
                  checked={form.watch("enabled")}
                  onCheckedChange={(v) => form.setValue("enabled", v)}
                  data-testid="enabled-switch"
                />
                <Label htmlFor="enabled">Enabled</Label>
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <Button
                type="submit"
                disabled={saveMutation.isPending}
                data-testid="save-rate-button"
              >
                {hasRate ? "Save Changes" : "Enable Paid Calls"}
              </Button>

              {hasRate && (
                <Button
                  type="button"
                  variant="destructive"
                  disabled={deleteMutation.isPending}
                  data-testid="delete-rate-button"
                  onClick={() => {
                    if (
                      window.confirm(
                        "Disable paid calls and remove your rate?",
                      )
                    ) {
                      deleteMutation.mutate();
                    }
                  }}
                >
                  Disable Paid Calls
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
