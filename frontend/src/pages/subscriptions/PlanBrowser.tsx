import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Check, Sparkles, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { listPlans, subscribe } from "@/api/endpoints/subscriptions";
import type { SubscriptionPlan } from "@/api/types";

// ─── Helpers ──────────────────────────────────────────────────

function formatPrice(cents: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function intervalLabel(interval: string, count?: number): string {
  const n = count ?? 1;
  if (n === 1) return interval;
  return `${n} ${interval}s`;
}

// ─── Component ──────────────────────────────────────────────────

interface PlanBrowserProps {
  creatorId: string;
}

export function PlanBrowser({ creatorId }: PlanBrowserProps) {
  const queryClient = useQueryClient();
  const [discountCode, setDiscountCode] = useState("");
  const [subscribingPlanId, setSubscribingPlanId] = useState<string | null>(null);

  const { data: plans, isLoading } = useQuery({
    queryKey: ["plans", creatorId],
    queryFn: () => listPlans(creatorId),
    enabled: !!creatorId,
  });

  const subscribeMutation = useMutation({
    mutationFn: (planId: string) =>
      subscribe(planId, discountCode ? { discount_code: discountCode } : undefined),
    onSuccess: () => {
      toast.success("Subscribed successfully!");
      void queryClient.invalidateQueries({ queryKey: ["subscriptions"] });
      setSubscribingPlanId(null);
    },
    onError: () => {
      toast.error("Failed to subscribe. Please try again.");
      setSubscribingPlanId(null);
    },
  });

  const handleSubscribe = (planId: string) => {
    setSubscribingPlanId(planId);
    subscribeMutation.mutate(planId);
  };

  const activePlans = (plans ?? []).filter((p) => p.status === "active");

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-72 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  if (activePlans.length === 0) {
    return (
      <EmptyState
        icon={<Sparkles className="h-8 w-8" />}
        title="No plans available"
        description="Check back later for subscription plans."
      />
    );
  }

  // Mark middle plan as "popular" if there are 3+ plans
  const popularIdx = activePlans.length >= 3 ? Math.floor(activePlans.length / 2) : -1;

  return (
    <div className="space-y-6">
      {/* Discount code input */}
      <div className="flex items-center gap-2">
        <Input
          placeholder="Discount code"
          value={discountCode}
          onChange={(e) => setDiscountCode(e.target.value)}
          className="max-w-xs"
        />
        {discountCode && (
          <Badge variant="outline" className="text-xs">
            Code: {discountCode}
          </Badge>
        )}
      </div>

      {/* Plan cards grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {activePlans.map((plan: SubscriptionPlan, idx: number) => {
          const isPopular = idx === popularIdx;
          const isBusy = subscribingPlanId === plan.plan_id && subscribeMutation.isPending;

          return (
            <Card
              key={plan.plan_id}
              className={isPopular ? "border-primary shadow-md" : ""}
            >
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <CardTitle className="text-lg">{plan.name}</CardTitle>
                  {isPopular && (
                    <Badge className="bg-primary text-primary-foreground">Popular</Badge>
                  )}
                </div>
                {plan.description && (
                  <p className="text-sm text-muted-foreground">{plan.description}</p>
                )}
              </CardHeader>

              <CardContent className="space-y-4">
                {/* Price */}
                <div>
                  <span className="text-3xl font-bold">
                    {formatPrice(plan.price_cents, plan.currency)}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {" "}
                    / {intervalLabel(plan.interval)}
                  </span>
                </div>

                {/* Annual price if available */}
                {plan.annual_price_cents != null && plan.interval === "month" && (
                  <p className="text-xs text-muted-foreground">
                    or {formatPrice(plan.annual_price_cents, plan.currency)} / year
                  </p>
                )}

                {/* Features */}
                {plan.assets && plan.assets.length > 0 && (
                  <ul className="space-y-1.5">
                    {plan.assets.map((asset) => (
                      <li key={asset.path} className="flex items-start gap-2 text-sm">
                        <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                        <span>{asset.name}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>

              <CardFooter>
                <Button
                  className="w-full"
                  variant={isPopular ? "default" : "outline"}
                  onClick={() => handleSubscribe(plan.plan_id)}
                  disabled={isBusy}
                >
                  {isBusy ? (
                    <>
                      <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                      Subscribing...
                    </>
                  ) : (
                    "Subscribe"
                  )}
                </Button>
              </CardFooter>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
