import { useQuery } from "@tanstack/react-query";
import {
  CreditCard,
  Calendar,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { getSubscriptions } from "@/api/endpoints/billing";
import type { Subscription } from "@/api/types";

function statusVariant(status: string) {
  switch (status) {
    case "active":
      return "success" as const;
    case "paused":
    case "trialing":
      return "warning" as const;
    case "canceled":
    case "expired":
      return "danger" as const;
    case "past_due":
      return "danger" as const;
    default:
      return "neutral" as const;
  }
}

function formatPrice(sub: Subscription): string {
  // Subscriptions may have arbitrary keys; look for common price fields
  const priceCents = (sub as Record<string, unknown>)["price_cents"];
  if (typeof priceCents === "number") {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    }).format(priceCents / 100);
  }
  return "";
}

export function Subscriptions() {
  const subsQuery = useQuery({
    queryKey: ["billing", "subscriptions"],
    queryFn: () => getSubscriptions(),
  });

  const subscriptions: Subscription[] = subsQuery.data?.items ?? [];

  if (subsQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  if (subscriptions.length === 0) {
    return (
      <EmptyState
        icon={<RefreshCw className="h-8 w-8" />}
        title="No subscriptions"
        description="You don't have any active subscriptions"
        className="py-16"
      />
    );
  }

  return (
    <div className="space-y-3">
      {subscriptions.map((sub) => {
        const price = formatPrice(sub);
        return (
          <Card key={sub.subscription_id}>
            <CardContent className="flex items-start gap-4 p-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                <CreditCard className="h-5 w-5 text-primary" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold">{sub.plan_id}</span>
                  <StatusBadge variant={statusVariant(sub.status)} className="capitalize">
                    {sub.status.replace(/_/g, " ")}
                  </StatusBadge>
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  {price && (
                    <span className="flex items-center gap-1">
                      <CreditCard className="h-3 w-3" />
                      {price}
                      {sub.billing_cycle && (
                        <span>/ {sub.billing_cycle}</span>
                      )}
                    </span>
                  )}
                  {sub.next_billing_date && (
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      Next billing: {sub.next_billing_date}
                    </span>
                  )}
                </div>

                {/* Additional metadata as badges */}
                <div className="mt-2 flex flex-wrap gap-1">
                  {sub.billing_cycle && (
                    <Badge variant="outline" className="text-[10px] capitalize">
                      {sub.billing_cycle}
                    </Badge>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
