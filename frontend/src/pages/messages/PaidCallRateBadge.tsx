import { useQuery } from "@tanstack/react-query";
import { DollarSign } from "lucide-react";
import { getCallRate } from "@/api/endpoints/callBilling";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface PaidCallRateBadgeProps {
  /** The user ID of the person being called (i.e. the creator / callee). */
  partnerUserId: string;
}

/**
 * Displays the per-minute rate for a paid call with the given partner so the
 * caller sees the cost before pressing the call button.
 *
 * Renders nothing when the partner has not configured a paid-call rate, when
 * the rate is disabled, or when the lookup returns no rate (404 → `null`).
 */
export function PaidCallRateBadge({ partnerUserId }: PaidCallRateBadgeProps) {
  const { data } = useQuery({
    queryKey: ["call-rate", partnerUserId],
    queryFn: () => getCallRate(partnerUserId),
    enabled: !!partnerUserId,
    // A 404 (no rate configured) is already converted to `null` by getCallRate;
    // any other error should not be retried for this passive disclosure badge.
    retry: false,
    // Rates change infrequently — cache for a minute to avoid refetching on
    // every conversation view.
    staleTime: 60_000,
  });

  if (!data?.enabled || !data.rate_cents_per_minute) {
    return null;
  }

  const dollars = (data.rate_cents_per_minute / 100).toFixed(2);
  const currency = data.currency ?? "USD";
  const unit = currency === "USD" ? "min" : `min (${currency})`;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="secondary"
          className="gap-1 text-xs font-normal"
          data-testid="paid-call-rate-badge"
        >
          <DollarSign className="h-3 w-3" />
          {dollars}/{unit}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        <p>This is a paid call.</p>
        <p>Rate: ${dollars} per minute.</p>
        <p>Minimum balance required: {data.min_balance_minutes} min.</p>
      </TooltipContent>
    </Tooltip>
  );
}
