import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PhoneOff, DollarSign, Clock } from "lucide-react";

export interface CallBillingSummaryProps {
  totalCostCents: number;
  rateCentsPerMinute: number;
  durationSeconds: number;
  billingCycles: number;
  endReason?: string;
}

function formatTime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) {
    return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function formatDollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function humanizeEndReason(reason?: string): string {
  switch (reason) {
    case "ended":
      return "Call ended normally";
    case "balance_depleted":
      return "Balance depleted";
    case "max_duration_reached":
      return "Maximum duration reached";
    case "heartbeat_timeout":
      return "Connection lost";
    default:
      return reason || "Call ended";
  }
}

export function CallBillingSummary({
  totalCostCents,
  rateCentsPerMinute,
  durationSeconds,
  billingCycles,
  endReason,
}: CallBillingSummaryProps) {
  return (
    <Card className="w-full max-w-sm">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <PhoneOff className="h-4 w-4" />
          Paid Call Ended
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <Clock className="h-3.5 w-3.5" />
            Duration
          </span>
          <span className="font-medium">{formatTime(durationSeconds)}</span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <DollarSign className="h-3.5 w-3.5" />
            Total
          </span>
          <span className="font-medium">
            {formatDollars(totalCostCents)} at{" "}
            {formatDollars(rateCentsPerMinute)}/min
          </span>
        </div>
        {billingCycles > 0 && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Billing cycles</span>
            <span className="font-medium">{billingCycles}</span>
          </div>
        )}
        {endReason && (
          <p className="text-xs text-muted-foreground pt-1">
            {humanizeEndReason(endReason)}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
