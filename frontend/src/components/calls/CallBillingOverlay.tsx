import { DollarSign, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

export interface CallBillingOverlayProps {
  totalCostCents: number;
  rateCentsPerMinute: number;
  elapsedSeconds: number;
  balanceRemainingCents: number;
  warnLowBalance?: boolean;
  minutesRemaining?: number;
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function formatDollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export function CallBillingOverlay({
  totalCostCents,
  rateCentsPerMinute,
  elapsedSeconds,
  balanceRemainingCents,
  warnLowBalance = false,
  minutesRemaining = 0,
}: CallBillingOverlayProps) {
  return (
    <>
      {/* Cost ticker */}
      <div className="absolute top-4 left-4 flex flex-col gap-1 bg-black/70 text-white px-3 py-2 rounded-lg text-sm z-50">
        <div className="flex items-center gap-2">
          <DollarSign className="h-3 w-3" />
          <span className="font-mono">{formatDollars(totalCostCents)}</span>
          <span className="text-xs text-gray-400">{formatTime(elapsedSeconds)}</span>
        </div>
        <div className="flex items-center justify-between text-xs text-gray-300">
          <span>{formatDollars(rateCentsPerMinute)}/min</span>
          <span>Bal: {formatDollars(balanceRemainingCents)}</span>
        </div>
      </div>

      {/* Low balance warning */}
      {warnLowBalance && (
        <div
          className={cn(
            "absolute top-16 left-1/2 -translate-x-1/2 z-50",
            "bg-yellow-600/90 text-white px-4 py-2 rounded-full",
            "text-sm font-medium animate-pulse",
            "flex items-center gap-2",
          )}
        >
          <AlertTriangle className="h-4 w-4" />
          Low balance — {minutesRemaining.toFixed(1)} min remaining
        </div>
      )}
    </>
  );
}
