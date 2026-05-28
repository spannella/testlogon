import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

interface BroadcastCountdownProps {
  scheduledAt: number;
  variant?: "full" | "compact";
  onExpired?: () => void;
  className?: string;
}

interface CountdownState {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  expired: boolean;
}

function computeCountdown(scheduledAt: number): CountdownState {
  const remaining = scheduledAt - Math.floor(Date.now() / 1000);
  if (remaining <= 0) {
    return { days: 0, hours: 0, minutes: 0, seconds: 0, expired: true };
  }
  return {
    days: Math.floor(remaining / 86400),
    hours: Math.floor((remaining % 86400) / 3600),
    minutes: Math.floor((remaining % 3600) / 60),
    seconds: remaining % 60,
    expired: false,
  };
}

export function BroadcastCountdown({
  scheduledAt,
  variant = "full",
  onExpired,
  className,
}: BroadcastCountdownProps) {
  const [state, setState] = useState<CountdownState>(() => computeCountdown(scheduledAt));

  useEffect(() => {
    const interval = setInterval(() => {
      const next = computeCountdown(scheduledAt);
      setState(next);
      if (next.expired) {
        clearInterval(interval);
        onExpired?.();
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [scheduledAt, onExpired]);

  if (state.expired) {
    return (
      <span className={cn("inline-flex items-center gap-1 text-green-600", className)}>
        <Loader2 className="h-3 w-3 animate-spin" />
        Starting now...
      </span>
    );
  }

  const remaining = scheduledAt - Math.floor(Date.now() / 1000);
  const colorClass =
    remaining <= 3600
      ? "text-red-600 animate-pulse"
      : remaining <= 86400
        ? "text-amber-600"
        : "text-muted-foreground";

  if (variant === "compact") {
    // Show two largest non-zero units
    const parts: string[] = [];
    if (state.days > 0) parts.push(`${state.days}d`);
    if (state.hours > 0) parts.push(`${state.hours}h`);
    if (state.minutes > 0 && parts.length < 2) parts.push(`${state.minutes}m`);
    if (state.seconds > 0 && parts.length < 2) parts.push(`${state.seconds}s`);
    return (
      <span className={cn("font-mono text-sm", colorClass, className)}>
        {parts.join(" ")}
      </span>
    );
  }

  // Full variant
  return (
    <span className={cn("font-mono text-sm", colorClass, className)}>
      {state.days > 0 && `${state.days}d `}
      {state.hours > 0 && `${state.hours}h `}
      {state.minutes}m {state.seconds}s
    </span>
  );
}
