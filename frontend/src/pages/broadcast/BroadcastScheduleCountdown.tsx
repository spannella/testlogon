import { useEffect, useState } from "react";

interface BroadcastScheduleCountdownProps {
  /** Target Unix timestamp (seconds) to count down to. */
  scheduledAt: number;
  /** "full" shows d/h/m/s; "compact" shows the two largest non-zero units. */
  variant?: "full" | "compact";
  /** Called once when the countdown reaches zero. */
  onExpired?: () => void;
  className?: string;
}

interface CountdownState {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  remaining: number;
  expired: boolean;
}

function compute(scheduledAt: number): CountdownState {
  const remaining = scheduledAt - Math.floor(Date.now() / 1000);
  if (remaining <= 0) {
    return { days: 0, hours: 0, minutes: 0, seconds: 0, remaining: 0, expired: true };
  }
  return {
    days: Math.floor(remaining / 86400),
    hours: Math.floor((remaining % 86400) / 3600),
    minutes: Math.floor((remaining % 3600) / 60),
    seconds: remaining % 60,
    remaining,
    expired: false,
  };
}

export function BroadcastScheduleCountdown({
  scheduledAt,
  variant = "full",
  onExpired,
  className,
}: BroadcastScheduleCountdownProps) {
  const [state, setState] = useState<CountdownState>(() => compute(scheduledAt));

  useEffect(() => {
    setState(compute(scheduledAt));
    const id = setInterval(() => {
      const next = compute(scheduledAt);
      setState(next);
      if (next.expired) {
        clearInterval(id);
        onExpired?.();
      }
    }, 1000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scheduledAt]);

  if (state.expired) {
    return (
      <span className={`text-green-600 dark:text-green-400 font-medium ${className ?? ""}`} data-testid="countdown-expired">
        Starting now...
      </span>
    );
  }

  let color = "text-muted-foreground";
  if (state.remaining <= 3600) color = "text-red-600 dark:text-red-400";
  else if (state.remaining <= 86400) color = "text-amber-600 dark:text-amber-400";

  let text: string;
  if (variant === "compact") {
    if (state.days > 0) text = `${state.days}d ${state.hours}h`;
    else if (state.hours > 0) text = `${state.hours}h ${state.minutes}m`;
    else text = `${state.minutes}m ${state.seconds}s`;
  } else {
    const parts: string[] = [];
    if (state.days > 0) parts.push(`${state.days}d`);
    if (state.hours > 0 || state.days > 0) parts.push(`${state.hours}h`);
    parts.push(`${state.minutes}m`);
    parts.push(`${state.seconds}s`);
    text = parts.join(" ");
  }

  return (
    <span className={`font-mono ${color} ${className ?? ""}`} data-testid="countdown-timer">
      {text}
    </span>
  );
}

export default BroadcastScheduleCountdown;
