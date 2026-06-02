import { useState, useEffect } from "react";
import { Timer, Radio, Phone, CalendarDays } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type CountdownEventType = "broadcast" | "call" | "calendar" | "custom";

export interface CountdownCardProps {
  title: string;
  /** UTC Unix timestamp (seconds) for the countdown target. */
  targetDatetime: number;
  associatedEventType?: CountdownEventType | null;
  associatedEventId?: string | null;
  className?: string;
}

interface TimeParts {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
  expired: boolean;
}

function computeTimeParts(targetMs: number, nowMs: number): TimeParts {
  let remaining = Math.floor((targetMs - nowMs) / 1000);
  if (remaining <= 0) {
    return { days: 0, hours: 0, minutes: 0, seconds: 0, expired: true };
  }
  const days = Math.floor(remaining / 86400);
  remaining -= days * 86400;
  const hours = Math.floor(remaining / 3600);
  remaining -= hours * 3600;
  const minutes = Math.floor(remaining / 60);
  remaining -= minutes * 60;
  const seconds = remaining;
  return { days, hours, minutes, seconds, expired: false };
}

const pad = (n: number) => String(n).padStart(2, "0");

function eventCta(
  eventType: CountdownEventType | null | undefined,
): { label: string; Icon: typeof Radio } | null {
  switch (eventType) {
    case "broadcast":
      return { label: "Watch Live", Icon: Radio };
    case "call":
      return { label: "Join Call", Icon: Phone };
    case "calendar":
      return { label: "View Event", Icon: CalendarDays };
    default:
      return null;
  }
}

/**
 * FEED-005 / MSG-010: Live countdown card.
 *
 * Renders a ticking days/hours/minutes/seconds timer until `targetDatetime`.
 * At zero it switches to a "Time's up!" state and reveals the contextual CTA
 * button for the associated event (if any).
 */
export function CountdownCard({
  title,
  targetDatetime,
  associatedEventType,
  associatedEventId,
  className,
}: CountdownCardProps) {
  const targetMs = targetDatetime * 1000;
  const [parts, setParts] = useState<TimeParts>(() =>
    computeTimeParts(targetMs, Date.now()),
  );

  useEffect(() => {
    setParts(computeTimeParts(targetMs, Date.now()));
    const id = setInterval(() => {
      setParts(computeTimeParts(targetMs, Date.now()));
    }, 1000);
    return () => clearInterval(id);
  }, [targetMs]);

  const cta = eventCta(associatedEventType);

  return (
    <div
      data-testid="countdown-card"
      data-expired={parts.expired ? "true" : "false"}
      className={cn(
        "rounded-lg border border-border bg-muted/30 p-4",
        className,
      )}
    >
      <div className="flex items-center gap-2 mb-3">
        <Timer className="h-4 w-4 text-primary shrink-0" />
        <p
          data-testid="countdown-title"
          className="text-sm font-semibold truncate"
        >
          {title}
        </p>
      </div>

      {parts.expired ? (
        <div
          data-testid="countdown-expired"
          className="text-center py-2"
        >
          <p className="text-lg font-bold text-primary">
            {associatedEventType === "broadcast" || associatedEventType === "call"
              ? "Happening now!"
              : "Time's up!"}
          </p>
        </div>
      ) : (
        <div
          data-testid="countdown-timer"
          className="grid grid-cols-4 gap-2 text-center"
        >
          {[
            { label: "Days", value: parts.days },
            { label: "Hours", value: parts.hours },
            { label: "Min", value: parts.minutes },
            { label: "Sec", value: parts.seconds },
          ].map((unit) => (
            <div key={unit.label} className="rounded-md bg-background p-2">
              <div className="text-xl font-bold tabular-nums">
                {unit.label === "Days" ? unit.value : pad(unit.value)}
              </div>
              <div className="text-[10px] uppercase text-muted-foreground tracking-wide">
                {unit.label}
              </div>
            </div>
          ))}
        </div>
      )}

      {cta && (
        <div className="mt-3 flex justify-center">
          <Button
            type="button"
            size="sm"
            variant={parts.expired ? "default" : "outline"}
            data-testid="countdown-cta"
            data-event-id={associatedEventId ?? undefined}
          >
            <cta.Icon className="mr-1 h-3.5 w-3.5" />
            {cta.label}
          </Button>
        </div>
      )}
    </div>
  );
}

export default CountdownCard;
