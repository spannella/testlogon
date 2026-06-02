import { useEffect, useState } from "react";
import { Timer } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export interface CountdownCardProps {
  title: string;
  targetDatetime: number; // UTC Unix timestamp (seconds)
  associatedEventType?: string | null;
  associatedEventId?: string | null;
}

interface Remaining {
  total: number;
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
}

function calculateRemaining(targetTs: number): Remaining {
  const diff = targetTs - Math.floor(Date.now() / 1000);
  if (diff <= 0) {
    return { total: 0, days: 0, hours: 0, minutes: 0, seconds: 0 };
  }
  return {
    total: diff,
    days: Math.floor(diff / 86400),
    hours: Math.floor((diff % 86400) / 3600),
    minutes: Math.floor((diff % 3600) / 60),
    seconds: diff % 60,
  };
}

function pad(n: number): string {
  return n.toString().padStart(2, "0");
}

export function CountdownCard({
  title,
  targetDatetime,
  associatedEventType,
  associatedEventId,
}: CountdownCardProps) {
  const [remaining, setRemaining] = useState<Remaining>(() =>
    calculateRemaining(targetDatetime),
  );

  useEffect(() => {
    setRemaining(calculateRemaining(targetDatetime));
    const interval = setInterval(() => {
      const next = calculateRemaining(targetDatetime);
      setRemaining(next);
      if (next.total <= 0) {
        clearInterval(interval);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [targetDatetime]);

  const isExpired = remaining.total <= 0;
  const eventType = associatedEventType || "custom";

  return (
    <Card className="w-72 max-w-full" data-testid="countdown-card">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Timer className="h-4 w-4 shrink-0" />
          <span className="truncate" data-testid="countdown-title">
            {title}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!isExpired ? (
          <div
            className="text-center text-2xl font-mono font-bold tracking-wider"
            data-testid="countdown-timer"
          >
            {remaining.days > 0 && <span>{remaining.days}d </span>}
            <span>
              {pad(remaining.hours)}:{pad(remaining.minutes)}:
              {pad(remaining.seconds)}
            </span>
          </div>
        ) : (
          <div className="text-center" data-testid="countdown-expired">
            <p className="text-lg font-semibold text-green-600">
              {eventType === "custom" ? "Time's up!" : "Event started!"}
            </p>
            {eventType === "broadcast" && associatedEventId && (
              <Button size="sm" className="mt-2" asChild>
                <a
                  href={`/broadcasts/${associatedEventId}`}
                  data-testid="countdown-cta"
                >
                  Watch Live
                </a>
              </Button>
            )}
            {eventType === "call" && associatedEventId && (
              <Button size="sm" className="mt-2" asChild>
                <a
                  href={`/calls/${associatedEventId}`}
                  data-testid="countdown-cta"
                >
                  Join Call
                </a>
              </Button>
            )}
            {eventType === "calendar" && associatedEventId && (
              <Button size="sm" className="mt-2" asChild>
                <a
                  href={`/calendar/events/${associatedEventId}`}
                  data-testid="countdown-cta"
                >
                  View Event
                </a>
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default CountdownCard;
