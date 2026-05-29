import { Clock } from "lucide-react";
import { useState, useEffect } from "react";

interface StalenessIndicatorProps {
  /** Timestamp (ms) when the data was cached */
  cachedAt: number | undefined;
  /** Whether to auto-update the age display */
  live?: boolean;
}

/**
 * Shows "Cached X ago" badge when data came from the offline cache.
 * Updates the age display every minute when `live` is true.
 */
export function StalenessIndicator({
  cachedAt,
  live = true,
}: StalenessIndicatorProps) {
  const [, forceUpdate] = useState(0);

  useEffect(() => {
    if (!cachedAt || !live) return;
    const interval = setInterval(() => forceUpdate((n) => n + 1), 60_000);
    return () => clearInterval(interval);
  }, [cachedAt, live]);

  if (!cachedAt) return null;

  const age = Date.now() - cachedAt;
  const minutes = Math.floor(age / 60_000);

  let label: string;
  if (minutes < 1) {
    label = "Just now";
  } else if (minutes < 60) {
    label = `${minutes}m ago`;
  } else {
    const hours = Math.floor(minutes / 60);
    label = hours === 1 ? "1 hour ago" : `${hours}h ago`;
  }

  return (
    <div
      className="flex items-center gap-1 text-xs text-muted-foreground"
      role="status"
      aria-label={`Data cached ${label}`}
    >
      <Clock className="h-3 w-3" aria-hidden />
      <span>Cached {label}</span>
    </div>
  );
}
