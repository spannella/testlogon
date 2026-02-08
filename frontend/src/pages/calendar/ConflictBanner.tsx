import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Loader2 } from "lucide-react";
import { previewConflicts } from "@/api/endpoints/calendar";
import type { CalendarEvent, ConflictPreviewReq } from "@/api/types";

interface ConflictBannerProps {
  calendarId: string;
  /** Full event body to check for conflicts */
  request: ConflictPreviewReq | null;
}

function formatTime(utc: string): string {
  return new Date(utc).toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatDateShort(utc: string): string {
  return new Date(utc).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

export function ConflictBanner({ calendarId, request }: ConflictBannerProps) {
  const hasTimeRange = !!(request?.start_utc && request?.end_utc);

  const conflictsQuery = useQuery({
    queryKey: ["calendar-conflicts", calendarId, request],
    queryFn: () => previewConflicts(calendarId, request!),
    enabled: !!calendarId && !!request && hasTimeRange,
    staleTime: 10_000,
  });

  const conflicts: CalendarEvent[] = conflictsQuery.data?.conflicts ?? [];

  if (!hasTimeRange) return null;

  if (conflictsQuery.isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-muted bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        Checking for conflicts...
      </div>
    );
  }

  if (conflicts.length === 0) return null;

  return (
    <div className="rounded-md border border-yellow-300 bg-yellow-50 px-3 py-2 dark:border-yellow-700 dark:bg-yellow-950/30">
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-600 dark:text-yellow-400" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
            {conflicts.length} conflict{conflicts.length !== 1 ? "s" : ""} detected
          </p>
          <ul className="space-y-0.5">
            {conflicts.slice(0, 5).map((ev) => (
              <li key={ev.event_id} className="text-xs text-yellow-700 dark:text-yellow-300">
                <span className="font-medium">{ev.name}</span>
                {ev.start_utc && ev.end_utc && (
                  <span className="ml-1 text-yellow-600 dark:text-yellow-400">
                    ({formatDateShort(ev.start_utc)} {formatTime(ev.start_utc)}&ndash;{formatTime(ev.end_utc)})
                  </span>
                )}
              </li>
            ))}
            {conflicts.length > 5 && (
              <li className="text-xs text-yellow-600 dark:text-yellow-400">
                +{conflicts.length - 5} more
              </li>
            )}
          </ul>
        </div>
      </div>
    </div>
  );
}
