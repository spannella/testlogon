import { useMemo } from "react";
import { Badge } from "@/components/ui/badge";
import { AvailabilityGrid } from "@/components/shared/AvailabilityGrid";
import type { FindDateTimeFull } from "@/api/types";

interface FindDateTimeResultProps {
  data: FindDateTimeFull;
}

function fmtWindow(start: string, end: string): string {
  const s = new Date(start);
  const e = new Date(end);
  const date = s.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  const st = s.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const et = e.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return `${date} ${st}–${et}`;
}

export function FindDateTimeResult({ data }: FindDateTimeResultProps) {
  const { meta, availabilities, result } = data;

  const heatMap = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const av of availabilities) {
      for (const slot of av.slots) {
        counts[slot] = (counts[slot] ?? 0) + 1;
      }
    }
    return counts;
  }, [availabilities]);

  const windows = result?.best_windows ?? [];

  return (
    <div className="space-y-3" data-testid="fadt-result">
      <div className="space-y-1">
        <p className="text-xs font-semibold text-muted-foreground">Best windows</p>
        {windows.length === 0 ? (
          <p className="text-xs text-muted-foreground">No overlapping availability found.</p>
        ) : (
          <ol className="space-y-1">
            {windows.slice(0, 3).map((w, i) => (
              <li
                key={`${w.start}-${i}`}
                className="flex items-center justify-between rounded-md border px-2 py-1 text-xs"
                data-testid="fadt-best-window"
              >
                <span className="font-medium">
                  #{i + 1} {fmtWindow(w.start, w.end)}
                </span>
                <Badge variant="secondary">
                  {w.count} {w.count === 1 ? "person" : "people"}
                </Badge>
              </li>
            ))}
          </ol>
        )}
      </div>

      <div>
        <p className="mb-1 text-xs font-semibold text-muted-foreground">Heat map</p>
        <AvailabilityGrid
          fromDate={meta.from_date}
          toDate={meta.to_date}
          startHour={meta.start_hour}
          endHour={meta.end_hour}
          slotDurationMinutes={meta.slot_duration_minutes}
          selectedSlots={[]}
          readOnly
          heatMap={heatMap}
          maxParticipants={meta.participant_count}
        />
      </div>
    </div>
  );
}

export default FindDateTimeResult;
