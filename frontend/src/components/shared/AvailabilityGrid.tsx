import { useCallback, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";

/**
 * AvailabilityGrid (MSG-009)
 *
 * A continuous time grid where a user paints their available ranges. Columns are
 * days in the date range; rows are time slots at the configured granularity.
 * Click/drag to toggle slots. In read-only mode with a `heatMap`, cells are
 * colored by participant count (green gradient) for results visualization.
 *
 * Designed to be self-contained / reusable (FEED-003 imports this directly).
 */

export interface AvailabilityGridProps {
  fromDate: string; // ISO YYYY-MM-DD (inclusive)
  toDate: string; // ISO YYYY-MM-DD (inclusive)
  startHour: number; // 0-23
  endHour: number; // 1-24
  slotDurationMinutes: number; // 15 | 30 | 60
  selectedSlots: string[];
  onSlotsChange?: (slots: string[]) => void;
  readOnly?: boolean;
  /** slot key -> participant count (for results / heat map mode) */
  heatMap?: Record<string, number>;
  maxParticipants?: number;
}

const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function pad2(n: number): string {
  return n.toString().padStart(2, "0");
}

/** Enumerate every (date -> [minuteOfDay]) for the grid. */
export function buildGridAxes(
  fromDate: string,
  toDate: string,
  startHour: number,
  endHour: number,
  slotDurationMinutes: number,
): { days: string[]; minutes: number[] } {
  const days: string[] = [];
  const start = new Date(`${fromDate}T00:00:00Z`);
  const end = new Date(`${toDate}T00:00:00Z`);
  for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
    const y = d.getUTCFullYear();
    const m = pad2(d.getUTCMonth() + 1);
    const day = pad2(d.getUTCDate());
    days.push(`${y}-${m}-${day}`);
  }
  const minutes: number[] = [];
  for (let mn = startHour * 60; mn < endHour * 60; mn += slotDurationMinutes) {
    minutes.push(mn);
  }
  return { days, minutes };
}

export function slotKeyFor(dateIso: string, minuteOfDay: number): string {
  const h = Math.floor(minuteOfDay / 60);
  const m = minuteOfDay % 60;
  return `${dateIso}T${pad2(h)}:${pad2(m)}`;
}

function dayHeader(dateIso: string): { label: string; sub: string } {
  const d = new Date(`${dateIso}T00:00:00Z`);
  return {
    label: DAY_LABELS[d.getUTCDay()],
    sub: `${d.getUTCMonth() + 1}/${d.getUTCDate()}`,
  };
}

function minuteLabel(minuteOfDay: number): string {
  const h = Math.floor(minuteOfDay / 60);
  const m = minuteOfDay % 60;
  return `${pad2(h)}:${pad2(m)}`;
}

export function AvailabilityGrid({
  fromDate,
  toDate,
  startHour,
  endHour,
  slotDurationMinutes,
  selectedSlots,
  onSlotsChange,
  readOnly = false,
  heatMap,
  maxParticipants,
}: AvailabilityGridProps) {
  const { days, minutes } = useMemo(
    () => buildGridAxes(fromDate, toDate, startHour, endHour, slotDurationMinutes),
    [fromDate, toDate, startHour, endHour, slotDurationMinutes],
  );

  const selectedSet = useMemo(() => new Set(selectedSlots), [selectedSlots]);
  const [dragging, setDragging] = useState(false);
  const dragModeRef = useRef<"select" | "deselect">("select");
  const workingRef = useRef<Set<string>>(new Set(selectedSlots));

  const commit = useCallback(
    (next: Set<string>) => {
      workingRef.current = next;
      onSlotsChange?.(Array.from(next).sort());
    },
    [onSlotsChange],
  );

  const applyToggle = useCallback(
    (key: string) => {
      const next = new Set(workingRef.current);
      if (dragModeRef.current === "select") next.add(key);
      else next.delete(key);
      commit(next);
    },
    [commit],
  );

  const onCellDown = useCallback(
    (key: string) => {
      if (readOnly) return;
      workingRef.current = new Set(selectedSet);
      dragModeRef.current = selectedSet.has(key) ? "deselect" : "select";
      setDragging(true);
      applyToggle(key);
    },
    [readOnly, selectedSet, applyToggle],
  );

  const onCellEnter = useCallback(
    (key: string) => {
      if (readOnly || !dragging) return;
      applyToggle(key);
    },
    [readOnly, dragging, applyToggle],
  );

  const endDrag = useCallback(() => setDragging(false), []);

  const maxCount = useMemo(() => {
    if (maxParticipants && maxParticipants > 0) return maxParticipants;
    if (!heatMap) return 1;
    return Math.max(1, ...Object.values(heatMap));
  }, [heatMap, maxParticipants]);

  function heatStyle(count: number): React.CSSProperties {
    if (count <= 0) return {};
    const intensity = Math.min(1, count / maxCount);
    // green gradient: light -> dark
    const alpha = 0.15 + intensity * 0.75;
    return { backgroundColor: `rgba(34, 197, 94, ${alpha})` };
  }

  return (
    <div
      className="overflow-x-auto select-none"
      onMouseUp={endDrag}
      onMouseLeave={endDrag}
      data-testid="availability-grid"
    >
      <div className="inline-block min-w-full">
        <div
          className="grid"
          style={{ gridTemplateColumns: `4rem repeat(${days.length}, minmax(3rem, 1fr))` }}
        >
          {/* Header row */}
          <div className="sticky left-0 z-10 bg-background" />
          {days.map((d) => {
            const h = dayHeader(d);
            return (
              <div key={`h-${d}`} className="px-1 py-1 text-center text-xs font-medium">
                <div>{h.label}</div>
                <div className="text-muted-foreground">{h.sub}</div>
              </div>
            );
          })}

          {/* Body rows */}
          {minutes.map((mn) => (
            <FragmentRow
              key={`r-${mn}`}
              minuteOfDay={mn}
              days={days}
              readOnly={readOnly}
              heatMap={heatMap}
              selectedSet={selectedSet}
              onCellDown={onCellDown}
              onCellEnter={onCellEnter}
              heatStyle={heatStyle}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function FragmentRow({
  minuteOfDay,
  days,
  readOnly,
  heatMap,
  selectedSet,
  onCellDown,
  onCellEnter,
  heatStyle,
}: {
  minuteOfDay: number;
  days: string[];
  readOnly: boolean;
  heatMap?: Record<string, number>;
  selectedSet: Set<string>;
  onCellDown: (key: string) => void;
  onCellEnter: (key: string) => void;
  heatStyle: (count: number) => React.CSSProperties;
}) {
  return (
    <>
      <div className="sticky left-0 z-10 bg-background pr-2 text-right text-[10px] text-muted-foreground leading-6">
        {minuteLabel(minuteOfDay)}
      </div>
      {days.map((d) => {
        const key = slotKeyFor(d, minuteOfDay);
        const selected = selectedSet.has(key);
        const count = heatMap ? heatMap[key] ?? 0 : 0;
        return (
          <button
            key={key}
            type="button"
            data-slot={key}
            disabled={readOnly}
            aria-pressed={selected}
            onMouseDown={() => onCellDown(key)}
            onMouseEnter={() => onCellEnter(key)}
            style={heatMap ? heatStyle(count) : undefined}
            className={cn(
              "h-6 border border-border/40 transition-colors",
              !readOnly && "cursor-pointer hover:bg-primary/20",
              selected && !heatMap && "bg-primary",
              readOnly && "cursor-default",
            )}
            title={heatMap ? `${minuteLabel(minuteOfDay)} · ${count} available` : minuteLabel(minuteOfDay)}
          />
        );
      })}
    </>
  );
}

export default AvailabilityGrid;
