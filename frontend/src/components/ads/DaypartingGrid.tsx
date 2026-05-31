import { useCallback, useRef, useState } from "react";

const DAYS = [
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
] as const;

const HOURS = Array.from({ length: 24 }, (_, h) => h);

const PRESETS: Record<string, Record<string, number[]>> = {
  always: Object.fromEntries(DAYS.map((d) => [d, [...HOURS]])),
  weekdays_business: Object.fromEntries(
    DAYS.map((d, i) =>
      i < 5 ? [d, Array.from({ length: 9 }, (_, k) => k + 9)] : [d, []],
    ),
  ),
  evenings: Object.fromEntries(
    DAYS.map((d) => [d, Array.from({ length: 6 }, (_, k) => k + 18)]),
  ),
  weekends: Object.fromEntries(
    DAYS.map((d, i) => (i >= 5 ? [d, [...HOURS]] : [d, []])),
  ),
};

export interface DaypartingGridProps {
  schedule: Record<string, number[]>;
  onChange: (schedule: Record<string, number[]>) => void;
}

export default function DaypartingGrid({
  schedule,
  onChange,
}: DaypartingGridProps) {
  const dragging = useRef<{ active: boolean; setTo: boolean }>({
    active: false,
    setTo: true,
  });
  const [, force] = useState(0);

  const isActive = useCallback(
    (day: string, hour: number) => (schedule[day] ?? []).includes(hour),
    [schedule],
  );

  const setCell = useCallback(
    (day: string, hour: number, on: boolean) => {
      const hours = new Set(schedule[day] ?? []);
      if (on) hours.add(hour);
      else hours.delete(hour);
      onChange({ ...schedule, [day]: Array.from(hours).sort((a, b) => a - b) });
    },
    [schedule, onChange],
  );

  const toggleCell = (day: string, hour: number) => {
    const next = !isActive(day, hour);
    dragging.current = { active: true, setTo: next };
    setCell(day, hour, next);
  };

  const onEnter = (day: string, hour: number) => {
    if (dragging.current.active) setCell(day, hour, dragging.current.setTo);
  };

  const endDrag = () => {
    dragging.current.active = false;
    force((n) => n + 1);
  };

  const setDay = (day: string, on: boolean) =>
    onChange({ ...schedule, [day]: on ? [...HOURS] : [] });

  const applyPreset = (name: string) => onChange({ ...PRESETS[name] });

  const totalActive = DAYS.reduce(
    (sum, d) => sum + (schedule[d]?.length ?? 0),
    0,
  );
  const pct = Math.round((totalActive / (24 * 7)) * 100);

  return (
    <div className="space-y-3" onMouseUp={endDrag} onMouseLeave={endDrag}>
      <div className="flex flex-wrap gap-2">
        {Object.keys(PRESETS).map((name) => (
          <button
            key={name}
            type="button"
            data-testid={`preset-${name}`}
            onClick={() => applyPreset(name)}
            className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
          >
            {name.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto">
        <table className="border-collapse select-none text-[10px]">
          <thead>
            <tr>
              <th className="p-1" />
              {HOURS.map((h) => (
                <th key={h} className="w-5 p-0 text-center font-normal text-muted-foreground">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {DAYS.map((day) => {
              const dayActive = (schedule[day]?.length ?? 0) === 24;
              return (
                <tr key={day}>
                  <td className="whitespace-nowrap p-1 pr-2 text-right">
                    <button
                      type="button"
                      data-testid={`day-toggle-${day}`}
                      onClick={() => setDay(day, !dayActive)}
                      className="text-xs capitalize hover:underline"
                    >
                      {day.slice(0, 3)}
                    </button>
                  </td>
                  {HOURS.map((hour) => {
                    const on = isActive(day, hour);
                    return (
                      <td key={hour} className="p-0">
                        <button
                          type="button"
                          data-testid={`cell-${day}-${hour}`}
                          aria-pressed={on}
                          onMouseDown={() => toggleCell(day, hour)}
                          onMouseEnter={() => onEnter(day, hour)}
                          className={`h-5 w-5 border border-border ${
                            on ? "bg-primary" : "bg-muted/40"
                          }`}
                        />
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground" data-testid="dayparting-summary">
        Active {totalActive} hours/week ({pct}% of total)
      </p>
    </div>
  );
}
