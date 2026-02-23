import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { HelpCircle, Settings2, Loader2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { TimezoneCombobox } from "@/components/shared/TimezoneCombobox";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { getCalendars, updateCalendar, deleteCalendar } from "@/api/endpoints/calendar";
import type { Calendar, WorkingHoursWindow } from "@/api/types";

const DAYS = [
  { key: "mon", label: "Monday" },
  { key: "tue", label: "Tuesday" },
  { key: "wed", label: "Wednesday" },
  { key: "thu", label: "Thursday" },
  { key: "fri", label: "Friday" },
  { key: "sat", label: "Saturday" },
  { key: "sun", label: "Sunday" },
] as const;

type DayKey = (typeof DAYS)[number]["key"];

interface DayRow {
  enabled: boolean;
  start: string;
  end: string;
}

type WorkingHoursState = Record<DayKey, DayRow>;

function buildDefaultHours(): WorkingHoursState {
  const state = {} as WorkingHoursState;
  for (const d of DAYS) {
    state[d.key] = { enabled: d.key !== "sat" && d.key !== "sun", start: "09:00", end: "17:00" };
  }
  return state;
}

function fromCalendar(cal: Calendar): WorkingHoursState {
  const state = buildDefaultHours();
  const wh = cal.working_hours;
  if (!wh) return state;
  for (const d of DAYS) {
    const windows: WorkingHoursWindow[] | undefined = wh[d.key];
    if (windows && windows.length > 0) {
      const first = windows[0]!;
      state[d.key] = { enabled: true, start: first.start, end: first.end };
    } else {
      state[d.key] = { ...state[d.key], enabled: false };
    }
  }
  return state;
}

function toWorkingHours(state: WorkingHoursState): Record<string, WorkingHoursWindow[]> {
  const result: Record<string, WorkingHoursWindow[]> = {};
  for (const d of DAYS) {
    const row = state[d.key];
    result[d.key] = row.enabled ? [{ start: row.start, end: row.end }] : [];
  }
  return result;
}

export function CalendarSettings() {
  const queryClient = useQueryClient();
  const [selectedCalendarId, setSelectedCalendarId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [timezone, setTimezone] = useState("");
  const [bufferBefore, setBufferBefore] = useState(0);
  const [bufferAfter, setBufferAfter] = useState(0);
  const [hours, setHours] = useState<WorkingHoursState>(buildDefaultHours);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
  });

  const calendars: Calendar[] = Array.isArray(calendarsQuery.data) ? calendarsQuery.data : [];
  const calId = selectedCalendarId ?? (calendars.length > 0 ? calendars[0]!.calendar_id : null);
  const calendar = calendars.find((c) => c.calendar_id === calId) ?? null;

  // Sync form state when calendar changes
  useEffect(() => {
    if (!calendar) return;
    setName(calendar.name);
    setTimezone(calendar.timezone);
    setBufferBefore(calendar.buffer_before_minutes);
    setBufferAfter(calendar.buffer_after_minutes);
    setHours(fromCalendar(calendar));
  }, [calendar]);

  const saveMutation = useMutation({
    mutationFn: () =>
      updateCalendar(calId!, {
        name,
        timezone: timezone || undefined,
        working_hours: toWorkingHours(hours),
        buffer_before_minutes: bufferBefore,
        buffer_after_minutes: bufferAfter,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendars"] });
      toast.success("Calendar settings saved");
    },
    onError: () => {
      toast.error("Failed to save settings");
    },
  });

  const delMutation = useMutation({
    mutationFn: () => deleteCalendar(calId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendars"] });
      setSelectedCalendarId(null);
      setDeleteOpen(false);
      toast.success("Calendar deleted");
    },
    onError: () => {
      toast.error("Failed to delete calendar");
    },
  });

  const updateDayRow = (key: DayKey, patch: Partial<DayRow>) => {
    setHours((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }));
  };

  if (calendarsQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (calendars.length === 0) {
    return (
      <EmptyState
        icon={<Settings2 className="h-6 w-6" />}
        title="No calendars"
        description="Use the Calendars tab to create your first calendar, then return here to configure its settings."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Calendar selector */}
      {calendars.length > 1 && (
        <div className="space-y-1.5">
          <Label>Calendar</Label>
          <Select value={calId ?? ""} onValueChange={setSelectedCalendarId}>
            <SelectTrigger className="w-60">
              <SelectValue placeholder="Select calendar" />
            </SelectTrigger>
            <SelectContent>
              {calendars.map((c) => (
                <SelectItem key={c.calendar_id} value={c.calendar_id}>
                  {c.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {/* General settings */}
      <div className="rounded-lg border p-4 space-y-4">
        <h3 className="text-sm font-medium">General</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="cal-name">Name</Label>
            <Input id="cal-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label>Timezone</Label>
            <TimezoneCombobox value={timezone} onChange={setTimezone} />
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <Label htmlFor="buf-before">Buffer before (min)</Label>
              <Tooltip>
                <TooltipTrigger asChild>
                  <HelpCircle className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                </TooltipTrigger>
                <TooltipContent className="max-w-xs">
                  Blocks out this many minutes <strong>before</strong> each event. Useful for
                  travel or preparation time — no other events can be booked in this window.
                </TooltipContent>
              </Tooltip>
            </div>
            <Input
              id="buf-before"
              type="number"
              min={0}
              value={bufferBefore}
              onChange={(e) => setBufferBefore(Number(e.target.value) || 0)}
            />
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <Label htmlFor="buf-after">Buffer after (min)</Label>
              <Tooltip>
                <TooltipTrigger asChild>
                  <HelpCircle className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                </TooltipTrigger>
                <TooltipContent className="max-w-xs">
                  Blocks out this many minutes <strong>after</strong> each event. Useful for
                  wrap-up, note-taking, or recovery time between meetings.
                </TooltipContent>
              </Tooltip>
            </div>
            <Input
              id="buf-after"
              type="number"
              min={0}
              value={bufferAfter}
              onChange={(e) => setBufferAfter(Number(e.target.value) || 0)}
            />
          </div>
        </div>
      </div>

      {/* Working hours */}
      <div className="rounded-lg border p-4 space-y-3">
        <h3 className="text-sm font-medium">Working hours</h3>
        <div className="space-y-2">
          {DAYS.map((d) => {
            const row = hours[d.key];
            return (
              <div key={d.key} className="flex items-center gap-3">
                <Switch
                  checked={row.enabled}
                  onCheckedChange={(v) => updateDayRow(d.key, { enabled: v })}
                />
                <span className="w-24 text-sm">{d.label}</span>
                <Input
                  type="time"
                  className="w-28"
                  value={row.start}
                  disabled={!row.enabled}
                  onChange={(e) => updateDayRow(d.key, { start: e.target.value })}
                />
                <span className="text-xs text-muted-foreground">to</span>
                <Input
                  type="time"
                  className="w-28"
                  value={row.end}
                  disabled={!row.enabled}
                  onChange={(e) => updateDayRow(d.key, { end: e.target.value })}
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <Button
          variant="destructive"
          size="sm"
          onClick={() => setDeleteOpen(true)}
        >
          <Trash2 className="mr-1 h-3.5 w-3.5" />
          Delete Calendar
        </Button>
        <Button
          size="sm"
          disabled={!name.trim() || saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          {saveMutation.isPending && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
          Save Settings
        </Button>
      </div>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete calendar?"
        description={`This will permanently delete "${calendar?.name ?? "this calendar"}" and all its events.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => delMutation.mutate()}
        loading={delMutation.isPending}
      />
    </div>
  );
}
