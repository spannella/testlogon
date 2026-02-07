import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronLeft,
  ChevronRight,
  Plus,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { getCalendars, getEvents } from "@/api/endpoints/calendar";
import { EventDialog } from "./EventDialog";
import type { CalendarEvent, Calendar } from "@/api/types";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function formatHour(h: number): string {
  if (h === 0) return "12 AM";
  if (h < 12) return `${h} AM`;
  if (h === 12) return "12 PM";
  return `${h - 12} PM`;
}

function isSameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function getMonthDays(year: number, month: number): Date[] {
  const first = new Date(year, month, 1);
  const startDay = first.getDay();
  const days: Date[] = [];
  // Fill in days from previous month
  for (let i = startDay - 1; i >= 0; i--) {
    days.push(new Date(year, month, -i));
  }
  // Fill in current month days
  const last = new Date(year, month + 1, 0);
  for (let d = 1; d <= last.getDate(); d++) {
    days.push(new Date(year, month, d));
  }
  // Fill remaining to complete rows of 7
  while (days.length % 7 !== 0) {
    days.push(new Date(year, month + 1, days.length - last.getDate() - startDay + 1));
  }
  return days;
}

function getWeekDays(date: Date): Date[] {
  const day = date.getDay();
  const start = new Date(date);
  start.setDate(start.getDate() - day);
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    return d;
  });
}

function eventOnDay(ev: CalendarEvent, day: Date): boolean {
  if (ev.all_day && ev.all_day_date) {
    return ev.all_day_date === day.toISOString().slice(0, 10);
  }
  if (ev.start_utc) {
    return isSameDay(new Date(ev.start_utc), day);
  }
  return false;
}

function eventHour(ev: CalendarEvent): number {
  if (ev.start_utc) return new Date(ev.start_utc).getHours();
  return 0;
}

export function CalendarView() {
  const [view, setView] = useState("month");
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedCalendarId, setSelectedCalendarId] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingEvent, setEditingEvent] = useState<CalendarEvent | null>(null);
  const [defaultDate, setDefaultDate] = useState<string>("");

  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
  });

  const calendars: Calendar[] = Array.isArray(calendarsQuery.data) ? calendarsQuery.data : [];
  const calId = selectedCalendarId ?? (calendars.length > 0 ? calendars[0]!.calendar_id : null);

  const eventsQuery = useQuery({
    queryKey: ["calendar-events", calId],
    queryFn: () => getEvents(calId!),
    enabled: !!calId,
  });

  const events: CalendarEvent[] = eventsQuery.data?.events ?? [];

  const today = new Date();
  const year = currentDate.getFullYear();
  const month = currentDate.getMonth();

  const monthDays = useMemo(() => getMonthDays(year, month), [year, month]);
  const weekDays = useMemo(() => getWeekDays(currentDate), [currentDate]);

  const navigate = (dir: number) => {
    const d = new Date(currentDate);
    if (view === "month") d.setMonth(d.getMonth() + dir);
    else if (view === "week") d.setDate(d.getDate() + dir * 7);
    else d.setDate(d.getDate() + dir);
    setCurrentDate(d);
  };

  const goToday = () => setCurrentDate(new Date());

  const openNewEvent = (date?: Date) => {
    setEditingEvent(null);
    setDefaultDate(date ? date.toISOString().slice(0, 10) : "");
    setDialogOpen(true);
  };

  const openEditEvent = (ev: CalendarEvent) => {
    setEditingEvent(ev);
    setDefaultDate("");
    setDialogOpen(true);
  };

  const title =
    view === "month"
      ? currentDate.toLocaleDateString(undefined, { month: "long", year: "numeric" })
      : view === "week"
        ? `Week of ${weekDays[0]!.toLocaleDateString(undefined, { month: "short", day: "numeric" })}`
        : currentDate.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" });

  if (calendarsQuery.isLoading) {
    return <Skeleton className="h-96 w-full rounded-xl" />;
  }

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon" onClick={() => navigate(-1)}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button variant="outline" size="sm" onClick={goToday}>
            Today
          </Button>
          <Button variant="outline" size="icon" onClick={() => navigate(1)}>
            <ChevronRight className="h-4 w-4" />
          </Button>
          <h2 className="ml-2 text-lg font-semibold">{title}</h2>
        </div>
        <div className="flex items-center gap-2">
          {calendars.length > 1 && (
            <Select value={calId ?? ""} onValueChange={setSelectedCalendarId}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Calendar" />
              </SelectTrigger>
              <SelectContent>
                {calendars.map((c) => (
                  <SelectItem key={c.calendar_id} value={c.calendar_id}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <Button size="sm" onClick={() => openNewEvent()}>
            <Plus className="mr-1 h-3.5 w-3.5" />
            New Event
          </Button>
        </div>
      </div>

      {/* View tabs */}
      <Tabs value={view} onValueChange={setView}>
        <TabsList>
          <TabsTrigger value="month">Month</TabsTrigger>
          <TabsTrigger value="week">Week</TabsTrigger>
          <TabsTrigger value="day">Day</TabsTrigger>
        </TabsList>

        {/* ─── Month View ──────────────────────────────────── */}
        <TabsContent value="month">
          <div className="rounded-lg border">
            {/* Header */}
            <div className="grid grid-cols-7 border-b">
              {DAYS.map((d) => (
                <div key={d} className="px-2 py-1.5 text-center text-xs font-medium text-muted-foreground">
                  {d}
                </div>
              ))}
            </div>
            {/* Day cells */}
            <div className="grid grid-cols-7">
              {monthDays.map((day, i) => {
                const isCurrentMonth = day.getMonth() === month;
                const isToday = isSameDay(day, today);
                const dayEvents = events.filter((ev) => eventOnDay(ev, day));
                return (
                  <div
                    key={i}
                    className={cn(
                      "min-h-20 border-b border-r p-1 transition-colors hover:bg-accent/50 cursor-pointer",
                      !isCurrentMonth && "bg-muted/30 text-muted-foreground",
                    )}
                    onClick={() => openNewEvent(day)}
                  >
                    <span
                      className={cn(
                        "inline-flex h-6 w-6 items-center justify-center rounded-full text-xs",
                        isToday && "bg-primary text-primary-foreground font-bold",
                      )}
                    >
                      {day.getDate()}
                    </span>
                    <div className="mt-0.5 space-y-0.5">
                      {dayEvents.slice(0, 3).map((ev) => (
                        <button
                          key={ev.event_id}
                          className="block w-full truncate rounded bg-primary/10 px-1 py-0.5 text-left text-[10px] font-medium text-primary hover:bg-primary/20"
                          onClick={(e) => {
                            e.stopPropagation();
                            openEditEvent(ev);
                          }}
                        >
                          {ev.name}
                        </button>
                      ))}
                      {dayEvents.length > 3 && (
                        <span className="text-[10px] text-muted-foreground">
                          +{dayEvents.length - 3} more
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </TabsContent>

        {/* ─── Week View ───────────────────────────────────── */}
        <TabsContent value="week">
          <div className="overflow-x-auto rounded-lg border">
            <div className="min-w-[700px]">
              {/* Header */}
              <div className="grid grid-cols-[60px_repeat(7,1fr)] border-b">
                <div />
                {weekDays.map((day, i) => (
                  <div
                    key={i}
                    className={cn(
                      "border-l px-2 py-1.5 text-center text-xs",
                      isSameDay(day, today) && "bg-primary/5 font-bold",
                    )}
                  >
                    <span className="text-muted-foreground">{DAYS[day.getDay()]}</span>{" "}
                    <span>{day.getDate()}</span>
                  </div>
                ))}
              </div>
              {/* Time grid */}
              <div className="max-h-[600px] overflow-y-auto">
                {HOURS.map((h) => (
                  <div key={h} className="grid grid-cols-[60px_repeat(7,1fr)] border-b">
                    <div className="px-2 py-1 text-right text-[10px] text-muted-foreground">
                      {formatHour(h)}
                    </div>
                    {weekDays.map((day, di) => {
                      const cellEvents = events.filter(
                        (ev) => eventOnDay(ev, day) && eventHour(ev) === h,
                      );
                      return (
                        <div
                          key={di}
                          className="min-h-10 border-l p-0.5 hover:bg-accent/30 cursor-pointer"
                          onClick={() => openNewEvent(day)}
                        >
                          {cellEvents.map((ev) => (
                            <button
                              key={ev.event_id}
                              className="block w-full truncate rounded bg-primary/15 px-1 py-0.5 text-left text-[10px] font-medium text-primary"
                              onClick={(e) => {
                                e.stopPropagation();
                                openEditEvent(ev);
                              }}
                            >
                              {ev.name}
                            </button>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </TabsContent>

        {/* ─── Day View ────────────────────────────────────── */}
        <TabsContent value="day">
          <div className="rounded-lg border">
            <div className="max-h-[600px] overflow-y-auto">
              {HOURS.map((h) => {
                const hourEvents = events.filter(
                  (ev) => eventOnDay(ev, currentDate) && eventHour(ev) === h,
                );
                return (
                  <div
                    key={h}
                    className="flex min-h-12 border-b hover:bg-accent/30 cursor-pointer"
                    onClick={() => openNewEvent(currentDate)}
                  >
                    <div className="w-16 shrink-0 px-2 py-1 text-right text-xs text-muted-foreground">
                      {formatHour(h)}
                    </div>
                    <div className="flex-1 border-l p-1 space-y-0.5">
                      {hourEvents.map((ev) => (
                        <button
                          key={ev.event_id}
                          className="block w-full rounded bg-primary/15 px-2 py-1 text-left text-sm font-medium text-primary hover:bg-primary/20"
                          onClick={(e) => {
                            e.stopPropagation();
                            openEditEvent(ev);
                          }}
                        >
                          {ev.name}
                          {ev.description && (
                            <span className="ml-2 text-xs font-normal text-muted-foreground">
                              {ev.description}
                            </span>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* Event dialog */}
      <EventDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        calendars={calendars}
        selectedCalendarId={calId ?? ""}
        event={editingEvent}
        defaultDate={defaultDate}
      />
    </div>
  );
}
