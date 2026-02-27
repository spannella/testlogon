import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CalendarCheck, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { getCalendars, getEvents } from "@/api/endpoints/calendar";
import type { SendCalendarEventReq } from "@/api/types";

interface EventPickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (params: SendCalendarEventReq) => void;
}

function formatEventTime(startUtc?: string, allDay?: boolean, allDayDate?: string): string {
  if (allDay && allDayDate) return allDayDate;
  if (!startUtc) return "";
  return new Date(startUtc).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function EventPickerDialog({ open, onClose, onSelect }: EventPickerDialogProps) {
  const [selectedCalendarId, setSelectedCalendarId] = useState<string | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const { data: calendars = [], isLoading: loadingCals } = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
    enabled: open,
  });

  const { data: eventsPage, isLoading: loadingEvents } = useQuery({
    queryKey: ["events", selectedCalendarId],
    queryFn: () => getEvents(selectedCalendarId!),
    enabled: !!selectedCalendarId,
  });

  const events = eventsPage?.events ?? [];

  function handleSelect() {
    if (!selectedCalendarId || !selectedEventId) return;
    onSelect({ calendar_id: selectedCalendarId, event_id: selectedEventId });
    onClose();
  }

  function handleOpenChange(isOpen: boolean) {
    if (!isOpen) onClose();
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Share an event</DialogTitle>
        </DialogHeader>

        <div className="space-y-3 py-2">
          {/* Calendar list */}
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Calendar</p>
            {loadingCals && <p className="text-sm text-muted-foreground">Loading…</p>}
            <div className="max-h-36 overflow-y-auto space-y-1">
              {calendars.map((cal) => (
                <button
                  key={cal.calendar_id}
                  type="button"
                  onClick={() => {
                    setSelectedCalendarId(cal.calendar_id);
                    setSelectedEventId(null);
                  }}
                  className={cn(
                    "w-full flex items-center gap-2 rounded-md px-3 py-2 text-sm text-left transition-colors",
                    selectedCalendarId === cal.calendar_id
                      ? "bg-primary text-primary-foreground"
                      : "hover:bg-muted",
                  )}
                >
                  <CalendarCheck className="h-4 w-4 shrink-0" />
                  <span className="truncate flex-1">{cal.name}</span>
                  <ChevronRight className="h-3 w-3 shrink-0 opacity-50" />
                </button>
              ))}
            </div>
          </div>

          {/* Event list */}
          {selectedCalendarId && (
            <div className="space-y-1">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Event</p>
              {loadingEvents && <p className="text-sm text-muted-foreground">Loading events…</p>}
              {!loadingEvents && events.length === 0 && (
                <p className="text-sm text-muted-foreground">No events found.</p>
              )}
              <div className="max-h-40 overflow-y-auto space-y-1">
                {events.map((evt) => (
                  <button
                    key={evt.event_id}
                    type="button"
                    onClick={() => setSelectedEventId(evt.event_id)}
                    className={cn(
                      "w-full flex flex-col rounded-md px-3 py-2 text-left transition-colors",
                      selectedEventId === evt.event_id
                        ? "bg-primary text-primary-foreground"
                        : "hover:bg-muted",
                    )}
                  >
                    <span className="text-sm font-medium truncate">{evt.name}</span>
                    <span className="text-xs opacity-70">
                      {formatEventTime(evt.start_utc, evt.all_day, evt.all_day_date)}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={!selectedCalendarId || !selectedEventId} onClick={handleSelect}>
            Share event
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
