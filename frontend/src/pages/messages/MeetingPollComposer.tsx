import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { X, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { SlotSuggestions } from "@/pages/calendar/SlotSuggestions";
import { getCalendars } from "@/api/endpoints/calendar";
import type { SendMeetingPollReq } from "@/api/types";

interface MeetingPollComposerProps {
  open: boolean;
  onClose: () => void;
  onSend: (params: SendMeetingPollReq) => void;
}

interface PollSlot {
  id: string;
  start_utc: string;
  end_utc: string;
}

const DURATIONS = [15, 30, 45, 60, 90, 120];

function formatSlotLabel(start: string, end: string): string {
  const s = new Date(start);
  const e = new Date(end);
  const date = s.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  const startTime = s.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  const endTime = e.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  return `${date}, ${startTime} – ${endTime}`;
}

export function MeetingPollComposer({ open, onClose, onSend }: MeetingPollComposerProps) {
  const [title, setTitle] = useState("");
  const [durationMinutes, setDurationMinutes] = useState(30);
  const [slots, setSlots] = useState<PollSlot[]>([]);
  const [manualStart, setManualStart] = useState("");
  const [showManual, setShowManual] = useState(false);

  const { data: calendars = [] } = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
    enabled: open,
  });

  const defaultCalendarId = calendars[0]?.calendar_id ?? null;

  function addSlot(start: string, end: string) {
    if (slots.length >= 5) return;
    setSlots((prev) => [...prev, { id: Date.now().toString(), start_utc: start, end_utc: end }]);
  }

  function removeSlot(id: string) {
    setSlots((prev) => prev.filter((s) => s.id !== id));
  }

  function handleAddManual() {
    if (!manualStart) return;
    const start = new Date(manualStart);
    if (isNaN(start.getTime())) return;
    const end = new Date(start.getTime() + durationMinutes * 60 * 1000);
    addSlot(start.toISOString(), end.toISOString());
    setManualStart("");
    setShowManual(false);
  }

  function handleSend() {
    if (!title.trim() || slots.length < 2) return;
    onSend({
      title: title.trim(),
      duration_minutes: durationMinutes,
      slots: slots.map(({ start_utc, end_utc }) => ({ start_utc, end_utc })),
    });
    onClose();
    // Reset
    setTitle("");
    setDurationMinutes(30);
    setSlots([]);
    setShowManual(false);
    setManualStart("");
  }

  function handleOpenChange(isOpen: boolean) {
    if (!isOpen) onClose();
  }

  const canSend = title.trim().length > 0 && slots.length >= 2;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Schedule a meeting</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Title */}
          <div className="space-y-1">
            <Label htmlFor="poll-title">Meeting title</Label>
            <Input
              id="poll-title"
              placeholder="e.g. Project sync"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>

          {/* Duration */}
          <div className="space-y-1">
            <Label>Duration</Label>
            <div className="flex flex-wrap gap-2">
              {DURATIONS.map((d) => (
                <Button
                  key={d}
                  type="button"
                  variant={durationMinutes === d ? "default" : "outline"}
                  size="sm"
                  onClick={() => setDurationMinutes(d)}
                >
                  {d < 60 ? `${d} min` : `${d / 60}h`}
                </Button>
              ))}
            </div>
          </div>

          {/* Slot suggestions */}
          {defaultCalendarId && (
            <div className="space-y-1">
              <Label>Find free times</Label>
              <SlotSuggestions
                calendarId={defaultCalendarId}
                onSelectSlot={(start, end) => addSlot(start, end)}
              />
            </div>
          )}

          {/* Slot list */}
          {slots.length > 0 && (
            <div className="space-y-1">
              <Label>Selected times ({slots.length}/5)</Label>
              <div className="space-y-1 max-h-36 overflow-y-auto">
                {slots.map((slot) => (
                  <div
                    key={slot.id}
                    className="flex items-center justify-between rounded-md border px-3 py-1.5 text-sm"
                  >
                    <span className="truncate">{formatSlotLabel(slot.start_utc, slot.end_utc)}</span>
                    <button
                      type="button"
                      onClick={() => removeSlot(slot.id)}
                      className="ml-2 shrink-0 text-muted-foreground hover:text-destructive"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Manual add */}
          {slots.length < 5 && (
            <div className="space-y-1">
              {showManual ? (
                <div className="flex gap-2 items-end">
                  <div className="flex-1 space-y-1">
                    <Label htmlFor="manual-start">Date &amp; time</Label>
                    <Input
                      id="manual-start"
                      type="datetime-local"
                      value={manualStart}
                      onChange={(e) => setManualStart(e.target.value)}
                    />
                  </div>
                  <Button size="sm" onClick={handleAddManual} disabled={!manualStart}>
                    Add
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setShowManual(false)}>
                    Cancel
                  </Button>
                </div>
              ) : (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setShowManual(true)}
                >
                  <Plus className="h-3.5 w-3.5 mr-1" /> Add time manually
                </Button>
              )}
            </div>
          )}

          {slots.length < 2 && (
            <p className="text-xs text-muted-foreground">Select at least 2 time slots to continue.</p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={!canSend} onClick={handleSend}>Send Poll</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
