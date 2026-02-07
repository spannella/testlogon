import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Clock, Loader2, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { suggestSlots } from "@/api/endpoints/calendar";
import type { Opening } from "@/api/types";

interface SlotSuggestionsProps {
  calendarId: string;
  /** Called when user picks a suggested slot */
  onSelectSlot: (start: string, end: string) => void;
}

function formatSlot(slot: Opening): string {
  const start = new Date(slot.start_utc);
  const end = new Date(slot.end_utc);

  const dateStr = start.toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  });

  const startTime = start.toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });

  const endTime = end.toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });

  return `${dateStr}, ${startTime} \u2013 ${endTime}`;
}

export function SlotSuggestions({ calendarId, onSelectSlot }: SlotSuggestionsProps) {
  const [duration, setDuration] = useState(30);
  const [windowDays, setWindowDays] = useState(7);
  const [slots, setSlots] = useState<Opening[]>([]);
  const [searched, setSearched] = useState(false);

  const mutation = useMutation({
    mutationFn: () => {
      const now = new Date();
      const end = new Date(now);
      end.setDate(end.getDate() + windowDays);

      return suggestSlots(calendarId, {
        start_utc: now.toISOString(),
        end_utc: end.toISOString(),
        duration_minutes: duration,
        limit: 8,
        window_days: windowDays,
      });
    },
    onSuccess: (data) => {
      setSlots(Array.isArray(data) ? data : []);
      setSearched(true);
    },
  });

  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-primary" />
        <h4 className="text-sm font-medium">Find available time</h4>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <Label className="text-xs">Duration (min)</Label>
          <Input
            type="number"
            min={15}
            step={15}
            className="w-24"
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value) || 30)}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Look ahead (days)</Label>
          <Input
            type="number"
            min={1}
            max={30}
            className="w-24"
            value={windowDays}
            onChange={(e) => setWindowDays(Number(e.target.value) || 7)}
          />
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending || !calendarId}
        >
          {mutation.isPending ? (
            <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
          ) : (
            <Clock className="mr-1 h-3.5 w-3.5" />
          )}
          Suggest
        </Button>
      </div>

      {searched && slots.length === 0 && (
        <p className="text-xs text-muted-foreground">No available slots found in the window.</p>
      )}

      {slots.length > 0 && (
        <div className="grid gap-1.5 sm:grid-cols-2">
          {slots.map((slot, i) => (
            <button
              key={i}
              className="rounded-md border px-3 py-2 text-left text-xs transition-colors hover:bg-accent"
              onClick={() => onSelectSlot(slot.start_utc, slot.end_utc)}
            >
              {formatSlot(slot)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
