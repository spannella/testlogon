import { useState } from "react";
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
import type { SendFindDateTimeReq } from "@/api/types";

interface FindDateTimeComposerProps {
  open: boolean;
  onClose: () => void;
  onSend: (params: SendFindDateTimeReq) => void;
}

const SLOT_DURATIONS = [15, 30, 60] as const;
const DEADLINE_OPTIONS = [
  { label: "12 hours", value: 12 },
  { label: "24 hours", value: 24 },
  { label: "48 hours", value: 48 },
  { label: "72 hours", value: 72 },
  { label: "7 days", value: 168 },
];

function todayIso(offsetDays = 0): string {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

export function FindDateTimeComposer({ open, onClose, onSend }: FindDateTimeComposerProps) {
  const [title, setTitle] = useState("");
  const [fromDate, setFromDate] = useState(todayIso(1));
  const [toDate, setToDate] = useState(todayIso(3));
  const [startHour, setStartHour] = useState(9);
  const [endHour, setEndHour] = useState(17);
  const [slotDuration, setSlotDuration] = useState<number>(30);
  const [deadlineHours, setDeadlineHours] = useState(48);

  function reset() {
    setTitle("");
    setFromDate(todayIso(1));
    setToDate(todayIso(3));
    setStartHour(9);
    setEndHour(17);
    setSlotDuration(30);
    setDeadlineHours(48);
  }

  const valid =
    title.trim().length > 0 && fromDate < toDate && startHour < endHour;

  function handleSend() {
    if (!valid) return;
    onSend({
      title: title.trim(),
      from_date: fromDate,
      to_date: toDate,
      start_hour: startHour,
      end_hour: endHour,
      slot_duration_minutes: slotDuration,
      deadline_hours: deadlineHours,
    });
    onClose();
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Find a Time</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1">
            <Label htmlFor="fadt-title">Title</Label>
            <Input
              id="fadt-title"
              placeholder="e.g. Team standup this week"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="fadt-from">From date</Label>
              <Input
                id="fadt-from"
                type="date"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="fadt-to">To date</Label>
              <Input
                id="fadt-to"
                type="date"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="fadt-start">Start hour</Label>
              <Input
                id="fadt-start"
                type="number"
                min={0}
                max={23}
                value={startHour}
                onChange={(e) => setStartHour(Number(e.target.value))}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="fadt-end">End hour</Label>
              <Input
                id="fadt-end"
                type="number"
                min={1}
                max={24}
                value={endHour}
                onChange={(e) => setEndHour(Number(e.target.value))}
              />
            </div>
          </div>

          <div className="space-y-1">
            <Label>Slot duration</Label>
            <div className="flex gap-2">
              {SLOT_DURATIONS.map((d) => (
                <Button
                  key={d}
                  type="button"
                  variant={slotDuration === d ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSlotDuration(d)}
                >
                  {d} min
                </Button>
              ))}
            </div>
          </div>

          <div className="space-y-1">
            <Label htmlFor="fadt-deadline">Deadline</Label>
            <select
              id="fadt-deadline"
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
              value={deadlineHours}
              onChange={(e) => setDeadlineHours(Number(e.target.value))}
            >
              {DEADLINE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          {!valid && (
            <p className="text-xs text-muted-foreground">
              Enter a title, ensure from-date is before to-date, and start hour is before end hour.
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={!valid} onClick={handleSend}>
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default FindDateTimeComposer;
