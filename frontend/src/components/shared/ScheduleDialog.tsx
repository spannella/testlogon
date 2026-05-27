import { useState, useMemo } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface ScheduleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (scheduledAt: number, notifyBefore?: number) => void;
  initialScheduledAt?: number;
  isSubmitting?: boolean;
  title?: string;
  minMinutesAhead?: number;
}

const NOTIFY_OPTIONS = [
  { label: "5 minutes", value: 300 },
  { label: "15 minutes", value: 900 },
  { label: "30 minutes", value: 1800 },
  { label: "1 hour", value: 3600 },
];

export default function ScheduleDialog({
  open,
  onOpenChange,
  onConfirm,
  initialScheduledAt,
  isSubmitting = false,
  title = "Schedule Content",
  minMinutesAhead = 5,
}: ScheduleDialogProps) {
  const defaultDate = useMemo(() => {
    if (initialScheduledAt) {
      return new Date(initialScheduledAt * 1000);
    }
    const d = new Date();
    d.setMinutes(d.getMinutes() + 30);
    d.setSeconds(0, 0);
    return d;
  }, [initialScheduledAt]);

  const [dateStr, setDateStr] = useState(
    defaultDate.toISOString().slice(0, 10),
  );
  const [timeStr, setTimeStr] = useState(
    defaultDate.toTimeString().slice(0, 5),
  );
  const [notifyEnabled, setNotifyEnabled] = useState(false);
  const [notifyBefore, setNotifyBefore] = useState(900);
  const [error, setError] = useState("");

  const handleConfirm = () => {
    const dt = new Date(`${dateStr}T${timeStr}`);
    const ts = Math.floor(dt.getTime() / 1000);
    const now = Math.floor(Date.now() / 1000);
    if (ts <= now + minMinutesAhead * 60) {
      setError(
        `Must be at least ${minMinutesAhead} minutes in the future`,
      );
      return;
    }
    setError("");
    onConfirm(ts, notifyEnabled ? notifyBefore : undefined);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            Pick a date and time. Times are in your local timezone (
            {Intl.DateTimeFormat().resolvedOptions().timeZone}).
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="sched-date">Date</Label>
            <Input
              id="sched-date"
              type="date"
              value={dateStr}
              onChange={(e) => setDateStr(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="sched-time">Time</Label>
            <Input
              id="sched-time"
              type="time"
              value={timeStr}
              onChange={(e) => setTimeStr(e.target.value)}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="sched-notify"
              checked={notifyEnabled}
              onCheckedChange={(v) => setNotifyEnabled(v === true)}
            />
            <Label htmlFor="sched-notify">Notify me before</Label>
          </div>

          {notifyEnabled && (
            <Select
              value={String(notifyBefore)}
              onValueChange={(v) => setNotifyBefore(Number(v))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {NOTIFY_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={String(opt.value)}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleConfirm} disabled={isSubmitting}>
            {isSubmitting ? "Scheduling..." : "Confirm Schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
