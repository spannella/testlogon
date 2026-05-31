import { useEffect, useState } from "react";
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

interface BroadcastScheduleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Existing scheduled_at (Unix seconds) when rescheduling; undefined when scheduling fresh. */
  initialScheduledAt?: number | null;
  /** When true, only the date/time is editable (reschedule mode). */
  rescheduleOnly?: boolean;
  sessionName?: string;
  onConfirm: (args: { scheduledAt: number; name?: string; description?: string }) => void;
  isSubmitting?: boolean;
}

const MIN_LEAD_SECONDS = 300; // mirrors backend broadcast_schedule_min_lead_time_seconds default

/** Convert a Unix-seconds timestamp into a value for <input type="datetime-local">. */
function toLocalInput(ts: number): string {
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function BroadcastScheduleDialog({
  open,
  onOpenChange,
  initialScheduledAt,
  rescheduleOnly = false,
  sessionName,
  onConfirm,
  isSubmitting,
}: BroadcastScheduleDialogProps) {
  const defaultTs = initialScheduledAt ?? Math.floor(Date.now() / 1000) + 3600;
  const [dateTime, setDateTime] = useState<string>(() => toLocalInput(defaultTs));
  const [name, setName] = useState<string>(sessionName ?? "");
  const [description, setDescription] = useState<string>("");
  const [error, setError] = useState<string>("");

  useEffect(() => {
    if (open) {
      setDateTime(toLocalInput(initialScheduledAt ?? Math.floor(Date.now() / 1000) + 3600));
      setName(sessionName ?? "");
      setDescription("");
      setError("");
    }
  }, [open, initialScheduledAt, sessionName]);

  const handleConfirm = () => {
    const scheduledAt = Math.floor(new Date(dateTime).getTime() / 1000);
    if (!scheduledAt || Number.isNaN(scheduledAt)) {
      setError("Please choose a valid date and time.");
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    if (scheduledAt < now + MIN_LEAD_SECONDS) {
      setError("Scheduled time must be at least 5 minutes in the future.");
      return;
    }
    setError("");
    onConfirm({
      scheduledAt,
      name: rescheduleOnly ? undefined : name.trim() || undefined,
      description: rescheduleOnly ? undefined : description.trim() || undefined,
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{rescheduleOnly ? "Reschedule Broadcast" : "Schedule Broadcast"}</DialogTitle>
          <DialogDescription>
            {rescheduleOnly
              ? "Pick a new date and time for this scheduled broadcast."
              : "Choose when this broadcast should go live. The system will start it automatically."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {!rescheduleOnly && (
            <>
              <div className="space-y-2">
                <Label htmlFor="bcast-sched-name">Name</Label>
                <Input
                  id="bcast-sched-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Friday Night Live"
                  maxLength={200}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="bcast-sched-desc">Description</Label>
                <Input
                  id="bcast-sched-desc"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What's this broadcast about?"
                  maxLength={2000}
                />
              </div>
            </>
          )}
          <div className="space-y-2">
            <Label htmlFor="bcast-sched-when">Date &amp; Time</Label>
            <Input
              id="bcast-sched-when"
              type="datetime-local"
              value={dateTime}
              onChange={(e) => setDateTime(e.target.value)}
              data-testid="schedule-datetime"
            />
          </div>
          {error && <p className="text-sm text-destructive" data-testid="schedule-error">{error}</p>}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button onClick={handleConfirm} disabled={isSubmitting} data-testid="schedule-confirm">
            {rescheduleOnly ? "Reschedule" : "Schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default BroadcastScheduleDialog;
