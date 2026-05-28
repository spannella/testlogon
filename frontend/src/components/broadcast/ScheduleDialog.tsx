import { useState, useEffect } from "react";
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
import { Loader2, CalendarClock } from "lucide-react";

interface ScheduleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialScheduledAt?: number | null;
  sessionName?: string;
  onConfirm: (scheduledAt: number) => void;
  isSubmitting?: boolean;
}

export function ScheduleDialog({
  open,
  onOpenChange,
  initialScheduledAt,
  sessionName,
  onConfirm,
  isSubmitting,
}: ScheduleDialogProps) {
  const [dateStr, setDateStr] = useState("");
  const [timeStr, setTimeStr] = useState("");
  const [validationError, setValidationError] = useState("");

  useEffect(() => {
    if (open) {
      if (initialScheduledAt) {
        const d = new Date(initialScheduledAt * 1000);
        setDateStr(d.toISOString().split("T")[0] ?? "");
        setTimeStr(d.toTimeString().slice(0, 5) ?? "");
      } else {
        // Default to 1 hour from now
        const d = new Date(Date.now() + 3600_000);
        setDateStr(d.toISOString().split("T")[0] ?? "");
        setTimeStr(d.toTimeString().slice(0, 5) ?? "");
      }
      setValidationError("");
    }
  }, [open, initialScheduledAt]);

  const computeTimestamp = (): number | null => {
    if (!dateStr || !timeStr) return null;
    const dt = new Date(`${dateStr}T${timeStr}`);
    if (isNaN(dt.getTime())) return null;
    return Math.floor(dt.getTime() / 1000);
  };

  const handleConfirm = () => {
    const ts = computeTimestamp();
    if (!ts) {
      setValidationError("Invalid date or time");
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    if (ts < now + 300) {
      setValidationError("Must be at least 5 minutes in the future");
      return;
    }
    setValidationError("");
    onConfirm(ts);
  };

  const previewTs = computeTimestamp();
  const previewDate = previewTs ? new Date(previewTs * 1000) : null;
  const nowSec = Math.floor(Date.now() / 1000);
  const remaining = previewTs ? previewTs - nowSec : 0;
  const remainingLabel =
    remaining > 86400
      ? `in ${Math.floor(remaining / 86400)} days`
      : remaining > 3600
        ? `in ${Math.floor(remaining / 3600)} hours, ${Math.floor((remaining % 3600) / 60)} minutes`
        : remaining > 60
          ? `in ${Math.floor(remaining / 60)} minutes`
          : remaining > 0
            ? `in ${remaining} seconds`
            : "in the past";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CalendarClock className="h-5 w-5" />
            Schedule Broadcast
          </DialogTitle>
          <DialogDescription>
            {sessionName ? `Schedule "${sessionName}"` : "Set the date and time for this broadcast"}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="schedule-date">Date</Label>
            <Input
              id="schedule-date"
              type="date"
              value={dateStr}
              onChange={(e) => {
                setDateStr(e.target.value);
                setValidationError("");
              }}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="schedule-time">Time (local)</Label>
            <Input
              id="schedule-time"
              type="time"
              value={timeStr}
              onChange={(e) => {
                setTimeStr(e.target.value);
                setValidationError("");
              }}
            />
          </div>

          {previewDate && remaining > 0 && (
            <div className="rounded-md border p-3 text-sm text-muted-foreground">
              <p className="font-medium text-foreground">
                {previewDate.toLocaleString()}
              </p>
              <p>({remainingLabel})</p>
            </div>
          )}

          {validationError && (
            <p className="text-sm text-destructive">{validationError}</p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleConfirm} disabled={isSubmitting}>
            {isSubmitting && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}
            {initialScheduledAt ? "Reschedule" : "Schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
