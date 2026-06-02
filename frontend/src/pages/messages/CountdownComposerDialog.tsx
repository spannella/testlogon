import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { CountdownCard } from "./CountdownCard";

export interface CountdownSubmitData {
  title: string;
  target_datetime: number;
  associated_event_type: "broadcast" | "call" | "calendar" | "custom";
  associated_event_id?: string;
}

interface CountdownComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CountdownSubmitData) => void;
}

const EVENT_TYPES: Array<{
  value: "custom" | "broadcast" | "call" | "calendar";
  label: string;
}> = [
  { value: "custom", label: "Custom" },
  { value: "broadcast", label: "Broadcast" },
  { value: "call", label: "Call" },
  { value: "calendar", label: "Calendar Event" },
];

// Build a default datetime-local value 1 hour from now.
function defaultLocalDatetime(): string {
  const d = new Date(Date.now() + 60 * 60 * 1000);
  // Adjust for local timezone offset so the input shows local time.
  const off = d.getTimezoneOffset() * 60 * 1000;
  return new Date(d.getTime() - off).toISOString().slice(0, 16);
}

export function CountdownComposerDialog({
  open,
  onClose,
  onSubmit,
}: CountdownComposerDialogProps) {
  const [title, setTitle] = useState("");
  const [localDatetime, setLocalDatetime] = useState<string>(
    defaultLocalDatetime(),
  );
  const [eventType, setEventType] = useState<
    "custom" | "broadcast" | "call" | "calendar"
  >("custom");
  const [eventId, setEventId] = useState("");

  const targetTs = localDatetime
    ? Math.floor(new Date(localDatetime).getTime() / 1000)
    : 0;
  const nowTs = Math.floor(Date.now() / 1000);
  const isFuture = targetTs > nowTs;
  const eventIdRequired = eventType !== "custom";
  const canSubmit =
    title.trim().length > 0 &&
    title.length <= 200 &&
    isFuture &&
    (!eventIdRequired || eventId.trim().length > 0);

  function reset() {
    setTitle("");
    setLocalDatetime(defaultLocalDatetime());
    setEventType("custom");
    setEventId("");
  }

  function handleClose() {
    reset();
    onClose();
  }

  function handleSubmit() {
    if (!canSubmit) return;
    onSubmit({
      title: title.trim(),
      target_datetime: targetTs,
      associated_event_type: eventType,
      associated_event_id: eventIdRequired ? eventId.trim() : undefined,
    });
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create Countdown</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="countdown-title-input">Title</Label>
            <Input
              id="countdown-title-input"
              value={title}
              maxLength={200}
              placeholder="Team standup starts in..."
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="countdown-datetime-input">Target date &amp; time</Label>
            <Input
              id="countdown-datetime-input"
              type="datetime-local"
              value={localDatetime}
              onChange={(e) => setLocalDatetime(e.target.value)}
            />
            {!isFuture && localDatetime && (
              <p className="text-xs text-destructive">
                Target must be in the future.
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label>Linked event</Label>
            <RadioGroup
              value={eventType}
              onValueChange={(v) =>
                setEventType(v as "custom" | "broadcast" | "call" | "calendar")
              }
            >
              {EVENT_TYPES.map((t) => (
                <div key={t.value} className="flex items-center gap-2">
                  <RadioGroupItem
                    value={t.value}
                    id={`countdown-event-${t.value}`}
                  />
                  <Label
                    htmlFor={`countdown-event-${t.value}`}
                    className="font-normal cursor-pointer"
                  >
                    {t.label}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>

          {eventIdRequired && (
            <div className="space-y-1.5">
              <Label htmlFor="countdown-eventid-input">Event ID</Label>
              <Input
                id="countdown-eventid-input"
                value={eventId}
                maxLength={128}
                placeholder="e.g. bcast_123"
                onChange={(e) => setEventId(e.target.value)}
              />
            </div>
          )}

          {title.trim() && isFuture && (
            <div className="flex justify-center pt-1">
              <CountdownCard
                title={title.trim()}
                targetDatetime={targetTs}
                associatedEventType={eventType}
                associatedEventId={eventIdRequired ? eventId.trim() : null}
              />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default CountdownComposerDialog;
