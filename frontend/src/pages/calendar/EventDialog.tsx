import { useEffect, useMemo } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { createEvent, updateEvent, deleteEvent } from "@/api/endpoints/calendar";
import { ConflictBanner } from "./ConflictBanner";
import { SlotSuggestions } from "./SlotSuggestions";
import type { CalendarEvent, Calendar, ConflictPreviewReq } from "@/api/types";

const eventSchema = z.object({
  name: z.string().min(1, "Title is required"),
  description: z.string().optional(),
  all_day: z.boolean(),
  start_utc: z.string().optional(),
  end_utc: z.string().optional(),
  all_day_date: z.string().optional(),
  recurrence_freq: z.string().optional(),
  recurrence_interval: z.coerce.number().min(1).optional(),
  recurrence_count: z.coerce.number().min(1).optional(),
});

type EventFormValues = z.infer<typeof eventSchema>;

interface EventDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  calendars: Calendar[];
  selectedCalendarId: string;
  event?: CalendarEvent | null;
  defaultDate?: string;
}

export function EventDialog({
  open,
  onOpenChange,
  calendars,
  selectedCalendarId,
  event,
  defaultDate,
}: EventDialogProps) {
  const queryClient = useQueryClient();
  const isEditing = !!event;

  const form = useForm<EventFormValues>({
    resolver: zodResolver(eventSchema),
    defaultValues: {
      name: "",
      description: "",
      all_day: false,
      start_utc: "",
      end_utc: "",
      all_day_date: "",
      recurrence_freq: "none",
      recurrence_interval: 1,
      recurrence_count: undefined,
    },
  });

  useEffect(() => {
    if (!open) return;
    if (event) {
      form.reset({
        name: event.name,
        description: event.description ?? "",
        all_day: event.all_day,
        start_utc: event.start_utc ? event.start_utc.slice(0, 16) : "",
        end_utc: event.end_utc ? event.end_utc.slice(0, 16) : "",
        all_day_date: event.all_day_date ?? "",
        recurrence_freq: event.recurrence_rule?.freq ?? "none",
        recurrence_interval: event.recurrence_rule?.interval ?? 1,
        recurrence_count: event.recurrence_rule?.count,
      });
    } else {
      form.reset({
        name: "",
        description: "",
        all_day: false,
        start_utc: defaultDate ? `${defaultDate}T09:00` : "",
        end_utc: defaultDate ? `${defaultDate}T10:00` : "",
        all_day_date: defaultDate ?? "",
        recurrence_freq: "none",
        recurrence_interval: 1,
        recurrence_count: undefined,
      });
    }
  }, [open, event, defaultDate, form]);

  const saveMutation = useMutation({
    mutationFn: (values: EventFormValues) => {
      const recurrence_rule =
        values.recurrence_freq && values.recurrence_freq !== "none"
          ? {
              freq: values.recurrence_freq as "DAILY" | "WEEKLY" | "MONTHLY",
              interval: values.recurrence_interval,
              count: values.recurrence_count,
            }
          : undefined;

      const body = {
        name: values.name,
        description: values.description,
        all_day: values.all_day,
        start_utc: values.all_day ? undefined : (values.start_utc || undefined),
        end_utc: values.all_day ? undefined : (values.end_utc || undefined),
        all_day_date: values.all_day ? (values.all_day_date || undefined) : undefined,
        recurrence_rule,
      };

      if (isEditing) {
        return updateEvent(event.calendar_id, event.event_id, body);
      }
      return createEvent(selectedCalendarId, body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendar-events"] });
      onOpenChange(false);
      toast.success(isEditing ? "Event updated" : "Event created");
    },
    onError: () => {
      toast.error(isEditing ? "Failed to update event" : "Failed to create event");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => {
      if (!event) return Promise.reject(new Error("No event"));
      return deleteEvent(event.calendar_id, event.event_id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendar-events"] });
      onOpenChange(false);
      toast.success("Event deleted");
    },
    onError: () => {
      toast.error("Failed to delete event");
    },
  });

  const allDay = form.watch("all_day");
  const startUtc = form.watch("start_utc");
  const endUtc = form.watch("end_utc");
  const watchedName = form.watch("name");
  const recurrenceFreq = form.watch("recurrence_freq");

  const calId = isEditing ? event.calendar_id : selectedCalendarId;

  // Build conflict preview request from current form state
  const conflictReq: ConflictPreviewReq | null = useMemo(() => {
    if (allDay || !startUtc || !endUtc) return null;
    return {
      name: watchedName || "Untitled",
      start_utc: startUtc,
      end_utc: endUtc,
      all_day: false,
      ...(isEditing ? { event_id: event.event_id } : {}),
    };
  }, [allDay, startUtc, endUtc, watchedName, isEditing, event]);

  const handleSlotSelect = (start: string, end: string) => {
    form.setValue("start_utc", start.slice(0, 16));
    form.setValue("end_utc", end.slice(0, 16));
    form.setValue("all_day", false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-md overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEditing ? "Edit Event" : "New Event"}</DialogTitle>
        </DialogHeader>
        <form
          onSubmit={form.handleSubmit((v) => saveMutation.mutate(v))}
          className="space-y-4 py-2"
        >
          <div className="space-y-1.5">
            <Label htmlFor="event-name">Title *</Label>
            <Input id="event-name" {...form.register("name")} />
            {form.formState.errors.name && (
              <p className="text-xs text-destructive">{form.formState.errors.name.message}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="event-desc">Description</Label>
            <Textarea id="event-desc" rows={2} {...form.register("description")} />
          </div>

          {/* Calendar selector (only for new events) */}
          {!isEditing && calendars.length > 1 && (
            <div className="space-y-1.5">
              <Label>Calendar</Label>
              <p className="text-xs text-muted-foreground">
                Using: {calendars.find((c) => c.calendar_id === selectedCalendarId)?.name ?? selectedCalendarId}
              </p>
            </div>
          )}

          {/* All day toggle */}
          <div className="flex items-center gap-2">
            <Switch
              checked={allDay}
              onCheckedChange={(checked) => form.setValue("all_day", checked)}
            />
            <Label>All day</Label>
          </div>

          {allDay ? (
            <div className="space-y-1.5">
              <Label htmlFor="event-allday-date">Date</Label>
              <Input id="event-allday-date" type="date" {...form.register("all_day_date")} />
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="event-start">Start</Label>
                <Input id="event-start" type="datetime-local" {...form.register("start_utc")} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="event-end">End</Label>
                <Input id="event-end" type="datetime-local" {...form.register("end_utc")} />
              </div>
            </div>
          )}

          {/* Conflict banner */}
          {calId && (
            <ConflictBanner calendarId={calId} request={conflictReq} />
          )}

          {/* Recurrence */}
          <div className="space-y-1.5">
            <Label>Repeat</Label>
            <Select
              value={recurrenceFreq ?? "none"}
              onValueChange={(v) => form.setValue("recurrence_freq", v)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Does not repeat</SelectItem>
                <SelectItem value="DAILY">Daily</SelectItem>
                <SelectItem value="WEEKLY">Weekly</SelectItem>
                <SelectItem value="MONTHLY">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {recurrenceFreq && recurrenceFreq !== "none" && (
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="event-interval">Every N</Label>
                <Input
                  id="event-interval"
                  type="number"
                  min={1}
                  {...form.register("recurrence_interval")}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="event-count">Occurrences</Label>
                <Input
                  id="event-count"
                  type="number"
                  min={1}
                  placeholder="∞"
                  {...form.register("recurrence_count")}
                />
              </div>
            </div>
          )}

          {/* Slot suggestions (only for new events, non-all-day) */}
          {!isEditing && !allDay && calId && (
            <SlotSuggestions calendarId={calId} onSelectSlot={handleSlotSelect} />
          )}

          <DialogFooter className="gap-2">
            {isEditing && (
              <Button
                type="button"
                variant="destructive"
                size="sm"
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete"}
              </Button>
            )}
            <Button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending
                ? "Saving..."
                : isEditing
                  ? "Update"
                  : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
