import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, CalendarPlus } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/api/client";
import {
  createCrmEvent,
  upsertLocalEvent,
  type CrmEvent,
} from "@/api/endpoints/crmEvents";
import { EventsFeatureDisabled } from "./EventsFeatureDisabled";

export default function CrmEventCreatePage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [maxAttendance, setMaxAttendance] = useState("");
  const [calendarEventId, setCalendarEventId] = useState("");
  const [disabled, setDisabled] = useState(false);

  const createMut = useMutation({
    mutationFn: (): Promise<CrmEvent> =>
      createCrmEvent({
        name: name.trim(),
        description: description.trim() || undefined,
        max_attendance: maxAttendance.trim() ? Number(maxAttendance) : null,
        calendar_event_id: calendarEventId.trim() || null,
      }),
    onSuccess: (ev) => {
      upsertLocalEvent(ev);
      toast.success("Event created");
      navigate(`/crm/events/${ev.event_id}`);
    },
    onError: (err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
        setDisabled(true);
        return;
      }
      toast.error(err instanceof ApiError ? err.detail : "Failed to create event");
    },
  });

  if (disabled) {
    return (
      <div className="space-y-6">
        <PageHeader title="Create Event" description="SuiteCRM Events" />
        <EventsFeatureDisabled />
      </div>
    );
  }

  const maxNum = maxAttendance.trim() ? Number(maxAttendance) : null;
  const maxInvalid = maxNum !== null && (!Number.isInteger(maxNum) || maxNum < 1);
  const canSubmit = name.trim().length > 0 && !maxInvalid && !createMut.isPending;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Create Event"
        description="Set up a new SuiteCRM event with optional capacity limit."
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to="/crm/events">
              <ArrowLeft className="mr-1 h-4 w-4" />
              Back to events
            </Link>
          </Button>
        }
      />

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <CalendarPlus className="h-4 w-4" />
            Event details
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="ev-name">Name *</Label>
            <Input
              id="ev-name"
              value={name}
              maxLength={200}
              placeholder="Quarterly customer summit"
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ev-desc">Description</Label>
            <Textarea
              id="ev-desc"
              value={description}
              maxLength={5000}
              rows={4}
              placeholder="Agenda, location, and other details…"
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="ev-max">Max attendance</Label>
              <Input
                id="ev-max"
                type="number"
                min={1}
                value={maxAttendance}
                placeholder="Unlimited"
                onChange={(e) => setMaxAttendance(e.target.value)}
              />
              {maxInvalid && (
                <p className="text-xs text-destructive">Must be a whole number ≥ 1.</p>
              )}
              <p className="text-xs text-muted-foreground">
                Leave blank for no limit. Over-capacity registrations are waitlisted.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="ev-cal">Calendar event ID</Label>
              <Input
                id="ev-cal"
                value={calendarEventId}
                maxLength={200}
                placeholder="Optional"
                onChange={(e) => setCalendarEventId(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Link to an existing calendar event (optional).
              </p>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => navigate("/crm/events")}>
              Cancel
            </Button>
            <Button disabled={!canSubmit} onClick={() => createMut.mutate()}>
              {createMut.isPending ? "Creating…" : "Create event"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
