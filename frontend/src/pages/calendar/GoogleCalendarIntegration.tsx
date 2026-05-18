import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createGoogleCalendarMapping,
  disconnectGoogleCalendar,
  getCalendars,
  getGoogleCalendarProviderCalendars,
  getGoogleCalendarIntegrationStatus,
  runGoogleCalendarSync,
  startGoogleCalendarConnect,
} from "@/api/endpoints/calendar";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";

export function GoogleCalendarIntegration() {
  const queryClient = useQueryClient();

  const statusQuery = useQuery({
    queryKey: ["google-calendar-integration-status"],
    queryFn: getGoogleCalendarIntegrationStatus,
  });

  const connectMutation = useMutation({
    mutationFn: startGoogleCalendarConnect,
    onSuccess: (data) => {
      window.open(data.authorization_url, "_blank", "noopener,noreferrer");
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: () => disconnectGoogleCalendar(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["google-calendar-integration-status"] });
    },
  });
  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
    enabled: !!statusQuery.data?.connection_active,
  });
  const providerCalendarsQuery = useQuery({
    queryKey: ["google-calendar-provider-calendars"],
    queryFn: getGoogleCalendarProviderCalendars,
    enabled: !!statusQuery.data?.connection_active,
  });
  const mappingMutation = useMutation({
    mutationFn: createGoogleCalendarMapping,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["google-calendar-provider-calendars"] });
      queryClient.invalidateQueries({ queryKey: ["calendar-events"] });
      toast.success("Calendar mapping saved");
    },
    onError: () => {
      toast.error("Failed to save mapping");
    },
  });
  const syncMutation = useMutation({
    mutationFn: () => runGoogleCalendarSync("incremental"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["google-calendar-integration-status"] });
      queryClient.invalidateQueries({ queryKey: ["calendar-events"] });
      toast.success("Sync started");
    },
    onError: () => {
      toast.error("Failed to start sync");
    },
  });

  if (statusQuery.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading Google Calendar integration status…</p>;
  }

  if (statusQuery.isError || !statusQuery.data) {
    return (
      <EmptyState
        title="Google Calendar integration unavailable"
        description="The integration is currently disabled for your account or environment."
      />
    );
  }

  const status = statusQuery.data;

  return (
    <div className="space-y-3 rounded-md border p-4">
      <h3 className="text-sm font-semibold">Google Calendar rollout</h3>
      <p className="text-sm text-muted-foreground">
        Sync is enabled for your cohort. Writeback is currently {status.writeback_enabled ? "ON" : "OFF"}.
      </p>
      <div className="flex flex-wrap gap-2">
        <Badge variant={status.connection_active ? "default" : "outline"} aria-label={`Google connection is ${status.connection_active ? "active" : "disconnected"}`}>
          {status.connection_active ? "Connected" : "Disconnected"}
        </Badge>
        <Badge variant={status.reauth_required ? "destructive" : "secondary"} aria-label={`Google authentication ${status.reauth_required ? "requires reauthorization" : "healthy"}`}>
          {status.reauth_required ? "Reauth required" : "Auth healthy"}
        </Badge>
        <Badge variant="outline" aria-label={`Google sync health ${status.sync_health}`}>
          Sync health: {status.sync_health}
        </Badge>
      </div>
      <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
        <li>Rollout mode: {status.rollout_mode}</li>
        <li>Rollout percentage: {status.rollout_percent}%</li>
        <li>In cohort: {status.in_rollout_cohort ? "Yes" : "No"}</li>
        <li>Last sync: {status.last_sync_at_utc ? `${status.last_sync_status} at ${status.last_sync_at_utc}` : "Never"}</li>
      </ul>
      <div className="flex gap-2">
        <Button onClick={() => connectMutation.mutate()} disabled={connectMutation.isPending}>
          Connect Google Calendar
        </Button>
        <Button
          variant="outline"
          onClick={() => disconnectMutation.mutate()}
          disabled={disconnectMutation.isPending}
        >
          Disconnect
        </Button>
        <Button
          variant="secondary"
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending || !status.connection_active}
        >
          Run Sync
        </Button>
      </div>
      {status.connection_active && (
        <div className="space-y-2 rounded border p-3">
          <p className="text-sm font-medium">Calendar mappings</p>
          <p className="text-xs text-muted-foreground">
            Map each Google calendar to one internal calendar. Unmapped internal calendars remain unchanged.
          </p>
          <div className="space-y-3">
            {(providerCalendarsQuery.data?.calendars ?? []).map((googleCalendar) => (
              <div key={googleCalendar.google_calendar_id} className="grid gap-2 sm:grid-cols-[1fr_220px_auto] sm:items-center">
                <div>
                  <p className="text-sm font-medium">{googleCalendar.summary}</p>
                  <p className="text-xs text-muted-foreground">
                    {googleCalendar.primary ? "Primary" : "Secondary"} {googleCalendar.access_role ? `• ${googleCalendar.access_role}` : ""}
                  </p>
                </div>
                <div>
                  <Label className="sr-only" htmlFor={`map-${googleCalendar.google_calendar_id}`}>Internal calendar</Label>
                  <Select
                    value={googleCalendar.mapped_internal_calendar_id ?? "__unmapped__"}
                    onValueChange={(internalCalendarId) => {
                      if (internalCalendarId === "__unmapped__") return;
                      mappingMutation.mutate({
                        google_calendar_id: googleCalendar.google_calendar_id,
                        internal_calendar_id: internalCalendarId,
                      });
                    }}
                  >
                    <SelectTrigger id={`map-${googleCalendar.google_calendar_id}`}>
                      <SelectValue placeholder="Select internal calendar" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__unmapped__">Not mapped</SelectItem>
                      {(calendarsQuery.data ?? []).map((calendar) => (
                        <SelectItem key={calendar.calendar_id} value={calendar.calendar_id}>
                          {calendar.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <Badge variant={googleCalendar.mapped_internal_calendar_id ? "default" : "outline"} aria-label={googleCalendar.mapped_internal_calendar_id ? "Calendar mapped" : "Calendar not mapped"}>
                  {googleCalendar.mapped_internal_calendar_id ? "Mapped" : "Unmapped"}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
