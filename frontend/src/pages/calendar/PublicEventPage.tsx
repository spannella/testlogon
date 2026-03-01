import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { CalendarCheck, Download, Plus, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { getPublicEvent, getPublicIcalUrl } from "@/api/endpoints/calendar";
import { createEvent } from "@/api/endpoints/calendar";
import { useAuthStore } from "@/stores/authStore";

function formatEventTime(
  startUtc?: string,
  endUtc?: string,
  allDay?: boolean,
  allDayDate?: string,
  timezone?: string,
): string {
  if (allDay && allDayDate) return allDayDate;
  if (!startUtc) return "Time not set";

  const opts: Intl.DateTimeFormatOptions = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  };
  try {
    if (timezone) opts.timeZone = timezone;
  } catch {
    // ignore invalid timezone
  }

  const start = new Date(startUtc).toLocaleString(undefined, opts);
  if (!endUtc) return start;

  const endOpts: Intl.DateTimeFormatOptions = { hour: "numeric", minute: "2-digit" };
  try {
    if (timezone) endOpts.timeZone = timezone;
  } catch {
    // ignore
  }
  const end = new Date(endUtc).toLocaleTimeString(undefined, endOpts);
  return `${start} – ${end}`;
}

export default function PublicEventPage() {
  const { calendarId, eventId } = useParams<{ calendarId: string; eventId: string }>();
  const isLoggedIn = useAuthStore((s) => s.isAuthenticated);

  const { data: evt, isLoading, isError } = useQuery({
    queryKey: ["public-event", calendarId, eventId],
    queryFn: () => getPublicEvent(calendarId!, eventId!),
    enabled: !!calendarId && !!eventId,
    retry: false,
  });

  function handleDownloadIcal() {
    if (!calendarId || !eventId) return;
    window.open(getPublicIcalUrl(calendarId, eventId), "_blank", "noopener,noreferrer");
  }

  async function handleAddToCalendar() {
    if (!evt || !calendarId) return;
    try {
      await createEvent(calendarId, {
        name: evt.name ?? "Event",
        description: evt.description,
        timezone: evt.timezone,
        start_utc: evt.start_utc,
        end_utc: evt.end_utc,
        all_day: evt.all_day,
        all_day_date: evt.all_day_date,
      });
      toast.success("Added to your calendar");
    } catch {
      toast.error("Failed to add event to calendar");
    }
  }

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (isError || !evt) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-8 text-center">
        <CalendarCheck className="h-12 w-12 text-muted-foreground" />
        <h1 className="text-xl font-semibold">Event not found</h1>
        <p className="text-muted-foreground">This event may have been removed or is no longer public.</p>
        <Link to="/" className="text-primary hover:underline text-sm">Go home</Link>
      </div>
    );
  }

  const dateStr = formatEventTime(evt.start_utc, evt.end_utc, evt.all_day, evt.all_day_date, evt.timezone);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-8">
      <div className="w-full max-w-md space-y-6">
        <div className="flex items-center gap-3">
          <CalendarCheck className="h-8 w-8 text-primary shrink-0" />
          <div>
            <h1 className="text-2xl font-bold">{evt.name}</h1>
            <p className="text-sm text-muted-foreground">{dateStr}</p>
          </div>
        </div>

        {evt.description && (
          <p className="text-sm text-muted-foreground whitespace-pre-wrap">{evt.description}</p>
        )}

        <div className="flex flex-wrap gap-3">
          <Button variant="outline" onClick={handleDownloadIcal}>
            <Download className="h-4 w-4 mr-2" />
            Download .ics
          </Button>

          {isLoggedIn ? (
            <Button onClick={handleAddToCalendar}>
              <Plus className="h-4 w-4 mr-2" />
              Add to my Calendar
            </Button>
          ) : (
            <Link to="/login">
              <Button variant="secondary">
                Sign in to add to calendar
              </Button>
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
