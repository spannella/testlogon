import { api } from "@/api/client";
import type {
  Calendar,
  CalendarCreateIn,
  CalendarEvent,
  EventCreateIn,
  EventsPage,
  BookingLink,
  BookingLinkCreateIn,
  Opening,
  OkResp,
  CalendarShare,
  ShareCalendarReq,
  ConflictPreviewReq,
  ConflictResult,
  SlotSuggestionReq,
  AvailabilityReq,
  OccurrenceOverrideIn,
  BookingReserveReq,
} from "@/api/types";

// ─── Calendars ───────────────────────────────────────────────────

export const createCalendar = (body: CalendarCreateIn) =>
  api.post<Calendar>("/ui/calendars", body);

export const getCalendars = (limit = 50) =>
  api.get<Calendar[]>("/ui/calendars", { limit: String(limit) });

export const getCalendar = (id: string) =>
  api.get<Calendar>(`/ui/calendars/${id}`);

export const updateCalendar = (id: string, body: Partial<CalendarCreateIn>) =>
  api.patch<Calendar>(`/ui/calendars/${id}`, body);

export const deleteCalendar = (id: string) =>
  api.del<OkResp>(`/ui/calendars/${id}`);

// ─── Events ──────────────────────────────────────────────────────

export const createEvent = (calendarId: string, body: EventCreateIn) =>
  api.post<CalendarEvent>(`/ui/calendars/${calendarId}/events`, body);

export const getEvents = (calendarId: string, cursor?: string) =>
  api.get<EventsPage>(
    `/ui/calendars/${calendarId}/events`,
    cursor ? { cursor } : undefined,
  );

export const getEvent = (calendarId: string, eventId: string) =>
  api.get<CalendarEvent>(`/ui/calendars/${calendarId}/events/${eventId}`);

export const updateEvent = (calendarId: string, eventId: string, body: Partial<EventCreateIn>) =>
  api.patch<CalendarEvent>(`/ui/calendars/${calendarId}/events/${eventId}`, body);

export const deleteEvent = (calendarId: string, eventId: string) =>
  api.del<OkResp>(`/ui/calendars/${calendarId}/events/${eventId}`);

// ─── Availability & Booking ──────────────────────────────────────

export const createBookingLink = (calendarId: string, body: BookingLinkCreateIn) =>
  api.post<BookingLink>(`/ui/calendars/${calendarId}/booking_links`, body);

// ─── Calendar Sharing ───────────────────────────────────────────

export const shareCalendar = (calendarId: string, body: ShareCalendarReq) =>
  api.post<CalendarShare>(`/ui/calendars/${calendarId}/shares`, body);

export const getCalendarShares = (calendarId: string) =>
  api.get<CalendarShare[]>(`/ui/calendars/${calendarId}/shares`);

export const removeCalendarShare = (calendarId: string, userSub: string) =>
  api.del<OkResp>(`/ui/calendars/${calendarId}/shares/${userSub}`);

// ─── Conflicts & Suggestions ────────────────────────────────────

export const previewConflicts = (calendarId: string, body: ConflictPreviewReq) =>
  api.post<ConflictResult>(`/ui/calendars/${calendarId}/events/conflicts`, body);

export const suggestSlots = (calendarId: string, body: SlotSuggestionReq) =>
  api.post<Opening[]>(`/ui/calendars/${calendarId}/events/suggestions`, body);

export const getTeamAvailability = (body: AvailabilityReq) =>
  api.post<Opening[]>("/ui/calendars/availability", body);

// ─── Openings & Booking Links (server-side list) ────────────────

export const getOpenings = (calendarId: string, startUtc: string, endUtc: string) =>
  api.get<Opening[]>(`/ui/calendars/${calendarId}/openings`, {
    start_utc: startUtc,
    end_utc: endUtc,
  });

export const listBookingLinks = (calendarId: string) =>
  api.get<BookingLink[]>(`/ui/calendars/${calendarId}/booking_links`);

// ─── Recurrence Occurrences ─────────────────────────────────────

export const excludeOccurrence = (
  calendarId: string,
  eventId: string,
  occurrenceStart: string,
) =>
  api.post<CalendarEvent>(
    `/ui/calendars/${calendarId}/events/${eventId}/occurrences/${occurrenceStart}/exclude`,
    {},
  );

export const overrideOccurrence = (
  calendarId: string,
  eventId: string,
  occurrenceStart: string,
  body: OccurrenceOverrideIn,
) =>
  api.post<CalendarEvent>(
    `/ui/calendars/${calendarId}/events/${eventId}/occurrences/${occurrenceStart}/override`,
    body,
  );

export const clearOccurrenceOverride = (
  calendarId: string,
  eventId: string,
  occurrenceStart: string,
) =>
  api.del<CalendarEvent>(
    `/ui/calendars/${calendarId}/events/${eventId}/occurrences/${occurrenceStart}`,
  );

// ─── Public Booking ─────────────────────────────────────────────

export const getPublicBookingLink = (linkId: string) =>
  api.get<BookingLink>(`/booking/${linkId}`);

export const getPublicOpenings = (
  linkId: string,
  startUtc: string,
  endUtc: string,
  limit?: number,
) =>
  api.get<Opening[]>(`/booking/${linkId}/openings`, {
    start_utc: startUtc,
    end_utc: endUtc,
    ...(limit ? { limit: String(limit) } : {}),
  });

export const reserveBookingSlot = (linkId: string, body: BookingReserveReq) =>
  api.post<CalendarEvent>(`/booking/${linkId}/reserve`, body);
