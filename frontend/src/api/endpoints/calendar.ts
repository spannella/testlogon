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

export const getAvailability = (calendarId: string, startUtc: string, endUtc: string) =>
  api.get<Opening[]>(`/ui/calendars/${calendarId}/availability`, {
    start_utc: startUtc,
    end_utc: endUtc,
  });

export const createBookingLink = (calendarId: string, body: BookingLinkCreateIn) =>
  api.post<BookingLink>(`/booking/links`, { ...body, calendar_id: calendarId });

export const getBookingLink = (linkId: string) =>
  api.get<BookingLink>(`/booking/links/${linkId}`);

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
