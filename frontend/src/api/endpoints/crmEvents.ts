// SuiteCRM EVENTS cluster (EVT-Events: EVT-001..EVT-004).
//
// Live backend contract (source of truth):
//   - Router:  app/routers/crm_events.py   (prefix /ui/crm/events, tag crm_events)
//   - Service: app/services/crm_events.py
//   - Models:  app/models.py  (CrmEvent*, CrmInvitee*, CrmRegistration*, CrmCapacity*)
//   - Flag:    S.crm_events_enabled (env CRM_EVENTS_ENABLED, default OFF -> 404)
//
// NOTE: the live backend exposes NO "list events" and NO "get single event"
// endpoint — only POST / (create) and the per-event sub-resources. To provide an
// events-list UI we mirror created events into localStorage (see localEvents helpers
// below). This is reported in `deferred`. All other calls hit the real backend.
//
// Types are defined INLINE here (mirroring app/models.py) — NOT in shared api/types.ts.

import { api } from "@/api/client";

const BASE = "/ui/crm/events";

// ─── Models (mirror app/models.py) ─────────────────────────────────────────

export interface CrmEvent {
  event_id: string;
  owner_sub: string;
  name: string;
  description: string;
  calendar_event_id: string | null;
  max_attendance: number | null;
  created_at: number;
  updated_at: number;
}

export interface CrmEventCreateIn {
  name: string;
  description?: string;
  calendar_event_id?: string | null;
  max_attendance?: number | null;
}

export type CrmInviteStatus = "pending" | "sent" | "accepted" | "declined" | string;

export interface CrmInvitee {
  event_id: string;
  invitee_sub: string;
  invite_status: CrmInviteStatus;
  invited_at: number;
  responded_at: number | null;
  display_name: string | null;
}

export interface CrmInviteeListOut {
  invitees: CrmInvitee[];
  cursor: string | null;
}

export interface CrmSendInvitationsOut {
  sent: number;
  skipped: number;
  failed: number;
}

export interface CrmBulkImportOut {
  added: number;
  skipped: number;
}

export type CrmRegistrationStatus =
  | "registered"
  | "accepted"
  | "declined"
  | "waitlisted"
  | "attended"
  | string;

export interface CrmRegistration {
  event_id: string;
  registrant_sub: string;
  status: CrmRegistrationStatus;
  registered_at: number;
  responded_at: number | null;
  checked_in_at: number | null;
  waitlist_position: number | null;
  invited: boolean | null;
}

export interface CrmRegistrationListOut {
  registrations: CrmRegistration[];
  cursor: string | null;
}

export interface CrmCapacity {
  event_id: string;
  max_attendance: number | null;
  accepted_count: number;
  waitlisted_count: number;
  available_spots: number | null;
}

// ─── EVT-002: Event creation + invitee management ──────────────────────────

export const createCrmEvent = (body: CrmEventCreateIn) =>
  api.post<CrmEvent>(`${BASE}/`, body);

export const addInvitee = (eventId: string, inviteeSub: string) =>
  api.post<CrmInvitee>(`${BASE}/${eventId}/invitees`, { invitee_sub: inviteeSub });

export const removeInvitee = (eventId: string, inviteeSub: string) =>
  api.del<void>(`${BASE}/${eventId}/invitees/${encodeURIComponent(inviteeSub)}`);

export const bulkImportInvitees = (eventId: string, userSubs: string[]) =>
  api.post<CrmBulkImportOut>(`${BASE}/${eventId}/invitees/bulk-import`, {
    user_subs: userSubs,
  });

export const sendInvitations = (eventId: string) =>
  api.post<CrmSendInvitationsOut>(`${BASE}/${eventId}/invitees/send-invitations`, {});

export const listInvitees = (
  eventId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmInviteeListOut>(`${BASE}/${eventId}/invitees`, params);
};

// ─── EVT-003: Registration workflow ────────────────────────────────────────

export const registerForEvent = (eventId: string) =>
  api.post<CrmRegistration>(`${BASE}/${eventId}/registrations`, {});

export const respondToInvitation = (
  eventId: string,
  registrantSub: string,
  newStatus: "accepted" | "declined",
) =>
  api.post<CrmRegistration>(
    `${BASE}/${eventId}/registrations/${encodeURIComponent(registrantSub)}/respond`,
    { new_status: newStatus },
  );

export const checkInAttendee = (eventId: string, registrantSub: string) =>
  api.post<CrmRegistration>(
    `${BASE}/${eventId}/registrations/${encodeURIComponent(registrantSub)}/check-in`,
    {},
  );

export const cancelRegistration = (eventId: string, registrantSub: string) =>
  api.del<void>(
    `${BASE}/${eventId}/registrations/${encodeURIComponent(registrantSub)}`,
  );

export const listRegistrations = (
  eventId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmRegistrationListOut>(`${BASE}/${eventId}/registrations`, params);
};

// ─── EVT-004: Capacity ─────────────────────────────────────────────────────

export const getEventCapacity = (eventId: string) =>
  api.get<CrmCapacity>(`${BASE}/${eventId}/capacity`);

// ─── Client-side event registry (no backend list endpoint) ─────────────────
// The backend has no list/get-single endpoint, so we mirror created events into
// localStorage keyed per browser. This is a UI convenience only — capacity and
// registration data always come fresh from the backend.

const LS_KEY = "crm_events_registry_v1";

export interface LocalEventEntry {
  event_id: string;
  name: string;
  description: string;
  max_attendance: number | null;
  calendar_event_id: string | null;
  created_at: number;
}

export function readLocalEvents(): LocalEventEntry[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as LocalEventEntry[];
  } catch {
    return [];
  }
}

export function upsertLocalEvent(ev: CrmEvent): void {
  try {
    const entries = readLocalEvents().filter((e) => e.event_id !== ev.event_id);
    entries.unshift({
      event_id: ev.event_id,
      name: ev.name,
      description: ev.description,
      max_attendance: ev.max_attendance,
      calendar_event_id: ev.calendar_event_id,
      created_at: ev.created_at,
    });
    localStorage.setItem(LS_KEY, JSON.stringify(entries.slice(0, 200)));
  } catch {
    /* localStorage unavailable — ignore */
  }
}

export function removeLocalEvent(eventId: string): void {
  try {
    const entries = readLocalEvents().filter((e) => e.event_id !== eventId);
    localStorage.setItem(LS_KEY, JSON.stringify(entries));
  } catch {
    /* ignore */
  }
}

export function getLocalEvent(eventId: string): LocalEventEntry | undefined {
  return readLocalEvents().find((e) => e.event_id === eventId);
}
