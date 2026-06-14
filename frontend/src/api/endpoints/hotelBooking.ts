/**
 * Hotel Booking Engine + Reservations API endpoints (QloApps HTL-017..HTL-019).
 *
 * All paths are under /ui (proxied to backend by Vite).
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404 when off.
 *
 * Inline TS types mirror app/models.py StaySearch*, StayReservationOut,
 * ReservationCreateIn, ReservationModifyIn, ReservationTransitionIn.
 *
 * NOTE: HotelOut is duplicated here (not imported from hotelSetup.ts) so
 * each area file is self-contained per shared-tree rules.
 */

import { api } from "@/api/client";

// ─── Shared sub-models ────────────────────────────────────────────────────────

export interface HotelAddress {
  line1: string;
  line2?: string | null;
  city: string;
  region: string;
  postal_code: string;
  country: string;
}

export interface HotelPolicies {
  cancellation_text: string;
  pet_policy: string;
  smoking: boolean;
  children: boolean;
}

export interface HotelContact {
  phone: string;
  email: string;
  website: string;
}

export interface HotelOut {
  hotel_id: string;
  owner_sub: string;
  name: string;
  description: string;
  star_rating: number;
  address: HotelAddress;
  check_in_time: string;
  check_out_time: string;
  policies: HotelPolicies;
  contact: HotelContact;
  photo_urls: string[];
  status: "active" | "archived";
  created_at: number;
  updated_at: number;
}

// ─── Stay search ──────────────────────────────────────────────────────────────

export interface StaySearchIn {
  hotel_id?: string | null;
  city?: string | null;
  checkin: string;   // "YYYY-MM-DD"
  checkout: string;  // "YYYY-MM-DD" (exclusive — departure day)
  adults: number;
  children?: number;
  rooms?: number;
}

/** One per-night price line from HTL-015 rate plans */
export interface NightLine {
  date: string;
  amount_cents: number;
  rule_id?: string | null;
  label?: string | null;
}

export interface StayRoomTypeResult {
  hotel_id: string;
  room_type_id: string;
  name: string;
  available: boolean;
  min_remaining: number;
  rooms: number;
  per_night: NightLine[];
  total_cents: number;
  currency: string;
  applied_rule_ids: string[];
}

export interface StaySearchResult {
  checkin: string;
  checkout: string;
  nights: number;
  adults: number;
  children: number;
  rooms: number;
  results: StayRoomTypeResult[];
  result_count: number;
}

// ─── Reservation ──────────────────────────────────────────────────────────────

export type ReservationStatus =
  | "confirmed"
  | "checked_in"
  | "checked_out"
  | "cancelled"
  | "no_show";

export interface StayReservationOut {
  reservation_id: string;
  hotel_id: string;
  guest_party_id: string;
  room_type_id: string;
  assigned_room_ids: string[];
  checkin: string;
  checkout: string;
  nights: number;
  adults: number;
  children: number;
  rooms: number;
  total_cents: number;
  deposit_cents: number;
  currency: string;
  status: ReservationStatus;
  hold_id: string;
  version: number;
  created_at: number;
  updated_at: number;
}

export interface ReservationCreateIn {
  hotel_id: string;
  guest_party_id: string;
  room_type_id: string;
  checkin: string;
  checkout: string;
  adults: number;
  children?: number;
  rooms?: number;
  deposit_cents?: number;
}

export interface ReservationModifyIn {
  checkin?: string | null;
  checkout?: string | null;
  room_type_id?: string | null;
  adults?: number | null;
  children?: number | null;
  rooms?: number | null;
}

export interface ReservationTransitionIn {
  target_status: "checked_in" | "checked_out" | "cancelled" | "no_show";
  reason?: string;
  assigned_room_ids?: string[] | null;
}

export interface ReservationsListResp {
  reservations: StayReservationOut[];
  count: number;
  cursor: string | null;
}

export interface ReservationHistoryEntry {
  event_id: string;
  from_status: string;
  to_status: string;
  actor: string;
  reason: string;
  ts: number;
}

export interface ReservationHistoryResp {
  history: ReservationHistoryEntry[];
  count: number;
  cursor: string | null;
}

// ─── API wrappers ─────────────────────────────────────────────────────────────

/** POST /ui/hotel-search — read-only stay-search (any authenticated user) */
export const searchStays = (body: StaySearchIn) =>
  api.post<StaySearchResult>("/ui/hotel-search", body);

export interface HotelListRespBooking {
  /** Backend returns 'items' key (from app/services/hotel_pms.py list_hotels) */
  items: HotelOut[];
  count: number;
  cursor: string | null;
}

/** GET /ui/hotels — list hotels (for the hotel picker in booking) */
export const listHotelsForBooking = (params?: { status?: string; limit?: number }) => {
  const p: Record<string, string> = {};
  if (params?.status) p["status"] = params.status;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<HotelListRespBooking>("/ui/hotels", p);
};

/** GET /ui/hotels/{hotel_id} — single hotel detail */
export const getHotelForBooking = (hotelId: string) =>
  api.get<HotelOut>(`/ui/hotels/${hotelId}`);

/** POST /ui/hotels/{hotel_id}/reservations — create a reservation (ADMIN/ROOT) */
export const createReservation = (hotelId: string, body: ReservationCreateIn) =>
  api.post<StayReservationOut>(`/ui/hotels/${hotelId}/reservations`, body);

/** GET /ui/hotels/{hotel_id}/reservations — list reservations */
export const listReservations = (
  hotelId: string,
  params?: {
    status?: ReservationStatus;
    checkin_from?: string;
    checkin_to?: string;
    cursor?: string;
    limit?: number;
  },
) => {
  const p: Record<string, string> = {};
  if (params?.status) p["status"] = params.status;
  if (params?.checkin_from) p["checkin_from"] = params.checkin_from;
  if (params?.checkin_to) p["checkin_to"] = params.checkin_to;
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<ReservationsListResp>(`/ui/hotels/${hotelId}/reservations`, p);
};

/** GET /ui/hotels/{hotel_id}/reservations/{reservation_id} — single reservation */
export const getReservation = (hotelId: string, reservationId: string) =>
  api.get<StayReservationOut>(`/ui/hotels/${hotelId}/reservations/${reservationId}`);

/** GET /ui/hotels/{hotel_id}/reservations/{reservation_id}/history */
export const getReservationHistory = (hotelId: string, reservationId: string) =>
  api.get<ReservationHistoryResp>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/history`,
  );

/** PUT /ui/hotels/{hotel_id}/reservations/{reservation_id} — modify dates/room */
export const modifyReservation = (
  hotelId: string,
  reservationId: string,
  body: ReservationModifyIn,
) => api.put<StayReservationOut>(`/ui/hotels/${hotelId}/reservations/${reservationId}`, body);

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/cancel */
export const cancelReservation = (
  hotelId: string,
  reservationId: string,
  reason?: string,
) =>
  api.post<StayReservationOut>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/cancel`,
    { reason: reason ?? "" },
  );

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/no-show */
export const noShowReservation = (
  hotelId: string,
  reservationId: string,
  reason?: string,
) =>
  api.post<StayReservationOut>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/no-show`,
    { reason: reason ?? "" },
  );

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/confirm */
export const confirmReservation = (hotelId: string, reservationId: string) =>
  api.post<StayReservationOut>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/confirm`,
    {},
  );

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/check-in */
export const checkInReservation = (
  hotelId: string,
  reservationId: string,
  body: { assigned_room_ids: string[]; reason?: string },
) =>
  api.post<StayReservationOut>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/check-in`,
    body,
  );

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/check-out */
export const checkOutReservation = (
  hotelId: string,
  reservationId: string,
  reason?: string,
) =>
  api.post<StayReservationOut>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/check-out`,
    { reason: reason ?? "" },
  );
