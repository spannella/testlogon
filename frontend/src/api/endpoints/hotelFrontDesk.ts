/**
 * Hotel Front-Desk API endpoints (QloApps HTL-022..HTL-024).
 *
 * All paths are under /ui/hotels/{hotel_id}/front-desk/...
 * proxied to the backend by Vite (already covered by /ui proxy rule).
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404 when off.
 * Handle gracefully with ApiError.status === 404.
 *
 * Inline TS types mirror:
 *   app/models.py: FrontDeskRow, FrontDeskListOut, OccupancySnapshotOut,
 *                  WalkInBookingIn, AssignRoomIn, RoomMoveIn, FrontDeskActionOut
 *
 * NOTE: ReservationStatus is duplicated here (not imported from hotelBooking.ts)
 * so each area file is self-contained per shared-tree rules.
 */

import { api } from "@/api/client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type FrontDeskStatus =
  | "confirmed"
  | "checked_in"
  | "checked_out"
  | "cancelled"
  | "no_show";

/** One reservation row as projected for the front-desk console (HTL-022). */
export interface FrontDeskRow {
  reservation_id: string;
  hotel_id: string;
  room_type_id: string;
  guest_name: string;
  guest_sub: string;
  checkin: string;       // "YYYY-MM-DD"
  checkout: string;      // "YYYY-MM-DD"
  status: FrontDeskStatus;
  nights: number;
  occupancy_adults: number;
  occupancy_children: number;
  assigned_room_ids: string[];
  total_cents: number;
}

/** Paginated list envelope returned by arrivals / departures / in-house queries. */
export interface FrontDeskListOut {
  rows: FrontDeskRow[];
  count: number;
  cursor: string | null;
}

/** Live occupancy snapshot for a hotel on a given date (HTL-022). */
export interface OccupancySnapshotOut {
  hotel_id: string;
  date: string;          // "YYYY-MM-DD"
  rooms_total: number;
  rooms_occupied: number;
  rooms_available: number;
  rooms_out_of_service: number;
  occupancy_rate: number; // 0.0..1.0
  arrivals_count: number;
  departures_count: number;
  in_house_count: number;
}

/** Walk-in booking request body (HTL-023). */
export interface WalkInBookingIn {
  room_type_id: string;
  checkin: string;         // "YYYY-MM-DD"
  checkout: string;        // "YYYY-MM-DD"
  occupancy_adults?: number;
  occupancy_children?: number;
  guest_name: string;
  guest_sub?: string | null;
  assigned_room_ids?: string[] | null;
  total_cents?: number | null;
}

/** Assign / change-room request body (HTL-023). */
export interface AssignRoomIn {
  assigned_room_ids: string[];
  version: number;
}

/** Room-move request body (HTL-023): swap one room for another on a checked-in stay. */
export interface RoomMoveIn {
  from_room_id: string;
  to_room_id: string;
  version: number;
}

/** Action response: updated reservation row + affected room rows (HTL-023). */
export interface FrontDeskActionOut {
  reservation: FrontDeskRow;
  affected_rooms: Record<string, unknown>[];
}

// ─── Read endpoints (any authenticated user) ──────────────────────────────────

/**
 * GET /ui/hotels/{hotel_id}/front-desk/arrivals
 * Today's confirmed arrivals (or a specific date via ?date=YYYY-MM-DD).
 */
export const getFrontDeskArrivals = (
  hotelId: string,
  params?: { date?: string; cursor?: string; limit?: number },
) => {
  const p: Record<string, string> = {};
  if (params?.date) p["date"] = params.date;
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<FrontDeskListOut>(
    `/ui/hotels/${hotelId}/front-desk/arrivals`,
    p,
  );
};

/**
 * GET /ui/hotels/{hotel_id}/front-desk/departures
 * Today's checked-in guests departing (or a specific date via ?date=YYYY-MM-DD).
 */
export const getFrontDeskDepartures = (
  hotelId: string,
  params?: { date?: string; cursor?: string; limit?: number },
) => {
  const p: Record<string, string> = {};
  if (params?.date) p["date"] = params.date;
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<FrontDeskListOut>(
    `/ui/hotels/${hotelId}/front-desk/departures`,
    p,
  );
};

/**
 * GET /ui/hotels/{hotel_id}/front-desk/in-house
 * All currently checked-in reservations.
 */
export const getFrontDeskInHouse = (
  hotelId: string,
  params?: { cursor?: string; limit?: number },
) => {
  const p: Record<string, string> = {};
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<FrontDeskListOut>(
    `/ui/hotels/${hotelId}/front-desk/in-house`,
    p,
  );
};

/**
 * GET /ui/hotels/{hotel_id}/front-desk/occupancy
 * Live occupancy snapshot (optionally scoped to a specific ?date=YYYY-MM-DD).
 */
export const getFrontDeskOccupancy = (
  hotelId: string,
  params?: { date?: string },
) => {
  const p: Record<string, string> = {};
  if (params?.date) p["date"] = params.date;
  return api.get<OccupancySnapshotOut>(
    `/ui/hotels/${hotelId}/front-desk/occupancy`,
    p,
  );
};

// ─── Write endpoints (ADMIN | ROOT + CSRF) ────────────────────────────────────

/**
 * POST /ui/hotels/{hotel_id}/front-desk/walk-in
 * Create a walk-in reservation and immediately check it in (HTL-023).
 */
export const postWalkIn = (hotelId: string, body: WalkInBookingIn) =>
  api.post<FrontDeskActionOut>(
    `/ui/hotels/${hotelId}/front-desk/walk-in`,
    body,
  );

/**
 * POST /ui/hotels/{hotel_id}/front-desk/reservations/{reservation_id}/assign-room
 * Set physical room(s) on a confirmed (not yet checked-in) reservation (HTL-023).
 */
export const assignRoom = (
  hotelId: string,
  reservationId: string,
  body: AssignRoomIn,
) =>
  api.post<FrontDeskActionOut>(
    `/ui/hotels/${hotelId}/front-desk/reservations/${reservationId}/assign-room`,
    body,
  );

/**
 * POST /ui/hotels/{hotel_id}/front-desk/reservations/{reservation_id}/change-room
 * Swap the room assignment set on a reservation (HTL-023).
 */
export const changeRoom = (
  hotelId: string,
  reservationId: string,
  body: AssignRoomIn,
) =>
  api.post<FrontDeskActionOut>(
    `/ui/hotels/${hotelId}/front-desk/reservations/${reservationId}/change-room`,
    body,
  );

/**
 * POST /ui/hotels/{hotel_id}/front-desk/reservations/{reservation_id}/room-move
 * Relocate a checked-in guest from one room to another (HTL-023).
 */
export const roomMove = (
  hotelId: string,
  reservationId: string,
  body: RoomMoveIn,
) =>
  api.post<FrontDeskActionOut>(
    `/ui/hotels/${hotelId}/front-desk/reservations/${reservationId}/room-move`,
    body,
  );

// ─── Also re-export the check-in / check-out endpoints needed by the front desk ─
// (The router lives in hotel_reservations.py; paths are /ui/hotels/{id}/reservations/...)
// These are duplicated here per shared-tree rules (no cross-area imports).

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/check-in */
export const frontDeskCheckIn = (
  hotelId: string,
  reservationId: string,
  body: { assigned_room_ids: string[]; reason?: string },
) =>
  api.post<FrontDeskRow>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/check-in`,
    body,
  );

/** POST /ui/hotels/{hotel_id}/reservations/{reservation_id}/check-out */
export const frontDeskCheckOut = (
  hotelId: string,
  reservationId: string,
  reason?: string,
) =>
  api.post<FrontDeskRow>(
    `/ui/hotels/${hotelId}/reservations/${reservationId}/check-out`,
    { reason: reason ?? "" },
  );
