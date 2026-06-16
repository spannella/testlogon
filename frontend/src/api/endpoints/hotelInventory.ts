/**
 * Hotel Availability + Rate Plans API endpoints (QloApps vertical, HTL-012..HTL-016).
 *
 * All money values are integer cents. HOTEL_PMS_ENABLED flag is OFF by default;
 * when off the backend returns 404 — callers should handle ApiError.status === 404
 * gracefully with a "not enabled" state (retry: false).
 *
 * Types are defined inline here (not in shared api/types.ts) per project conventions.
 */

import { api } from "@/api/client";

// ─── Domain types ─────────────────────────────────────────────────────────────

export interface AvailabilityDayOut {
  hotel_id: string;
  room_type_id: string;
  date: string; // YYYY-MM-DD
  total_rooms: number;
  booked: number;
  held: number;
  overbooking_allowance: number;
  min_availability: number;
  max_availability: number | null;
  available: number; // derived: total_rooms + overbooking_allowance - booked - held
  updated_at: number; // Unix seconds
}

export interface HoldOut {
  hold_id: string;
  hotel_id: string;
  room_type_id: string;
  checkin: string; // YYYY-MM-DD inclusive
  checkout: string; // YYYY-MM-DD exclusive
  dates: string[]; // each night touched
  quantity: number;
  status: "active" | "released" | "expired";
  user_sub: string;
  created_at: number;
  expires_at: number;
}

export interface AvailabilityCalendarResp {
  hotel_id: string;
  start_date: string;
  end_date: string;
  room_types: Record<string, AvailabilityDayOut[]>; // room_type_id → per-date rows
}

export interface AvailabilityCheckResp {
  available: boolean;
  rooms_needed: number;
  per_night: Array<{ date: string; remaining: number; sufficient: boolean }>;
  min_remaining: number;
}

export interface RatePlanOut {
  rate_plan_id: string;
  hotel_id: string;
  room_type_id: string;
  name: string;
  base_nightly_rate_cents: number;
  base_occupancy: number;
  currency: string;
  active: boolean;
  created_at: number;
  updated_at: number;
  created_by: string;
}

export interface RatePlanListResp {
  rate_plans: RatePlanOut[];
  count: number;
  cursor: string | null;
}

export interface RatePlanRuleOut {
  rule_id: string;
  kind: "season" | "occupancy" | "los" | "advance" | "weekend";
  rule_config: Record<string, unknown>;
  priority: number;
  created_at: number;
  updated_at: number;
  created_by: string;
}

// ── Rule config shapes per kind ──────────────────────────────────────────────

export interface SeasonRuleConfig {
  start_date: string;
  end_date: string;
  mode: "absolute" | "delta";
  value_cents: number;
}

export interface OccupancyRuleConfig {
  extra_adult_cents: number;
  extra_child_cents: number;
}

export interface LosRuleConfig {
  min_nights: number;
  max_nights: number | null;
  discount_type: "percentage" | "fixed_cents";
  discount_value: number;
}

export interface AdvanceRuleConfig {
  days_before_checkin: number;
  comparator: "gte" | "lte";
  mode: "percentage" | "fixed_cents";
  value: number;
}

export interface WeekendRuleConfig {
  dow: number[]; // ISO weekday: Mon=1..Sun=7
  mode: "absolute" | "delta";
  value_cents: number;
}

export interface NightLineOut {
  date: string;
  base_cents: number;
  season_delta_cents: number;
  weekend_delta_cents: number;
  occupancy_cents: number;
  night_total_cents: number;
}

export interface StayQuoteOut {
  nights: number;
  per_night: NightLineOut[];
  stay_subtotal_cents: number;
  los_discount_cents: number;
  advance_modifier_cents: number; // signed: negative = discount
  rooms: number;
  total_cents: number;
  currency: string;
  applied_rule_ids: string[];
}

// ─── Availability endpoints ────────────────────────────────────────────────────

/** Hotel-wide availability calendar across ALL room types for a date range. */
export const getAvailabilityCalendar = (
  hotelId: string,
  startDate: string,
  endDate: string,
) =>
  api.get<AvailabilityCalendarResp>(
    `/ui/hotels/${hotelId}/availability/calendar`,
    { start_date: startDate, end_date: endDate },
  );

/** Per-night availability rows for a stay span [checkin, checkout). */
export const getRoomTypeAvailability = (
  hotelId: string,
  roomTypeId: string,
  checkin: string,
  checkout: string,
) =>
  api.get<AvailabilityDayOut[]>(
    `/ui/hotels/${hotelId}/availability/${roomTypeId}`,
    { checkin, checkout },
  );

/** Booking-time span-intersection availability check. */
export const checkAvailability = (
  hotelId: string,
  roomTypeId: string,
  checkin: string,
  checkout: string,
  roomsNeeded = 1,
) =>
  api.get<AvailabilityCheckResp>(
    `/ui/hotels/${hotelId}/availability/check`,
    {
      room_type_id: roomTypeId,
      checkin,
      checkout,
      rooms_needed: String(roomsNeeded),
    },
  );

/** Seed / set total_rooms per date over a range. (Admin) */
export const setTotalRooms = (
  hotelId: string,
  roomTypeId: string,
  body: { hotel_id: string; room_type_id: string; start_date: string; end_date: string; total_rooms: number },
) =>
  api.put<AvailabilityDayOut[]>(
    `/ui/hotels/${hotelId}/availability/${roomTypeId}/total-rooms`,
    body,
  );

/** Hold rooms across all nights of a stay. (Admin) */
export const holdRooms = (
  hotelId: string,
  roomTypeId: string,
  body: {
    hotel_id: string;
    room_type_id: string;
    checkin: string;
    checkout: string;
    quantity: number;
    ttl_seconds?: number;
  },
) =>
  api.post<HoldOut>(
    `/ui/hotels/${hotelId}/availability/${roomTypeId}/hold`,
    body,
  );

/** Release an active hold. (Admin) */
export const releaseHold = (hotelId: string, holdId: string) =>
  api.post<HoldOut>(
    `/ui/hotels/${hotelId}/availability/holds/${holdId}/release`,
    {},
  );

/** Set overbooking allowance per date range. (Admin) */
export const setOverbooking = (
  hotelId: string,
  roomTypeId: string,
  body: { hotel_id: string; room_type_id: string; start_date: string; end_date: string; allowance: number },
) =>
  api.put<AvailabilityDayOut[]>(
    `/ui/hotels/${hotelId}/availability/${roomTypeId}/overbooking`,
    body,
  );

/** Set min/max availability per date range. (Admin) */
export const setMinMax = (
  hotelId: string,
  roomTypeId: string,
  body: {
    hotel_id: string;
    room_type_id: string;
    start_date: string;
    end_date: string;
    min_availability?: number;
    max_availability?: number;
  },
) =>
  api.put<AvailabilityDayOut[]>(
    `/ui/hotels/${hotelId}/availability/${roomTypeId}/min-max`,
    body,
  );

// ─── Rate plan endpoints ───────────────────────────────────────────────────────

/** List rate plans for a hotel. */
export const listRatePlans = (
  hotelId: string,
  opts?: { cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<RatePlanListResp>(`/ui/hotels/${hotelId}/rate-plans`, params);
};

/** Create a rate plan for a hotel/room-type. (Admin) */
export const createRatePlan = (
  hotelId: string,
  body: {
    room_type_id: string;
    name: string;
    base_nightly_rate_cents?: number;
    base_occupancy?: number;
    currency?: string;
  },
) =>
  api.post<RatePlanOut>(`/ui/hotels/${hotelId}/rate-plans`, body);

/** Get the rate plan for a specific room type. */
export const getRatePlan = (hotelId: string, roomTypeId: string) =>
  api.get<RatePlanOut>(`/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan`);

/** Update a rate plan. (Admin) */
export const updateRatePlan = (
  hotelId: string,
  roomTypeId: string,
  body: {
    name?: string;
    base_nightly_rate_cents?: number;
    base_occupancy?: number;
    currency?: string;
    active?: boolean;
  },
) =>
  api.put<RatePlanOut>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan`,
    body,
  );

/** Soft-deactivate a rate plan. (Admin) */
export const deactivateRatePlan = (hotelId: string, roomTypeId: string) =>
  api.del<RatePlanOut>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan`,
  );

/** List all rules for a rate plan. */
export const listRules = (hotelId: string, roomTypeId: string) =>
  api.get<RatePlanRuleOut[]>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan/rules`,
  );

/** Add a rule to a rate plan. (Admin) */
export const addRule = (
  hotelId: string,
  roomTypeId: string,
  body: {
    kind: "season" | "occupancy" | "los" | "advance" | "weekend";
    rule_config: Record<string, unknown>;
    priority?: number;
  },
) =>
  api.post<RatePlanRuleOut>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan/rules`,
    body,
  );

/** Update a rule. (Admin) */
export const updateRule = (
  hotelId: string,
  roomTypeId: string,
  ruleId: string,
  body: {
    kind: "season" | "occupancy" | "los" | "advance" | "weekend";
    rule_config: Record<string, unknown>;
    priority?: number;
  },
) =>
  api.put<RatePlanRuleOut>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan/rules/${ruleId}`,
    body,
  );

/** Delete a rule. (Admin) */
export const deleteRule = (
  hotelId: string,
  roomTypeId: string,
  ruleId: string,
  kind: string,
) =>
  api.del<{ ok: boolean }>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/rate-plan/rules/${ruleId}`,
    { kind },
  );

/** Compute a multi-night price quote for a stay. */
export const quoteStay = (
  hotelId: string,
  roomTypeId: string,
  body: {
    checkin: string;
    checkout: string;
    adults: number;
    children?: number;
    rooms?: number;
    advance_days?: number;
  },
) =>
  api.post<StayQuoteOut>(
    `/ui/hotels/${hotelId}/room-types/${roomTypeId}/quote`,
    body,
  );
