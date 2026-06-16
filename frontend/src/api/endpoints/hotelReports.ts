/**
 * Hotel Reports API endpoints — HTL-034 (Cancellation Policy) + HTL-035 (KPI Reports).
 *
 * All paths are under /ui/hotels (mounted on the Vite proxy to backend).
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404 when off.
 *
 * Inline TS types mirror app/models.py CancellationPolicyIn/Out and HotelKpisOut.
 *
 * NOTE: The canonical CRUD wrappers for hotels (listHotels, getHotel …) live in
 * hotelSetup.ts. This file deliberately re-exports only the types and functions
 * needed for the policy + reports area, keeping each area's dependencies isolated.
 */

import { api } from "@/api/client";

// ─── Cancellation Policy types ────────────────────────────────────────────────

export interface CancellationPolicyIn {
  /** Days before check-in within which cancellation is free. 0 = no free window. */
  free_until_days_before: number;
  /** Percentage penalty applied to reservation total (0..100). */
  penalty_pct: number;
  /** Fixed penalty in integer cents (mutually-exclusive with pct, but backend accepts both). */
  penalty_fixed_cents: number;
  /** No-show fee charged when guest never arrives, in integer cents. */
  no_show_fee_cents: number;
}

export interface CancellationPolicyOut {
  hotel_id: string;
  policy_id: string;
  scope: string;
  free_until_days_before: number;
  penalty_pct: number;
  penalty_fixed_cents: number;
  no_show_fee_cents: number;
  created_at: number;
  updated_at: number;
}

// ─── Hotel KPIs types ─────────────────────────────────────────────────────────

export interface HotelKpisOut {
  hotel_id: string;
  from_ts: number;
  to_ts: number;
  rooms_available: number;
  rooms_sold: number;
  occupancy_pct: number;
  room_revenue_cents: number;
  adr_cents: number;
  revpar_cents: number;
  arrivals: number;
  departures: number;
  currency: string;
}

// ─── Cancellation Policy endpoints ───────────────────────────────────────────

/**
 * GET /ui/hotels/{hotel_id}/cancellation-policy
 *
 * Returns 404 when:
 * - HOTEL_PMS_ENABLED is off (feature flag)
 * - No policy has been saved for this hotel+scope yet
 */
export const getCancellationPolicy = (hotelId: string, scope = "default") =>
  api.get<CancellationPolicyOut>(
    `/ui/hotels/${hotelId}/cancellation-policy`,
    { scope },
  );

/**
 * PUT /ui/hotels/{hotel_id}/cancellation-policy
 *
 * Upserts the cancellation policy for (hotel, scope).
 * Requires ADMIN or ROOT session + CSRF.
 * Query param: scope (default = "default").
 */
export const upsertCancellationPolicy = (
  hotelId: string,
  body: CancellationPolicyIn,
  scope = "default",
) =>
  api.put<CancellationPolicyOut>(
    `/ui/hotels/${hotelId}/cancellation-policy?scope=${encodeURIComponent(scope)}`,
    body,
  );

// ─── KPI Report endpoint ──────────────────────────────────────────────────────

/**
 * GET /ui/hotels/{hotel_id}/reports/kpis
 *
 * Aggregates occupancy / ADR / RevPAR for the given UTC timestamp range.
 * from_ts and to_ts are Unix epoch seconds (integer).
 * Returns 422 when to_ts <= from_ts or range > 366 days.
 */
export const getHotelKpis = (hotelId: string, fromTs: number, toTs: number) =>
  api.get<HotelKpisOut>(
    `/ui/hotels/${hotelId}/reports/kpis`,
    { from_ts: String(fromTs), to_ts: String(toTs) },
  );
