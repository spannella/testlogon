/**
 * Hotel Guest Folio API endpoints (QloApps PMS vertical, HTL-029..HTL-031).
 *
 * All money values are integer cents. HOTEL_PMS_ENABLED flag is OFF by default;
 * when off the backend returns 404 — callers should handle ApiError.status === 404
 * gracefully with a "not enabled" state (retry: false).
 *
 * Types are defined inline here (not in shared api/types.ts) per project conventions.
 *
 * Base prefix: /ui/hotels/{hotel_id}/reservations/{rid}/folio
 */

import { api } from "@/api/client";

// ─── Domain types ─────────────────────────────────────────────────────────────

export type FolioLineType = "room_night" | "addon" | "tax" | "fee";

export type FolioStatus = "open" | "closed";

export type DepositPolicyKind = "none" | "pct" | "fixed";

export type FolioPaymentMethod =
  | "wallet"
  | "card_external"
  | "cash"
  | "check"
  | "bank_transfer"
  | "deposit_applied";

export interface FolioLineOut {
  line_id: string;
  line_type: FolioLineType;
  description: string;
  quantity: number;
  unit_price_cents: number;
  amount_cents: number;
  sku: string;
  created_at: number; // Unix seconds
}

export interface FolioOut {
  reservation_id: string;
  folio_id: string;
  hotel_id: string;
  guest_sub: string;
  currency: string;
  status: FolioStatus;
  charges_total_cents: number;
  payments_total_cents: number;
  deposit_held_cents: number;
  deposit_policy_kind: DepositPolicyKind;
  deposit_pct_bps: number;
  deposit_fixed_cents: number;
  balance_due_cents: number;
  balance_due_on_arrival_cents: number;
  line_items: FolioLineOut[];
  closed_at: number | null;
  created_at: number; // Unix seconds
  updated_at: number; // Unix seconds
}

// ─── Request bodies ───────────────────────────────────────────────────────────

export interface FolioLineIn {
  line_type: FolioLineType;
  description: string;
  quantity?: number;
  unit_price_cents: number;
  sku?: string;
}

export interface FolioAddonIn {
  sku: string;
  quantity?: number;
}

export interface DepositPolicyIn {
  kind: DepositPolicyKind;
  pct_bps?: number;
  fixed_cents?: number;
}

export interface TakeDepositIn {
  amount_cents?: number;
}

export interface FolioPaymentIn {
  amount_cents: number;
  method: FolioPaymentMethod;
  reference?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function folioBase(hotelId: string, rid: string): string {
  return `/ui/hotels/${hotelId}/reservations/${rid}/folio`;
}

// ─── API functions ────────────────────────────────────────────────────────────

/**
 * GET the folio for a reservation. Auto-opens it on first read (idempotent).
 * Accessible to the guest (session auth) and admins.
 */
export const getFolio = (hotelId: string, rid: string) =>
  api.get<FolioOut>(folioBase(hotelId, rid));

/**
 * POST /folio/open — explicitly open/seed the folio (admin only, idempotent).
 */
export const openFolio = (hotelId: string, rid: string) =>
  api.post<FolioOut>(`${folioBase(hotelId, rid)}/open`);

/**
 * POST /folio/lines — add an arbitrary charge line to the folio (admin only).
 */
export const addFolioLine = (hotelId: string, rid: string, body: FolioLineIn) =>
  api.post<FolioOut>(`${folioBase(hotelId, rid)}/lines`, body);

/**
 * POST /folio/addons — attach a catalog add-on SKU (admin only).
 * Price is resolved server-side from the catalog (anti-tamper).
 */
export const addFolioAddon = (hotelId: string, rid: string, body: FolioAddonIn) =>
  api.post<FolioOut>(`${folioBase(hotelId, rid)}/addons`, body);

/**
 * POST /folio/deposit-policy — set or update the deposit policy (admin only).
 */
export const setFolioDepositPolicy = (
  hotelId: string,
  rid: string,
  body: DepositPolicyIn,
) => api.post<FolioOut>(`${folioBase(hotelId, rid)}/deposit-policy`, body);

/**
 * POST /folio/deposit — hold a deposit against the guest's wallet (admin only).
 * Idempotent: second call → 409 "Deposit already held".
 */
export const takeFolioDeposit = (
  hotelId: string,
  rid: string,
  body: TakeDepositIn,
) => api.post<FolioOut>(`${folioBase(hotelId, rid)}/deposit`, body);

/**
 * POST /folio/payments — record a payment against the folio (admin only).
 * method="wallet" deducts from guest wallet; other methods are informational.
 */
export const recordFolioPayment = (
  hotelId: string,
  rid: string,
  body: FolioPaymentIn,
) => api.post<FolioOut>(`${folioBase(hotelId, rid)}/payments`, body);

/**
 * POST /folio/close — close an open folio (admin only, idempotent).
 */
export const closeFolio = (hotelId: string, rid: string) =>
  api.post<FolioOut>(`${folioBase(hotelId, rid)}/close`);

/**
 * GET /folio/pdf — download folio PDF.
 * Returns the binary URL to fetch (application/pdf).
 */
export function folioPdfUrl(hotelId: string, rid: string): string {
  return `/ui/hotels/${hotelId}/reservations/${rid}/folio/pdf`;
}
