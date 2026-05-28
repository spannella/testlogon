/**
 * VOD Purchase Tiers API endpoints (VOD-019).
 *
 * Provides purchase with type selection, playback complete reporting,
 * and entitlement status types.
 */

import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export type PurchaseType = "view_once" | "rental" | "permanent" | "download";

export interface EntitlementStatus {
  entitled: boolean;
  purchase_type: PurchaseType;
  views_remaining: number; // -1 = unlimited, 0 = consumed, 1+ = remaining
  expires_at?: number; // Unix timestamp, undefined = no expiry
  download_allowed: boolean;
  reason: string; // "valid" | "consumed" | "expired" | "not_purchased"
}

export interface VodPurchaseRequest {
  payment_method_id?: string;
  idempotency_key?: string;
  purchase_type: PurchaseType;
}

export interface VodPurchaseResponse {
  video_id: string;
  already_owned: boolean;
  granted_at: number;
  grant_type: string;
  amount_cents: number;
  purchase_id: string;
  purchase_type: PurchaseType;
  views_remaining: number;
  expires_at?: number;
  download_allowed: boolean;
}

export interface PlaybackCompleteResponse {
  ok: boolean;
  views_remaining: number;
  purchase_type: string;
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const purchaseVideo = (
  videoId: string,
  purchaseType: PurchaseType,
  paymentMethodId?: string,
) =>
  api.post<VodPurchaseResponse>(`/ui/videos/${videoId}/purchase`, {
    purchase_type: purchaseType,
    payment_method_id: paymentMethodId,
  });

export const reportPlaybackComplete = (videoId: string) =>
  api.post<PlaybackCompleteResponse>(
    `/ui/videos/${videoId}/playback-complete`,
    {},
  );
