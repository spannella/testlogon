import { api } from "@/api/client";
import type {
  PromoCodeOut,
  PromoCodeListOut,
  PromoCodeStatsOut,
  PromoValidateOut,
  PromoDeactivateOut,
} from "@/api/types";

// ─── Creator CRUD ──────────────────────────────────────────────────

export const createPromoCode = (body: {
  code: string;
  discount_type: "percentage" | "fixed_amount" | "free_trial";
  discount_value?: number;
  free_trial_days?: number;
  applies_to?: string[];
  min_purchase_cents?: number;
  max_uses?: number;
  max_uses_per_user?: number;
  expires_at?: number;
}) => api.post<PromoCodeOut>("/ui/promo-codes", body);

export const listPromoCodes = () =>
  api.get<PromoCodeListOut>("/ui/promo-codes");

export const getPromoCodeStats = (codeId: string) =>
  api.get<PromoCodeStatsOut>(`/ui/promo-codes/${codeId}`);

export const updatePromoCode = (
  codeId: string,
  body: { active?: boolean; expires_at?: number; max_uses?: number },
) => api.patch<PromoCodeOut>(`/ui/promo-codes/${codeId}`, body);

export const deletePromoCode = (codeId: string) =>
  api.del<PromoDeactivateOut>(`/ui/promo-codes/${codeId}`);

// ─── Validation ────────────────────────────────────────────────────

export const validatePromoCode = (body: {
  code: string;
  checkout_type: "subscription" | "vod" | "shop";
  item_price_cents: number;
  creator_user_id: string;
}) => api.post<PromoValidateOut>("/ui/promo-codes/validate", body);

// ─── Redemption ────────────────────────────────────────────────────

export const redeemPromoCode = (body: {
  code_id: string;
  original_price_cents: number;
  final_price_cents: number;
  checkout_type: string;
  checkout_item_id?: string;
}) => api.post<{ ok: boolean; redeemed_at: number }>("/ui/promo-codes/redeem", body);
