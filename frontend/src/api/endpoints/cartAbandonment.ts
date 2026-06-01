import { api } from "@/api/client";
import type {
  CartAbandonmentStats,
  CartAbandonmentStatus,
  CartAbandonmentSweepResult,
} from "@/api/types";

// ─── Cart Abandonment (SHOP-003) ────────────────────────────────────

// Buyer-facing: abandonment status for one of the caller's own carts.
export const getCartAbandonmentStatus = (cartId: string) =>
  api.get<CartAbandonmentStatus>(
    `/ui/shoppingcart/carts/${cartId}/abandonment-status`,
  );

// Admin/root: aggregate abandonment metrics.
export const getCartAbandonmentStats = () =>
  api.get<CartAbandonmentStats>("/ui/shoppingcart/admin/cart-abandonment/stats");

// Admin/root: run an abandonment sweep manually. `now` is injectable for tests.
export const runCartAbandonmentSweep = (body?: {
  threshold_hours?: number;
  now?: number;
  expire?: boolean;
  expire_hours?: number;
}) =>
  api.post<CartAbandonmentSweepResult>(
    "/ui/shoppingcart/admin/cart-abandonment/scan",
    body ?? {},
  );
