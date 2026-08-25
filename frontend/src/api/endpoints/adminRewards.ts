import { api } from "@/api/client";
import type { RewardKind } from "@/api/endpoints/rewards";

/**
 * REWARDS CATALOG ADMIN (`/admin/rewards/catalog*`).
 *
 * Operator/admin CRUD over the redeemable rewards catalog that users see on the
 * Rewards surface (`GET /me/rewards/catalog`). The admin item is the user-facing
 * catalog reward PLUS an `active` flag (deactivated items are hidden from users)
 * and an optional `redeemed_count` metric.
 *
 * CONVENTIONS: every monetary amount is INTEGER CENTS; `cost_points` is a whole
 * integer. These endpoints do NOT exist on the backend yet: the LIST read
 * degrades on 404/absent to an honest "not available" empty state (callers use
 * `retry:false`), and every mutation surfaces a clear error toast on failure —
 * it never silently "succeeds".
 */

/** A catalog reward as seen by the operator (adds `active` + optional metric). */
export interface AdminCatalogItem {
  id: string;
  name: string;
  description: string;
  cost_points: number;
  value_cents: number;
  kind: RewardKind;
  active: boolean;
  redeemed_count?: number;
  /** Optional inventory cap. null/absent = UNLIMITED (back-compat default). */
  stock_limit?: number | null;
  /** Featured items sort first + get a badge for users. Absent/false = no. */
  featured?: boolean;
  /** Sort weight (asc) after featured, before name. Absent = 0. */
  sort_order?: number;
}

export interface AdminCatalogList {
  rewards: AdminCatalogItem[];
}

/** Write payload for create/update (server assigns the id + redeemed_count). */
export interface AdminCatalogInput {
  name: string;
  description: string;
  cost_points: number;
  value_cents: number;
  kind: RewardKind;
  active: boolean;
  /** Optional inventory cap. null = UNLIMITED (blank field in the form). */
  stock_limit?: number | null;
  /** Featured items sort first + get a badge for users. Default false. */
  featured?: boolean;
  /** Sort weight (asc) after featured, before name. Default 0. */
  sort_order?: number;
}

// ── Read (degrade on 404 — caller uses retry:false) ──────────────────

export const listAdminRewardsCatalog = () =>
  api.get<AdminCatalogList>("/admin/rewards/catalog");

// ── Mutations (clear error on failure — never silent) ────────────────

export const createAdminRewardsCatalogItem = (input: AdminCatalogInput) =>
  api.post<AdminCatalogItem>("/admin/rewards/catalog", input);

export const updateAdminRewardsCatalogItem = (id: string, input: AdminCatalogInput) =>
  api.put<AdminCatalogItem>(`/admin/rewards/catalog/${id}`, input);

export const deleteAdminRewardsCatalogItem = (id: string) =>
  api.del<{ ok: boolean }>(`/admin/rewards/catalog/${id}`);
