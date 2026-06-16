/**
 * Leases API endpoint wrappers — LSE-001..LSE-004
 * Backend route prefix: /ui/leases  (cookie-session auth)
 * Flag: LEASES_ENABLED (default false → 404 on all endpoints)
 */

import { api } from "@/api/client";

// ─── Inline TypeScript types (mirrors app/models.py LSE models) ──────────────

export type LeaseStatus = "draft" | "upcoming" | "active" | "ended";
export type LateFeeType = "none" | "flat" | "percent";

export interface LeaseOut {
  lease_id: string;
  lease_number: string;
  user_sub: string;
  tenant_id: string;
  property_id: string;
  unit_id: string;
  status: LeaseStatus;
  start_date: number;           // Unix ts
  end_date: number | null;      // Unix ts, null = open-ended
  monthly_rent_cents: number;
  security_deposit_cents: number;
  rent_due_day: number;
  late_fee_type: LateFeeType;
  late_fee_cents: number;
  late_fee_percent_bps: number;
  late_fee_grace_days: number;
  currency: string;
  notes: string;
  renewal_notice_days: number;
  renewal_notified_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface LeaseListOut {
  leases: LeaseOut[];
  count: number;
  next_cursor: string | null;
}

export interface LeaseCreateIn {
  tenant_id: string;
  property_id: string;
  unit_id: string;
  start_date: number;
  end_date?: number | null;
  monthly_rent_cents: number;
  security_deposit_cents?: number;
  rent_due_day: number;
  late_fee_type?: LateFeeType;
  late_fee_cents?: number;
  late_fee_percent_bps?: number;
  late_fee_grace_days?: number;
  currency?: string;
  notes?: string;
  renewal_notice_days?: number;
  force_draft?: boolean;
}

export interface LeasePatchIn {
  end_date?: number | null;
  monthly_rent_cents?: number | null;
  security_deposit_cents?: number | null;
  rent_due_day?: number | null;
  late_fee_type?: LateFeeType | null;
  late_fee_cents?: number | null;
  late_fee_percent_bps?: number | null;
  late_fee_grace_days?: number | null;
  currency?: string | null;
  notes?: string | null;
  renewal_notice_days?: number | null;
}

// ─── Endpoint wrappers ────────────────────────────────────────────────────────

/** Create a new lease (LSE-002). Returns 404 when feature flag is off. */
export const createLease = (body: LeaseCreateIn): Promise<LeaseOut> =>
  api.post<LeaseOut>("/ui/leases", body);

/** List all leases for the authenticated user, with optional status filter (LSE-002). */
export const listLeases = (opts?: {
  status?: LeaseStatus;
  limit?: number;
  cursor?: string;
}): Promise<LeaseListOut> => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<LeaseListOut>("/ui/leases", params);
};

/** Get a single lease by ID (LSE-002). */
export const getLease = (leaseId: string): Promise<LeaseOut> =>
  api.get<LeaseOut>(`/ui/leases/${leaseId}`);

/** Partially update mutable fields on a lease (LSE-002). */
export const patchLease = (leaseId: string, body: LeasePatchIn): Promise<LeaseOut> =>
  api.patch<LeaseOut>(`/ui/leases/${leaseId}`, body);

/** Transition a lease's status (LSE-002). */
export const transitionLeaseStatus = (leaseId: string, status: string): Promise<LeaseOut> =>
  api.post<LeaseOut>(`/ui/leases/${leaseId}/status`, { status });

/** List leases expiring within N days (LSE-003). */
export const listExpiringLeases = (opts?: {
  within_days?: number;
  limit?: number;
}): Promise<LeaseListOut> => {
  const params: Record<string, string> = {};
  if (opts?.within_days) params["within_days"] = String(opts.within_days);
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<LeaseListOut>("/ui/leases/expiring", params);
};

/** List all leases for a specific tenant (LSE-003). */
export const listTenantLeases = (
  tenantId: string,
  opts?: { limit?: number; cursor?: string },
): Promise<LeaseListOut> => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<LeaseListOut>(`/ui/tenants/${tenantId}/leases`, params);
};

/** Admin: list all leases across all owners (LSE-002). */
export const adminListLeases = (opts?: {
  limit?: number;
  cursor?: string;
}): Promise<LeaseListOut> => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<LeaseListOut>("/ui/admin/leases", params);
};
