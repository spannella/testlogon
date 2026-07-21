import { api } from "@/api/client";

export interface EntitlementRequest {
  request_id: string;
  requester_sub: string;
  entitlement_kind: string;
  target_ref: string;
  justification: string;
  status: string;
  claimed_by_sub?: string | null;
  claimed_at?: number | null;
  decided_by_sub?: string | null;
  decided_at?: number | null;
  decision_reason?: string | null;
  created_at: number;
  updated_at?: number;
}

export interface EntitlementRequestHistoryRow {
  from_status?: string;
  to_status?: string;
  actor_sub?: string;
  reason?: string;
  created_at: number;
  event?: string;
}

export const listEntitlementRequestQueue = (status = "pending", limit = 50, cursor?: string) => {
  const params: Record<string, string> = { status, limit: String(limit) };
  if (cursor) params.cursor = cursor;
  return api.get<{ requests: EntitlementRequest[]; next_cursor: string | null }>(
    "/ui/admin/entitlement-requests",
    params,
  );
};

export const getEntitlementRequest = (id: string) =>
  api.get<EntitlementRequest>(`/ui/admin/entitlement-requests/${encodeURIComponent(id)}`);

export const getEntitlementRequestHistory = (id: string) =>
  api.get<EntitlementRequestHistoryRow[]>(
    `/ui/admin/entitlement-requests/${encodeURIComponent(id)}/history`,
  );

export const claimEntitlementRequest = (id: string) =>
  api.post<EntitlementRequest>(`/ui/admin/entitlement-requests/${encodeURIComponent(id)}/claim`);

export const approveEntitlementRequest = (id: string, reason: string) =>
  api.post<EntitlementRequest>(`/ui/admin/entitlement-requests/${encodeURIComponent(id)}/approve`, {
    reason,
  });

export const rejectEntitlementRequest = (id: string, reason: string) =>
  api.post<EntitlementRequest>(`/ui/admin/entitlement-requests/${encodeURIComponent(id)}/reject`, {
    reason,
  });
