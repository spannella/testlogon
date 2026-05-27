import { api } from "@/api/client";
import type {
  RefundRequestIn,
  RefundRequestOut,
  AdminRefundApproveIn,
  AdminRefundDenyIn,
} from "@/api/types";

// Customer endpoints
export const submitRefundRequest = (body: RefundRequestIn) =>
  api.post<RefundRequestOut>("/ui/billing/refund-requests", body);

export const listMyRefundRequests = (limit = 50) =>
  api.get<{ items: RefundRequestOut[] }>("/ui/billing/refund-requests", { limit: String(limit) });

export const getRefundRequest = (id: string) =>
  api.get<RefundRequestOut>(`/ui/billing/refund-requests/${id}`);

// Admin endpoints
export const adminListRefundRequests = (status = "pending", limit = 50) =>
  api.get<{ items: RefundRequestOut[] }>("/ui/admin/refund-requests", { status, limit: String(limit) });

export const adminApproveRefund = (id: string, body: AdminRefundApproveIn) =>
  api.post<{ ok: boolean; refund_request_id: string; status: string; approved_amount_cents: number }>(
    `/ui/admin/refund-requests/${id}/approve`,
    body,
  );

export const adminRejectRefund = (id: string, body: AdminRefundDenyIn) =>
  api.post<{ ok: boolean; refund_request_id: string; status: string }>(
    `/ui/admin/refund-requests/${id}/reject`,
    body,
  );
