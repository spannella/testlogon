import { api } from "@/api/client";
import type {
  DataRequest,
  DataRequestListResp,
  DeleteAccountBody,
  ExportRequestBody,
} from "@/api/types";

// ─── User Endpoints ─────────────────────────────────────────────

export const requestExport = (body: ExportRequestBody) =>
  api.post<DataRequest>("/ui/privacy/export", body);

export const getPrivacyRequests = () =>
  api.get<DataRequestListResp>("/ui/privacy/requests");

export const getRequestStatus = (requestId: string) =>
  api.get<DataRequest>(`/ui/privacy/requests/${requestId}`);

export const getExportDownloadUrl = (requestId: string) =>
  `/ui/privacy/export/${requestId}/download`;

export const requestDeletion = (body: DeleteAccountBody) =>
  api.post<DataRequest>("/ui/privacy/delete-account", body);

export const cancelDeletion = (requestId: string) =>
  api.post<DataRequest>(`/ui/privacy/requests/${requestId}/cancel`);

// ─── Admin Endpoints ────────────────────────────────────────────

export const getAdminPrivacyRequests = (params?: {
  status?: string;
  request_type?: string;
  limit?: number;
}) => {
  const p: Record<string, string> = {};
  if (params?.status) p.status = params.status;
  if (params?.request_type) p.request_type = params.request_type;
  if (params?.limit) p.limit = String(params.limit);
  return api.get<DataRequestListResp>("/ui/admin/privacy/requests", p);
};

export const adminApproveRequest = (requestId: string) =>
  api.post<DataRequest>(`/ui/admin/privacy/requests/${requestId}/approve`);

export const adminRejectRequest = (requestId: string) =>
  api.post<DataRequest>(`/ui/admin/privacy/requests/${requestId}/reject`);

export const adminHoldRequest = (requestId: string) =>
  api.post<DataRequest>(`/ui/admin/privacy/requests/${requestId}/hold`);

export const adminReleaseHold = (requestId: string) =>
  api.post<DataRequest>(`/ui/admin/privacy/requests/${requestId}/release-hold`);
