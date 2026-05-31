import { api } from "@/api/client";
import type {
  AccountDeletionAuditTrail,
  AccountDeletionCancelResp,
  AccountDeletionListResp,
  AccountDeletionRequestBody,
  AccountDeletionRetentionHoldBody,
  AccountDeletionStatus,
  PrivacyExportRequestBody,
  PrivacyExportStatus,
} from "@/api/types";

const BASE = "/ui/privacy/account-deletion";
const ADMIN = "/ui/admin/privacy/account-deletion";

// ─── User ───────────────────────────────────────────────────────

export const requestAccountDeletion = (body: AccountDeletionRequestBody) =>
  api.post<AccountDeletionStatus>(`${BASE}/request`, body);

export const listAccountDeletions = () =>
  api.get<AccountDeletionListResp>(`${BASE}/requests`);

export const getAccountDeletion = (requestId: string) =>
  api.get<AccountDeletionStatus>(`${BASE}/requests/${requestId}`);

export const cancelAccountDeletion = (requestId: string) =>
  api.post<AccountDeletionCancelResp>(`${BASE}/requests/${requestId}/cancel`);

export const requestPrivacyExport = (body: PrivacyExportRequestBody) =>
  api.post<PrivacyExportStatus>(`${BASE}/export`, body);

export const getPrivacyExport = (requestId: string) =>
  api.get<PrivacyExportStatus>(`${BASE}/export/${requestId}`);

export const privacyExportDownloadUrl = (requestId: string) =>
  `${BASE}/export/${requestId}/download`;

// ─── Admin ──────────────────────────────────────────────────────

export const adminListAccountDeletions = (status = "pending", limit = 50) =>
  api.get<AccountDeletionListResp>(`${ADMIN}/requests`, {
    status,
    limit: String(limit),
  });

export const adminAccountDeletionAudit = (requestId: string) =>
  api.get<AccountDeletionAuditTrail>(`${ADMIN}/requests/${requestId}/audit`);

export const adminPlaceRetentionHold = (
  requestId: string,
  body: AccountDeletionRetentionHoldBody,
) => api.post(`${ADMIN}/requests/${requestId}/hold`, body);

export const adminReleaseRetentionHold = (requestId: string) =>
  api.post(`${ADMIN}/requests/${requestId}/release-hold`);

export const adminProcessDueDeletions = () =>
  api.post(`${ADMIN}/process-due`);
