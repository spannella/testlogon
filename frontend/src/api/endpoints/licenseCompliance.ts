import { api } from "@/api/client";
import type {
  AdminComplianceIssueListOut,
  ComplianceCheckResultOut,
  ComplianceFlagListOut,
  ComplianceFlagOut,
  ComplianceScanResultOut,
  ComplianceStatusOut,
  CreatorComplianceListOut,
  LicenseRefListOut,
} from "@/api/types";

export const FLAG_REASONS = [
  "unlicensed_music",
  "unlicensed_video",
  "unlicensed_image",
  "expired_license",
  "copyright_claim",
  "other",
] as const;

export const COMPLIANCE_STATUSES = [
  "compliant",
  "expiring_soon",
  "license_expired",
  "license_revoked",
  "flagged",
  "under_review",
  "action_required",
  "removed",
  "resolved",
] as const;

// ─── Creator ────────────────────────────────────────────────────────────────

export const listMyContentCompliance = (params?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.status) q.status = params.status;
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<CreatorComplianceListOut>(
    "/ui/licenses/compliance/my-content",
    q,
  );
};

export const getContentCompliance = (contentId: string) =>
  api.get<ComplianceStatusOut>(
    `/ui/licenses/compliance/content/${contentId}`,
  );

export const listContentLicenseRefs = (contentId: string) =>
  api.get<LicenseRefListOut>(
    `/ui/licenses/compliance/content/${contentId}/refs`,
  );

export const listContentFlags = (contentId: string, status?: string) => {
  const q: Record<string, string> = {};
  if (status) q.status = status;
  return api.get<ComplianceFlagListOut>(
    `/ui/licenses/compliance/content/${contentId}/flags`,
    q,
  );
};

export const checkContentCompliance = (
  contentId: string,
  contentType?: string,
) => {
  const q: Record<string, string> = {};
  if (contentType) q.content_type = contentType;
  return api.post<ComplianceCheckResultOut>(
    `/ui/licenses/compliance/content/${contentId}/check`,
    undefined,
    q,
  );
};

export interface FlagContentBody {
  content_id: string;
  reason: string;
  evidence?: string;
  reporter_type?: "viewer" | "creator";
}

export const flagContent = (body: FlagContentBody) =>
  api.post<ComplianceFlagOut>("/ui/licenses/compliance/flag", body);

// ─── Admin ────────────────────────────────────────────────────────────────

export const adminListComplianceIssues = (params?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.status) q.status = params.status;
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<AdminComplianceIssueListOut>(
    "/ui/admin/licenses/compliance/issues",
    q,
  );
};

export const adminListComplianceFlags = (params?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.status) q.status = params.status;
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<ComplianceFlagListOut>(
    "/ui/admin/licenses/compliance/flags",
    q,
  );
};

export const adminResolveComplianceFlag = (
  flagId: string,
  body: { content_id?: string; resolution: string; notes?: string },
) =>
  api.post<{ flag_id: string; content_id: string; status: string }>(
    `/ui/admin/licenses/compliance/flags/${flagId}/resolve`,
    body,
  );

export const adminUpdateComplianceStatus = (
  contentId: string,
  body: { new_status: string; notes?: string },
) =>
  api.post<{ content_id: string; compliance_status: string }>(
    `/ui/admin/licenses/compliance/content/${contentId}/status`,
    body,
  );

export const adminRunComplianceScan = () =>
  api.post<ComplianceScanResultOut>("/ui/admin/licenses/compliance/scan");
