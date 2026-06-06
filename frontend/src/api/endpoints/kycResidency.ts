import { api } from "@/api/client";
import type {
  KycResidencyDocumentOut,
  KycResidencyListResponse,
  KycResidencyReviewRequest,
  KycResidencyStatus,
  KycResidencyUploadRequest,
} from "@/api/types";

// ── Owner endpoints ───────────────────────────────────────────────────────

export const uploadKycResidencyDocument = (body: KycResidencyUploadRequest) =>
  api.post<KycResidencyDocumentOut>("/ui/kyc/residency", body);

export const listMyKycResidencyDocuments = () =>
  api.get<KycResidencyListResponse>("/ui/kyc/residency");

export const getKycResidencyDocument = (documentId: string) =>
  api.get<KycResidencyDocumentOut>(`/ui/kyc/residency/${documentId}`);

export const extractKycResidencyDocument = (documentId: string) =>
  api.post<KycResidencyDocumentOut>(`/ui/kyc/residency/${documentId}/extract`);

// ── Reviewer / admin endpoints ────────────────────────────────────────────

export const listKycResidencyByStatus = (status: KycResidencyStatus, limit = 100) =>
  api.get<KycResidencyListResponse>("/ui/kyc/residency/admin/by-status", {
    status,
    limit: String(limit),
  });

export const adminGetKycResidencyDocument = (documentId: string) =>
  api.get<KycResidencyDocumentOut>(`/ui/kyc/residency/admin/${documentId}`);

export const reviewKycResidencyDocument = (
  documentId: string,
  body: KycResidencyReviewRequest,
) => api.post<KycResidencyDocumentOut>(`/ui/kyc/residency/admin/${documentId}/review`, body);

export const adminListKycResidencyForCase = (caseId: string) =>
  api.get<KycResidencyListResponse>(`/ui/kyc/residency/admin/case/${caseId}`);
