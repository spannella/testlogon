import { api } from "@/api/client";
import type {
  KycDocumentListResponse,
  KycDocumentOut,
  KycDocumentReviewRequest,
  KycDocumentStatus,
  KycDocumentUploadRequest,
} from "@/api/types";

// ── Owner endpoints ───────────────────────────────────────────────────────

export const uploadKycDocument = (body: KycDocumentUploadRequest) =>
  api.post<KycDocumentOut>("/ui/kyc/documents", body);

export const listMyKycDocuments = () =>
  api.get<KycDocumentListResponse>("/ui/kyc/documents");

export const getKycDocument = (documentId: string) =>
  api.get<KycDocumentOut>(`/ui/kyc/documents/${documentId}`);

export const extractKycDocument = (documentId: string) =>
  api.post<KycDocumentOut>(`/ui/kyc/documents/${documentId}/extract`);

// ── Reviewer / admin endpoints ────────────────────────────────────────────

export const listKycDocumentsByStatus = (status: KycDocumentStatus, limit = 100) =>
  api.get<KycDocumentListResponse>("/ui/kyc/documents/admin/by-status", {
    status,
    limit: String(limit),
  });

export const adminGetKycDocument = (documentId: string) =>
  api.get<KycDocumentOut>(`/ui/kyc/documents/admin/${documentId}`);

export const reviewKycDocument = (documentId: string, body: KycDocumentReviewRequest) =>
  api.post<KycDocumentOut>(`/ui/kyc/documents/admin/${documentId}/review`, body);
