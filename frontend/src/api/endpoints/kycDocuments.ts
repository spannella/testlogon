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

// List all documents for a single case (admin view, with match results).
// Passes `case_id` to the by-status endpoint; the backend `case_id` filter is
// added by GAP-0248. `status` is required by the route, so we request the
// "extracted" status (the one carrying OCR fields/match results) when scoping
// by case.
export const listKycDocumentsForCase = (
  caseId: string,
  status: KycDocumentStatus = "extracted",
  limit = 100,
) =>
  api.get<KycDocumentListResponse>("/ui/kyc/documents/admin/by-status", {
    case_id: caseId,
    status,
    limit: String(limit),
  });

export const adminGetKycDocument = (documentId: string) =>
  api.get<KycDocumentOut>(`/ui/kyc/documents/admin/${documentId}`);

export const reviewKycDocument = (documentId: string, body: KycDocumentReviewRequest) =>
  api.post<KycDocumentOut>(`/ui/kyc/documents/admin/${documentId}/review`, body);
