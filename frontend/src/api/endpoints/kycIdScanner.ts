import { api } from "@/api/client";
import type {
  KycIdScannerAdjudicateRequest,
  KycIdScannerScanListResponse,
  KycIdScannerScanOut,
  KycIdScannerScanRequest,
  KycIdScannerStatus,
  KycIdScannerValidateRequest,
  KycIdScannerValidationOut,
} from "@/api/types";

// ── Owner endpoints ───────────────────────────────────────────────────────

export const scanKycIdDocument = (caseId: string, body: KycIdScannerScanRequest) =>
  api.post<KycIdScannerScanOut>(`/ui/kyc/id-scanner/cases/${caseId}/scan-document`, body);

export const listKycIdScans = (caseId: string) =>
  api.get<KycIdScannerScanListResponse>(`/ui/kyc/id-scanner/cases/${caseId}/scans`);

export const getKycIdScan = (caseId: string, scanId: string) =>
  api.get<KycIdScannerScanOut>(`/ui/kyc/id-scanner/cases/${caseId}/scans/${scanId}`);

export const validateKycIdDocument = (caseId: string, body: KycIdScannerValidateRequest) =>
  api.post<KycIdScannerValidationOut>(
    `/ui/kyc/id-scanner/cases/${caseId}/validate-document`,
    body,
  );

// ── Reviewer / admin endpoints ────────────────────────────────────────────

export const listKycIdScansByStatus = (status: KycIdScannerStatus, limit = 100) =>
  api.get<KycIdScannerScanListResponse>("/ui/kyc/id-scanner/admin/by-status", {
    status,
    limit: String(limit),
  });

export const adminGetKycIdScan = (scanId: string) =>
  api.get<KycIdScannerScanOut>(`/ui/kyc/id-scanner/admin/scans/${scanId}`);

export const adjudicateKycIdScan = (scanId: string, body: KycIdScannerAdjudicateRequest) =>
  api.post<KycIdScannerScanOut>(`/ui/kyc/id-scanner/admin/scans/${scanId}/adjudicate`, body);
