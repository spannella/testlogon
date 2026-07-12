import { api } from "@/api/client";
import type {
  PiiMaskedResponse,
  PiiDecryptRequest,
  PiiDecryptResponse,
  PiiWriteRequest,
  PiiWriteResponse,
  PiiAuditLogResponse,
  KeyRotationResponse,
  KeyDestroyResponse,
  KycSelfServiceCaseEnvelope,
  KycDisputeRequest,
  KycReopenRequest,
} from "@/api/types";

const BASE = "/v1/kyc/cases";

// ─── KYD-009: Dispute / reopen-and-resubmit flow (flag-gated server-side by
// KYC_DISPUTE_ENABLED / KYC_RETRY_ENABLED — actions 503 until enabled). ──────

/** KYD-005: appeal a rejected case (rejected -> disputed). */
export const disputeKycCase = (caseId: string, body: KycDisputeRequest) =>
  api.post<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}/dispute`, body);

/** KYD-005: reopen a rejected/expired case to retry (-> draft). */
export const reopenKycCase = (caseId: string, body: KycReopenRequest) =>
  api.post<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}/reopen`, body);

/** KYC-023: Encrypt and store PII fields onto a draft case (owner). */
export const writePii = (caseId: string, body: PiiWriteRequest) =>
  api.post<PiiWriteResponse>(`${BASE}/${caseId}/pii`, body);

/** KYC-023: Get masked PII for a case (owner or admin). No KMS call. */
export const getMaskedPii = (caseId: string) =>
  api.get<PiiMaskedResponse>(`${BASE}/${caseId}/pii/masked`);

/** KYC-023: Decrypt specific PII fields (assigned admin / root). Audited. */
export const decryptPii = (caseId: string, body: PiiDecryptRequest) =>
  api.post<PiiDecryptResponse>(`${BASE}/${caseId}/pii/decrypt`, body);

/** KYC-023: PII access audit log for a single case (root only). */
export const getCaseAuditLog = (caseId: string, limit = 100) =>
  api.get<PiiAuditLogResponse>(`${BASE}/${caseId}/pii/audit-log`, { limit: String(limit) });

/** KYC-023: PII access audit log filtered by accessor sub (root only). */
export const getAuditLogByAccessor = (accessor: string, limit = 100) =>
  api.get<PiiAuditLogResponse>(`${BASE}/admin/pii/audit-log`, {
    accessor,
    limit: String(limit),
  });

/** KYC-023: Rotate a user's encryption key, re-encrypting their PII (root). */
export const rotateUserKey = (userSub: string) =>
  api.post<KeyRotationResponse>(`${BASE}/admin/encryption/rotate-key/${userSub}`);

/** KYC-023: Permanently destroy a user's keys (GDPR erasure, root). */
export const destroyUserKeys = (userSub: string) =>
  api.post<KeyDestroyResponse>(`${BASE}/admin/encryption/destroy-keys/${userSub}`);
