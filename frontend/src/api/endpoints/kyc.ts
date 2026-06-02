import { api } from "@/api/client";
import { uploadFile } from "@/api/endpoints/files";
import type {
  KycSelfServiceCaseEnvelope,
  KycSelfServiceCaseListEnvelope,
  KycReadinessEnvelope,
  KycQuestionnaireStatusEnvelope,
  KycSignatureStatusEnvelope,
  KycEstimatedWaitEnvelope,
  KycSelfServiceFileType,
} from "@/api/types";

// ─── KYC-013: User Self-Service Portal API wrappers ──────────────────────────
// These wrap the EXISTING /v1/kyc/cases endpoints (app/routers/kyc_cases.py).

const BASE = "/v1/kyc/cases";

export const createKycCase = (intakeProfile?: string) =>
  api.post<KycSelfServiceCaseEnvelope>(BASE, intakeProfile ? { intake_profile: intakeProfile } : {});

export const listKycCases = () => api.get<KycSelfServiceCaseListEnvelope>(BASE);

export const getKycCase = (caseId: string) =>
  api.get<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}`);

export const patchKycDraft = (
  caseId: string,
  body: { expected_version: number; intake_profile?: string | null },
) => api.patch<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}`, body);

export const attachKycFile = (
  caseId: string,
  body: { expected_version: number; path: string; file_type: KycSelfServiceFileType },
) => api.post<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}/files`, body);

export const getKycReadiness = (caseId: string) =>
  api.get<KycReadinessEnvelope>(`${BASE}/${caseId}/readiness`);

export const submitKycCase = (caseId: string, body: { expected_version: number }) =>
  api.post<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}/submit`, body);

export const startKycQuestionnaire = (caseId: string, body: { published_slug: string }) =>
  api.post<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}/start-questionnaire`, body);

export const getKycQuestionnaireStatus = (caseId: string) =>
  api.get<KycQuestionnaireStatusEnvelope>(`${BASE}/${caseId}/questionnaire-status`);

export const linkKycSignaturePacket = (
  caseId: string,
  body: { expected_version: number; source_path: string },
) => api.post<KycSelfServiceCaseEnvelope>(`${BASE}/${caseId}/signature-packet`, body);

export const getKycSignatureStatus = (caseId: string) =>
  api.get<KycSignatureStatusEnvelope>(`${BASE}/${caseId}/signature-status`);

export const getKycEstimatedWait = () =>
  api.get<KycEstimatedWaitEnvelope>(`${BASE}/estimated-wait`);

/**
 * Convenience: upload a File to the file manager under the user's KYC folder,
 * then attach it to the case. Returns the updated case (latest version).
 */
export async function uploadAndAttachKycFile(params: {
  caseId: string;
  expectedVersion: number;
  fileType: KycSelfServiceFileType;
  file: File;
}): Promise<KycSelfServiceCaseEnvelope> {
  const { caseId, expectedVersion, fileType, file } = params;
  const ext = (file.name.split(".").pop() || "bin").toLowerCase();
  const path = `/kyc/${caseId}/${fileType}_${Date.now()}.${ext}`;
  await uploadFile(file, path);
  return attachKycFile(caseId, { expected_version: expectedVersion, path, file_type: fileType });
}
