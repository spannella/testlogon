import { api } from "@/api/client";
import type {
  KybAddressRequest,
  KybAdminQueueEnvelope,
  KybCaseEnvelope,
  KybCaseListEnvelope,
  KybCreateRequest,
  KybDirectorAddRequest,
  KybDirectorEnvelope,
  KybDirectorListEnvelope,
  KybDocumentEnvelope,
  KybDocumentRequest,
  KybScreeningEnvelope,
  KybUboAddRequest,
  KybUboEnvelope,
  KybUboListEnvelope,
} from "@/api/types";

const BASE = "/v1/kyc/business-cases";

export async function createKybCase(data: KybCreateRequest): Promise<KybCaseEnvelope> {
  return api.post<KybCaseEnvelope>(BASE, data);
}

export async function listKybCases(): Promise<KybCaseListEnvelope> {
  return api.get<KybCaseListEnvelope>(BASE);
}

export async function getKybCase(caseId: string): Promise<KybCaseEnvelope> {
  return api.get<KybCaseEnvelope>(`${BASE}/${caseId}`);
}

export async function patchKybCase(
  caseId: string,
  data: Partial<KybCreateRequest> & { expected_version: number },
): Promise<KybCaseEnvelope> {
  return api.patch<KybCaseEnvelope>(`${BASE}/${caseId}`, data);
}

export async function submitKybCase(
  caseId: string,
  data: { expected_version: number },
): Promise<KybCaseEnvelope> {
  return api.post<KybCaseEnvelope>(`${BASE}/${caseId}/submit`, data);
}

export async function addKybUbo(
  caseId: string,
  data: KybUboAddRequest,
): Promise<KybUboEnvelope> {
  return api.post<KybUboEnvelope>(`${BASE}/${caseId}/ubos`, data);
}

export async function listKybUbos(caseId: string): Promise<KybUboListEnvelope> {
  return api.get<KybUboListEnvelope>(`${BASE}/${caseId}/ubos`);
}

export async function linkKybUbo(
  caseId: string,
  uboId: string,
  data: { personal_kyc_case_id: string },
): Promise<KybUboEnvelope> {
  return api.post<KybUboEnvelope>(`${BASE}/${caseId}/ubos/${uboId}/link`, data);
}

export async function removeKybUbo(caseId: string, uboId: string): Promise<void> {
  await api.del(`${BASE}/${caseId}/ubos/${uboId}`);
}

export async function addKybDirector(
  caseId: string,
  data: KybDirectorAddRequest,
): Promise<KybDirectorEnvelope> {
  return api.post<KybDirectorEnvelope>(`${BASE}/${caseId}/directors`, data);
}

export async function listKybDirectors(caseId: string): Promise<KybDirectorListEnvelope> {
  return api.get<KybDirectorListEnvelope>(`${BASE}/${caseId}/directors`);
}

export async function removeKybDirector(caseId: string, directorId: string): Promise<void> {
  await api.del(`${BASE}/${caseId}/directors/${directorId}`);
}

export async function addKybDocument(
  caseId: string,
  data: KybDocumentRequest,
): Promise<KybDocumentEnvelope> {
  return api.post<KybDocumentEnvelope>(`${BASE}/${caseId}/documents`, data);
}

export async function setKybAddress(
  caseId: string,
  data: KybAddressRequest,
): Promise<{ address: Record<string, unknown> }> {
  return api.post<{ address: Record<string, unknown> }>(`${BASE}/${caseId}/addresses`, data);
}

export async function adminKybQueue(status?: string): Promise<KybAdminQueueEnvelope> {
  return api.get<KybAdminQueueEnvelope>(
    `${BASE}/admin/queue`,
    status ? { status } : undefined,
  );
}

export async function adminGetKybCase(caseId: string): Promise<KybCaseEnvelope> {
  return api.get<KybCaseEnvelope>(`${BASE}/admin/${caseId}`);
}

export async function adminScreenKybCase(caseId: string): Promise<KybScreeningEnvelope> {
  return api.post<KybScreeningEnvelope>(`${BASE}/admin/${caseId}/screen`, {});
}

export async function adminApproveKybCase(
  caseId: string,
  data: { expected_version: number; reason_codes?: string[]; note?: string },
): Promise<KybCaseEnvelope> {
  return api.post<KybCaseEnvelope>(`${BASE}/admin/${caseId}/approve`, data);
}

export async function adminRejectKybCase(
  caseId: string,
  data: { expected_version: number; reason_codes?: string[]; note?: string },
): Promise<KybCaseEnvelope> {
  return api.post<KybCaseEnvelope>(`${BASE}/admin/${caseId}/reject`, data);
}
