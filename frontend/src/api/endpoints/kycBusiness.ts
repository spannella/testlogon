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
  return (await api.post(BASE, data)).data;
}

export async function listKybCases(): Promise<KybCaseListEnvelope> {
  return (await api.get(BASE)).data;
}

export async function getKybCase(caseId: string): Promise<KybCaseEnvelope> {
  return (await api.get(`${BASE}/${caseId}`)).data;
}

export async function patchKybCase(
  caseId: string,
  data: Partial<KybCreateRequest> & { expected_version: number },
): Promise<KybCaseEnvelope> {
  return (await api.patch(`${BASE}/${caseId}`, data)).data;
}

export async function submitKybCase(
  caseId: string,
  data: { expected_version: number },
): Promise<KybCaseEnvelope> {
  return (await api.post(`${BASE}/${caseId}/submit`, data)).data;
}

export async function addKybUbo(
  caseId: string,
  data: KybUboAddRequest,
): Promise<KybUboEnvelope> {
  return (await api.post(`${BASE}/${caseId}/ubos`, data)).data;
}

export async function listKybUbos(caseId: string): Promise<KybUboListEnvelope> {
  return (await api.get(`${BASE}/${caseId}/ubos`)).data;
}

export async function linkKybUbo(
  caseId: string,
  uboId: string,
  data: { personal_kyc_case_id: string },
): Promise<KybUboEnvelope> {
  return (await api.post(`${BASE}/${caseId}/ubos/${uboId}/link`, data)).data;
}

export async function removeKybUbo(caseId: string, uboId: string): Promise<void> {
  await api.delete(`${BASE}/${caseId}/ubos/${uboId}`);
}

export async function addKybDirector(
  caseId: string,
  data: KybDirectorAddRequest,
): Promise<KybDirectorEnvelope> {
  return (await api.post(`${BASE}/${caseId}/directors`, data)).data;
}

export async function listKybDirectors(caseId: string): Promise<KybDirectorListEnvelope> {
  return (await api.get(`${BASE}/${caseId}/directors`)).data;
}

export async function removeKybDirector(caseId: string, directorId: string): Promise<void> {
  await api.delete(`${BASE}/${caseId}/directors/${directorId}`);
}

export async function addKybDocument(
  caseId: string,
  data: KybDocumentRequest,
): Promise<KybDocumentEnvelope> {
  return (await api.post(`${BASE}/${caseId}/documents`, data)).data;
}

export async function setKybAddress(
  caseId: string,
  data: KybAddressRequest,
): Promise<{ address: Record<string, unknown> }> {
  return (await api.post(`${BASE}/${caseId}/addresses`, data)).data;
}

export async function adminKybQueue(status?: string): Promise<KybAdminQueueEnvelope> {
  return (await api.get(`${BASE}/admin/queue`, { params: status ? { status } : {} })).data;
}

export async function adminGetKybCase(caseId: string): Promise<KybCaseEnvelope> {
  return (await api.get(`${BASE}/admin/${caseId}`)).data;
}

export async function adminScreenKybCase(caseId: string): Promise<KybScreeningEnvelope> {
  return (await api.post(`${BASE}/admin/${caseId}/screen`, {})).data;
}

export async function adminApproveKybCase(
  caseId: string,
  data: { expected_version: number; reason_codes?: string[]; note?: string },
): Promise<KybCaseEnvelope> {
  return (await api.post(`${BASE}/admin/${caseId}/approve`, data)).data;
}

export async function adminRejectKybCase(
  caseId: string,
  data: { expected_version: number; reason_codes?: string[]; note?: string },
): Promise<KybCaseEnvelope> {
  return (await api.post(`${BASE}/admin/${caseId}/reject`, data)).data;
}
