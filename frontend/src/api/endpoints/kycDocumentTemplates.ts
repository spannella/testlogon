import { api } from "@/api/client";
import type {
  CreateKycTemplateRequest,
  KycDocumentTemplate,
  KycDocumentTemplateList,
  KycDocumentTemplateVersion,
  KycRequiredTemplates,
  KycTemplateRenderForCaseResult,
} from "@/api/types";

const BASE = "/v1/kyc/document-templates";

export const listKycTemplates = (status?: string) =>
  api.get<KycDocumentTemplateList>(BASE, status ? { status } : undefined);

export const getKycTemplate = (templateId: string) =>
  api.get<KycDocumentTemplate>(`${BASE}/${templateId}`);

export const createKycTemplate = (data: CreateKycTemplateRequest) =>
  api.post<KycDocumentTemplate>(BASE, data);

export const uploadKycTemplateVersion = (templateId: string, pdfBase64: string) =>
  api.post<KycDocumentTemplateVersion>(`${BASE}/${templateId}/versions`, {
    pdf_base64: pdfBase64,
  });

export const activateKycTemplateVersion = (templateId: string, version: number) =>
  api.patch<KycDocumentTemplateVersion>(
    `${BASE}/${templateId}/versions/${version}/activate`,
  );

export const deactivateKycTemplateVersion = (templateId: string, version: number) =>
  api.patch<KycDocumentTemplateVersion>(
    `${BASE}/${templateId}/versions/${version}/deactivate`,
  );

export const archiveKycTemplate = (templateId: string) =>
  api.del<KycDocumentTemplate>(`${BASE}/${templateId}`);

export const previewKycTemplateUrl = (templateId: string, version: number) =>
  `${BASE}/${templateId}/versions/${version}/preview`;

export const getRequiredKycTemplates = (tier: string) =>
  api.get<KycRequiredTemplates>(`${BASE}/required/list`, { tier });

export const renderKycTemplatesForCase = (caseId: string) =>
  api.post<KycTemplateRenderForCaseResult>(`${BASE}/render-for-case`, {
    case_id: caseId,
  });
