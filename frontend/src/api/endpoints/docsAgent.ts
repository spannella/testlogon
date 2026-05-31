import { api } from "@/api/client";
import type {
  DocAgentConfig,
  DocCoverageDetails,
  DocCoverageRecord,
  DocCoverageSummary,
  DocTemplate,
  DocTemplateIn,
  DocTemplatesList,
  FreshnessCheckResult,
  PrImpactAssessment,
  RegisterDocBody,
  StaleDocsList,
} from "@/api/types";

const BASE = "/ui/agents/docs";

export const getDocCoverage = () => api.get<DocCoverageSummary>(`${BASE}/coverage`);

export const listDocCoverageDetails = (docType?: string) =>
  api.get<DocCoverageDetails>(
    `${BASE}/coverage/details`,
    docType ? { doc_type: docType } : undefined,
  );

export const listStaleDocs = (limit = 50) =>
  api.get<StaleDocsList>(`${BASE}/stale`, { limit: String(limit) });

export const triggerFreshnessCheck = () =>
  api.post<FreshnessCheckResult>(`${BASE}/freshness-check`, {});

export const registerDoc = (body: RegisterDocBody) =>
  api.post<DocCoverageRecord>(`${BASE}/register`, body);

export const updateDocRecord = (
  docPath: string,
  body: { source_refs?: string[]; coverage_score?: number },
) => api.put<DocCoverageRecord>(`${BASE}/coverage/${docPath}`, body);

export const assessPrImpact = (changedFiles: string[]) =>
  api.post<PrImpactAssessment>(`${BASE}/assess-pr`, { changed_files: changedFiles });

export const listDocTemplates = (docType?: string) =>
  api.get<DocTemplatesList>(`${BASE}/templates`, docType ? { doc_type: docType } : undefined);

export const createDocTemplate = (body: DocTemplateIn) =>
  api.post<DocTemplate>(`${BASE}/templates`, body);

export const updateDocTemplate = (id: string, body: Partial<DocTemplateIn>) =>
  api.put<DocTemplate>(`${BASE}/templates/${id}`, body);

export const deleteDocTemplate = (id: string) =>
  api.del<{ ok: boolean; template_id: string }>(`${BASE}/templates/${id}`);

export const getDocConfig = () => api.get<DocAgentConfig>(`${BASE}/config`);

export const updateDocConfig = (config: Partial<DocAgentConfig>) =>
  api.put<DocAgentConfig>(`${BASE}/config`, config);
