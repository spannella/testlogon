import { api } from "@/api/client";
import type {
  ComplianceStatus,
  CreateSecurityFindingIn,
  SecurityAgentConfig,
  SecurityAgentConfigIn,
  SecurityAudit,
  SecurityAuditsList,
  SecurityFinding,
  SecurityFindingsList,
  SecurityTrends,
} from "@/api/types";

const BASE = "/ui/agents/compliance";

export const getComplianceConfigSchema = () =>
  api.get<Record<string, unknown>>(`${BASE}/config-schema`);

export const createSecurityFinding = (body: CreateSecurityFindingIn) =>
  api.post<SecurityFinding>(`${BASE}/findings`, body);

export const listSecurityFindings = (filters?: {
  severity?: string;
  status?: string;
  source_ref?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (filters?.severity) params.severity = filters.severity;
  if (filters?.status) params.status = filters.status;
  if (filters?.source_ref) params.source_ref = filters.source_ref;
  if (filters?.limit) params.limit = String(filters.limit);
  return api.get<SecurityFindingsList>(`${BASE}/findings`, params);
};

export const getSecurityFinding = (findingId: string) =>
  api.get<SecurityFinding>(`${BASE}/findings/${findingId}`);

export const updateFindingStatus = (
  findingId: string,
  status: "acknowledged" | "remediated" | "false_positive" | "accepted_risk",
  note?: string,
) => api.patch<SecurityFinding>(`${BASE}/findings/${findingId}/status`, { status, note });

export const listSecurityAudits = (limit = 20) =>
  api.get<SecurityAuditsList>(`${BASE}/audits`, { limit: String(limit) });

export const getSecurityAudit = (auditId: string) =>
  api.get<SecurityAudit>(`${BASE}/audits/${auditId}`);

export const triggerSecurityAudit = () =>
  api.post<SecurityAudit>(`${BASE}/audits/trigger`, {});

export const getFindingTrends = (days = 90) =>
  api.get<SecurityTrends>(`${BASE}/trends`, { days: String(days) });

export const getComplianceStatus = () =>
  api.get<ComplianceStatus>(`${BASE}/compliance`);

export const getSecurityConfig = () =>
  api.get<SecurityAgentConfig>(`${BASE}/config`);

export const updateSecurityConfig = (config: SecurityAgentConfigIn) =>
  api.put<SecurityAgentConfig>(`${BASE}/config`, config);
