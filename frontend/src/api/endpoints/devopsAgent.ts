import { api } from "@/api/client";
import type {
  DeploymentApproval,
  DeploymentLog,
  DevOpsConfigIn,
  DevOpsConfigResult,
  DevOpsConfigValidation,
  DevOpsDeploymentsResult,
  DevOpsEligibleTicketsResult,
  DevOpsMetrics,
  DevOpsOutput,
  DevOpsWorkflowPreview,
} from "@/api/types";

const BASE = "/ui/agents";

export const getDevOpsConfigSchema = () =>
  api.get<Record<string, unknown>>(`${BASE}/types/devops/config-schema`);

export const getDevOpsConfig = (typeId: string) =>
  api.get<DevOpsConfigResult>(`${BASE}/types/${typeId}/devops-config`);

export const updateDevOpsConfig = (typeId: string, body: DevOpsConfigIn) =>
  api.put<DevOpsConfigResult>(`${BASE}/types/${typeId}/devops-config`, body);

export const validateDevOpsConfig = (typeId: string, body: Partial<DevOpsConfigIn>) =>
  api.post<DevOpsConfigValidation>(`${BASE}/types/${typeId}/devops-config/validate`, body);

export const getDevOpsEligibleTickets = (typeId: string, limit = 10) =>
  api.get<DevOpsEligibleTicketsResult>(`${BASE}/types/${typeId}/devops-eligible-tickets`, {
    limit: String(limit),
  });

export const testDevOpsWorkflow = (
  typeId: string,
  ticketId: string,
  environmentName?: string,
) =>
  api.post<DevOpsWorkflowPreview>(`${BASE}/types/${typeId}/test-devops-workflow`, {
    ticket_id: ticketId,
    environment_name: environmentName ?? null,
  });

export const executeDevOpsWorkflow = (
  typeId: string,
  runId: string,
  body: {
    ticket_id: string;
    environment_name?: string;
    version?: string;
    force_health_failure?: boolean;
  },
) => api.post<DevOpsOutput>(`${BASE}/types/${typeId}/runs/${runId}/execute-devops`, body);

export const getDevOpsOutput = (runId: string) =>
  api.get<DevOpsOutput>(`${BASE}/runs/${runId}/devops-output`);

export const getDeploymentLog = (runId: string) =>
  api.get<DeploymentLog>(`${BASE}/runs/${runId}/deployment-log`);

export const approveDeployment = (runId: string, approverNotes?: string) =>
  api.post<DeploymentApproval>(`${BASE}/runs/${runId}/approve-deployment`, {
    approved: true,
    approver_notes: approverNotes ?? null,
  });

export const rejectDeployment = (runId: string, approverNotes?: string) =>
  api.post<DeploymentApproval>(`${BASE}/runs/${runId}/reject-deployment`, {
    approved: false,
    approver_notes: approverNotes ?? null,
  });

export const getDevOpsMetrics = (typeId?: string, periodDays = 30) =>
  api.get<DevOpsMetrics>(`${BASE}/devops/metrics`, {
    ...(typeId ? { type_id: typeId } : {}),
    period_days: String(periodDays),
  });

export const listDeployments = (limit = 50) =>
  api.get<DevOpsDeploymentsResult>(`${BASE}/devops/deployments`, {
    limit: String(limit),
  });
