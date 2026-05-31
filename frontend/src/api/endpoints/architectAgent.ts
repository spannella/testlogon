import { api } from "@/api/client";
import type {
  ArchitectConfig,
  ArchitectConfigIn,
  ArchitectConfigValidation,
  ArchitectEligibleTicketsResult,
  ArchitectMetrics,
  ArchitectOutput,
  ArchitectWorkflowPreview,
  Decomposition,
  DependencyGraph,
  DevTicketListResult,
} from "@/api/types";

const BASE = "/ui/agents";

export const getArchitectConfigSchema = () =>
  api.get<Record<string, unknown>>(`${BASE}/types/architect/config-schema`);

export const getArchitectConfig = (typeId: string) =>
  api.get<ArchitectConfig>(`${BASE}/types/${typeId}/architect-config`);

export const updateArchitectConfig = (typeId: string, body: ArchitectConfigIn) =>
  api.put<ArchitectConfig>(`${BASE}/types/${typeId}/architect-config`, body);

export const validateArchitectConfig = (typeId: string, body: Partial<ArchitectConfigIn>) =>
  api.post<ArchitectConfigValidation>(`${BASE}/types/${typeId}/architect-config/validate`, body);

export const getArchitectEligibleTickets = (typeId: string, limit = 10) =>
  api.get<ArchitectEligibleTicketsResult>(`${BASE}/types/${typeId}/architect-eligible-tickets`, {
    limit: String(limit),
  });

export const testArchitectWorkflow = (typeId: string, ticketId: string) =>
  api.post<ArchitectWorkflowPreview>(`${BASE}/types/${typeId}/test-architect-workflow`, {
    ticket_id: ticketId,
  });

export const decomposeFeature = (typeId: string, runId: string, ticketId: string) =>
  api.post<ArchitectOutput>(`${BASE}/types/${typeId}/runs/${runId}/decompose`, {
    ticket_id: ticketId,
  });

export const getDecomposition = (featureTicketId: string) =>
  api.get<Decomposition>(`${BASE}/features/${featureTicketId}/decomposition`);

export const getDependencyGraph = (featureTicketId: string) =>
  api.get<DependencyGraph>(`${BASE}/features/${featureTicketId}/dependency-graph`);

export const getDevTicketsForFeature = (featureTicketId: string) =>
  api.get<DevTicketListResult>(`${BASE}/features/${featureTicketId}/dev-tickets`);

export const getArchitectOutput = (runId: string) =>
  api.get<ArchitectOutput>(`${BASE}/runs/${runId}/architect-output`);

export const getArchitectMetrics = (typeId: string, periodDays = 30) =>
  api.get<ArchitectMetrics>(`${BASE}/architect/metrics`, {
    type_id: typeId,
    period_days: String(periodDays),
  });
