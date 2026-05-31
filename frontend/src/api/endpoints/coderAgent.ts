import { api } from "@/api/client";
import type {
  CoderConfig,
  CoderConfigIn,
  CoderConfigValidation,
  CoderMetrics,
  CoderOutput,
  CoderWorkflowPreview,
  EligibleTicketsResult,
} from "@/api/types";

const BASE = "/ui/agents";

export const getCoderConfigSchema = () =>
  api.get<Record<string, unknown>>(`${BASE}/types/coder/config-schema`);

export const getCoderConfig = (typeId: string) =>
  api.get<CoderConfig>(`${BASE}/types/${typeId}/coder-config`);

export const updateCoderConfig = (typeId: string, body: CoderConfigIn) =>
  api.put<CoderConfig>(`${BASE}/types/${typeId}/coder-config`, body);

export const validateCoderConfig = (typeId: string, body: Partial<CoderConfigIn>) =>
  api.post<CoderConfigValidation>(`${BASE}/types/${typeId}/coder-config/validate`, body);

export const getEligibleTickets = (typeId: string, limit = 10) =>
  api.get<EligibleTicketsResult>(`${BASE}/types/${typeId}/eligible-tickets`, {
    limit: String(limit),
  });

export const claimTicket = (runId: string, ticketId: string) =>
  api.post<Record<string, unknown>>(`${BASE}/runs/${runId}/claim-ticket`, {
    ticket_id: ticketId,
  });

export const testWorkflow = (typeId: string, ticketId: string) =>
  api.post<CoderWorkflowPreview>(`${BASE}/types/${typeId}/test-workflow`, {
    ticket_id: ticketId,
  });

export const executeWorkflow = (typeId: string, runId: string, ticketId: string) =>
  api.post<CoderOutput>(`${BASE}/types/${typeId}/runs/${runId}/execute`, {
    ticket_id: ticketId,
  });

export const getCoderOutput = (runId: string) =>
  api.get<CoderOutput>(`${BASE}/runs/${runId}/coder-output`);

export const getCoderMetrics = (typeId: string, periodDays = 30) =>
  api.get<CoderMetrics>(`${BASE}/coder/metrics`, {
    type_id: typeId,
    period_days: String(periodDays),
  });
