import { api } from "@/api/client";
import type {
  QaConfig,
  QaConfigIn,
  QaConfigValidation,
  QaEligibleTicketsResult,
  QaMetrics,
  QaOutput,
  QaReport,
  QaScreenshotsResult,
  QaWorkflowPreview,
} from "@/api/types";

const BASE = "/ui/agents";

export const getQaConfigSchema = () =>
  api.get<Record<string, unknown>>(`${BASE}/types/qa/config-schema`);

export const getQaConfig = (typeId: string) =>
  api.get<QaConfig>(`${BASE}/types/${typeId}/qa-config`);

export const updateQaConfig = (typeId: string, body: QaConfigIn) =>
  api.put<QaConfig>(`${BASE}/types/${typeId}/qa-config`, body);

export const validateQaConfig = (typeId: string, body: Partial<QaConfigIn>) =>
  api.post<QaConfigValidation>(`${BASE}/types/${typeId}/qa-config/validate`, body);

export const getQaEligibleTickets = (typeId: string, limit = 10) =>
  api.get<QaEligibleTicketsResult>(`${BASE}/types/${typeId}/qa-eligible-tickets`, {
    limit: String(limit),
  });

export const claimQaTicket = (runId: string, ticketId: string) =>
  api.post<Record<string, unknown>>(`${BASE}/runs/${runId}/claim-qa-ticket`, {
    ticket_id: ticketId,
  });

export const testQaWorkflow = (typeId: string, ticketId: string) =>
  api.post<QaWorkflowPreview>(`${BASE}/types/${typeId}/test-qa-workflow`, {
    ticket_id: ticketId,
  });

export const executeQaWorkflow = (
  typeId: string,
  runId: string,
  ticketId: string,
  scenario: "pass" | "fail" | "flaky" | "error" = "fail",
) =>
  api.post<QaOutput>(`${BASE}/types/${typeId}/runs/${runId}/execute-qa`, {
    ticket_id: ticketId,
    scenario,
  });

export const getQaOutput = (runId: string) =>
  api.get<QaOutput>(`${BASE}/runs/${runId}/qa-output`);

export const getQaReport = (runId: string) =>
  api.get<QaReport>(`${BASE}/runs/${runId}/qa-report`);

export const getQaScreenshots = (runId: string) =>
  api.get<QaScreenshotsResult>(`${BASE}/runs/${runId}/qa-screenshots`);

export const getQaMetrics = (typeId: string, periodDays = 30) =>
  api.get<QaMetrics>(`${BASE}/qa/metrics`, {
    type_id: typeId,
    period_days: String(periodDays),
  });
