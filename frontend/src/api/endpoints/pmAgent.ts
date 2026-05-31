import { api } from "@/api/client";
import type {
  BacklogResult,
  BlockerListResult,
  CapacityResult,
  IdeaListResult,
  PmConfig,
  PmConfigIn,
  PmConfigValidation,
  PmMetrics,
  PmOutput,
  ProductIdea,
  ProjectDashboard,
  ProjectReport,
  ReportListResult,
  ReprioritizeResult,
  Sprint,
  SprintDetail,
  SprintListResult,
} from "@/api/types";

const BASE = "/ui/agents";

// ─── Config ───────────────────────────────────────────────────────
export const getPmConfig = (typeId: string) =>
  api.get<PmConfig>(`${BASE}/types/${typeId}/pm-config`);

export const updatePmConfig = (typeId: string, body: PmConfigIn) =>
  api.put<PmConfig>(`${BASE}/types/${typeId}/pm-config`, body);

export const validatePmConfig = (typeId: string, body: Partial<PmConfigIn>) =>
  api.post<PmConfigValidation>(`${BASE}/types/${typeId}/pm-config/validate`, body);

// ─── Ideas ────────────────────────────────────────────────────────
export const submitIdea = (title: string, description: string) =>
  api.post<ProductIdea>(`${BASE}/ideas`, { title, description });

export const listIdeas = (params?: { status?: string; limit?: number; cursor?: string }) =>
  api.get<IdeaListResult>(`${BASE}/ideas`, {
    ...(params?.status ? { status: params.status } : {}),
    ...(params?.limit ? { limit: String(params.limit) } : {}),
    ...(params?.cursor ? { cursor: params.cursor } : {}),
  });

export const getIdea = (ideaId: string) => api.get<ProductIdea>(`${BASE}/ideas/${ideaId}`);

export const updateIdeaStatus = (
  ideaId: string,
  status: "accepted" | "rejected",
  rejectionReason?: string,
) =>
  api.patch<ProductIdea>(`${BASE}/ideas/${ideaId}`, {
    status,
    rejection_reason: rejectionReason,
  });

// ─── Backlog ──────────────────────────────────────────────────────
export const getBacklog = (typeId?: string) =>
  api.get<BacklogResult>(`${BASE}/backlog`, typeId ? { type_id: typeId } : undefined);

export const reprioritizeBacklog = (typeId: string, runId?: string) =>
  api.post<ReprioritizeResult>(
    `${BASE}/backlog/reprioritize`,
    undefined,
    { type_id: typeId, ...(runId ? { run_id: runId } : {}) },
  );

// ─── Blockers & capacity ──────────────────────────────────────────
export const getBlockers = (typeId?: string) =>
  api.get<BlockerListResult>(`${BASE}/blockers`, typeId ? { type_id: typeId } : undefined);

export const getCapacity = (typeId?: string) =>
  api.get<CapacityResult>(`${BASE}/capacity`, typeId ? { type_id: typeId } : undefined);

// ─── Sprints ──────────────────────────────────────────────────────
export const listSprints = (typeId?: string) =>
  api.get<SprintListResult>(`${BASE}/sprints`, typeId ? { type_id: typeId } : undefined);

export const getSprint = (sprintId: string, typeId?: string) =>
  api.get<SprintDetail>(`${BASE}/sprints/${sprintId}`, typeId ? { type_id: typeId } : undefined);

export const createSprint = (
  typeId: string,
  body: { start_date: string; end_date: string; planned_ticket_ids?: string[] },
) =>
  api.post<Sprint>(`${BASE}/sprints`, body, { type_id: typeId });

export const updateSprint = (sprintId: string, action: "activate" | "close", typeId?: string) =>
  api.patch<Sprint>(
    `${BASE}/sprints/${sprintId}${typeId ? `?type_id=${encodeURIComponent(typeId)}` : ""}`,
    { action },
  );

// ─── Reports ──────────────────────────────────────────────────────
export const listReports = (typeId?: string) =>
  api.get<ReportListResult>(`${BASE}/reports`, typeId ? { type_id: typeId } : undefined);

export const getReport = (reportId: string, typeId?: string) =>
  api.get<ProjectReport>(`${BASE}/reports/${reportId}`, typeId ? { type_id: typeId } : undefined);

// ─── Orchestration & metrics ──────────────────────────────────────
export const runPmOperation = (
  typeId: string,
  runId: string,
  operationType: "idea_triage" | "backlog_prioritize" | "report_generate" | "blocker_detect",
  reportType: "daily" | "weekly" = "daily",
) =>
  api.post<PmOutput>(`${BASE}/types/${typeId}/runs/${runId}/pm-operation`, {
    operation_type: operationType,
    report_type: reportType,
  });

export const getPmOutput = (runId: string) => api.get<PmOutput>(`${BASE}/runs/${runId}/pm-output`);

export const getPmMetrics = (typeId?: string, periodDays = 30) =>
  api.get<PmMetrics>(`${BASE}/pm/metrics`, {
    ...(typeId ? { type_id: typeId } : {}),
    period_days: String(periodDays),
  });

export const getProjectDashboard = (typeId?: string) =>
  api.get<ProjectDashboard>(`${BASE}/pm/dashboard`, typeId ? { type_id: typeId } : undefined);
