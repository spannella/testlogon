import { api } from "@/api/client";
import type {
  KycAdminAvailability,
  KycAdminAvailabilityReq,
  KycAssignmentHistory,
  KycAutoAssignResult,
  KycClaimResult,
  KycEscalateResult,
  KycMyAssigned,
  KycReassignReq,
  KycReassignResult,
  KycSlaBreachList,
  KycSlaConfigEnvelope,
  KycSlaConfigResult,
  KycSlaConfigUpdateReq,
  KycWorkloadDashboard,
} from "@/api/types";

const BASE = "/v1/kyc/assignment";

// ─── Auto-assignment ─────────────────────────────────────────────

export const autoAssignCase = (caseId: string, applicantLanguage = "en") =>
  api<KycAutoAssignResult>(`${BASE}/cases/${caseId}/auto-assign`, {
    method: "POST",
    body: JSON.stringify({ applicant_language: applicantLanguage }),
  });

export const autoAssignBatch = (caseIds: string[], applicantLanguage = "en") =>
  api<{ results: Array<Record<string, unknown>> }>(`${BASE}/auto-assign-batch`, {
    method: "POST",
    body: JSON.stringify({ case_ids: caseIds, applicant_language: applicantLanguage }),
  });

// ─── Manual (re)assign / claim ───────────────────────────────────

export const reassignCase = (caseId: string, data: KycReassignReq) =>
  api<KycReassignResult>(`${BASE}/cases/${caseId}/reassign`, {
    method: "POST",
    body: JSON.stringify(data),
  });

export const claimCase = (caseId: string) =>
  api<KycClaimResult>(`${BASE}/cases/${caseId}/claim`, { method: "POST" });

export const unclaimCase = (caseId: string) =>
  api<KycClaimResult>(`${BASE}/cases/${caseId}/unclaim`, { method: "POST" });

export const getMyQueue = () => api<KycMyAssigned>(`${BASE}/my-queue`);

export const getAssignmentHistory = (caseId: string) =>
  api<KycAssignmentHistory>(`${BASE}/cases/${caseId}/history`);

// ─── Availability ────────────────────────────────────────────────

export const getMyAvailability = () =>
  api<KycAdminAvailability>(`${BASE}/availability`);

export const setMyAvailability = (data: KycAdminAvailabilityReq) =>
  api<KycAdminAvailability>(`${BASE}/availability`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });

// ─── Workload dashboard ──────────────────────────────────────────

export const getWorkloads = () =>
  api<KycWorkloadDashboard>(`${BASE}/workloads`);

// ─── SLA compliance + config ─────────────────────────────────────

export const getSlaBreaches = () => api<KycSlaBreachList>(`${BASE}/sla/breaches`);

export const escalateCase = (caseId: string) =>
  api<KycEscalateResult>(`${BASE}/cases/${caseId}/escalate`, { method: "POST" });

export const getSlaConfig = () => api<KycSlaConfigEnvelope>(`${BASE}/sla-config`);

export const updateSlaConfig = (tier: string, data: KycSlaConfigUpdateReq) =>
  api<KycSlaConfigResult>(`${BASE}/sla-config/${tier}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
