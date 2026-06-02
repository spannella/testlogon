import { api } from "@/api/client";
import type {
  KycReviewScheduleEnvelope,
  KycTriggerEventListEnvelope,
  KycMonitoringDashboard,
  KycReviewCheckResult,
  KycRescreeningResult,
  KycCompleteReviewRequest,
} from "@/api/types";

const BASE = "/v1/kyc/monitoring";

export const getMySchedule = () =>
  api.get<KycReviewScheduleEnvelope>(`${BASE}/schedule`);

export const getMyTriggers = () =>
  api.get<KycTriggerEventListEnvelope>(`${BASE}/triggers`);

export const getMonitoringDashboard = () =>
  api.get<KycMonitoringDashboard>(`${BASE}/admin/dashboard`);

export const runReviewCheck = (dryRun = false) =>
  api.post<KycReviewCheckResult>(`${BASE}/admin/review-check`, undefined, {
    dry_run: String(dryRun),
  });

export const runRescreening = (dryRun = false) =>
  api.post<KycRescreeningResult>(`${BASE}/admin/rescreening`, undefined, {
    dry_run: String(dryRun),
  });

export const getUserSchedule = (userSub: string) =>
  api.get<KycReviewScheduleEnvelope>(
    `${BASE}/admin/${encodeURIComponent(userSub)}/schedule`,
  );

export const triggerReview = (userSub: string, reason: string) =>
  api.post<Record<string, unknown>>(
    `${BASE}/admin/${encodeURIComponent(userSub)}/trigger`,
    { reason },
  );

export const completeReview = (userSub: string, body: KycCompleteReviewRequest) =>
  api.post<KycReviewScheduleEnvelope>(
    `${BASE}/admin/${encodeURIComponent(userSub)}/complete-review`,
    body,
  );
