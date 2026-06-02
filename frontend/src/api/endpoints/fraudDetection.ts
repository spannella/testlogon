import { api } from "@/api/client";
import type {
  FraudFlagQueueOut,
  FraudFlagReview,
  FraudFlagOut,
  UserRiskProfile,
  FreezeUserRequest,
  FraudCaseCreate,
  FraudCaseOut,
  FraudCaseResolve,
  FraudConfigOut,
  FraudConfigUpdate,
  FraudStatsOut,
} from "@/api/types";

const BASE = "/v1/admin/fraud";

export const getFraudQueue = (params?: { status?: string; limit?: number; cursor?: string }) => {
  const q: Record<string, string> = {};
  if (params?.status) q.status = params.status;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<FraudFlagQueueOut>(`${BASE}/queue`, q);
};

export const reviewFlag = (flagId: string, body: FraudFlagReview) =>
  api.post<FraudFlagOut>(`${BASE}/flags/${flagId}/review`, body);

export const getUserRisk = (userId: string) =>
  api.get<UserRiskProfile>(`${BASE}/users/${userId}/risk`);

export const freezeUser = (userId: string, body: FreezeUserRequest) =>
  api.post<{ user_id: string; frozen: boolean; frozen_at: number }>(
    `${BASE}/users/${userId}/freeze`,
    body,
  );

export const unfreezeUser = (userId: string) =>
  api.post<{ user_id: string; frozen: boolean }>(`${BASE}/users/${userId}/unfreeze`);

export const recordChargeback = (body: { user_id: string; amount_cents?: number; tx_id?: string }) =>
  api.post<{ user_id: string; chargeback_count: number; auto_flagged: boolean; flag_id: string | null }>(
    `${BASE}/chargebacks`,
    body,
  );

export const createFraudCase = (body: FraudCaseCreate) =>
  api.post<FraudCaseOut>(`${BASE}/cases`, body);

export const listFraudCases = (status = "open") =>
  api.get<FraudCaseOut[]>(`${BASE}/cases`, { status });

export const getFraudCase = (caseId: string) =>
  api.get<FraudCaseOut>(`${BASE}/cases/${caseId}`);

export const resolveCase = (caseId: string, body: FraudCaseResolve) =>
  api.post<{ case_id: string; status: string; resolution: string; resolved_at: number }>(
    `${BASE}/cases/${caseId}/resolve`,
    body,
  );

export const getFraudConfig = () => api.get<FraudConfigOut>(`${BASE}/config`);

export const updateFraudConfig = (body: FraudConfigUpdate) =>
  api.patch<FraudConfigOut>(`${BASE}/config`, body);

export const getFraudStats = () => api.get<FraudStatsOut>(`${BASE}/stats`);
