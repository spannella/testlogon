import { api } from "@/api/client";
import type {
  KycLivenessCallListResponse,
  KycLivenessCallOut,
  KycLivenessCallResultRequest,
  KycLivenessCallScheduleRequest,
  KycLivenessCallStatus,
  KycLivenessCallStatusResponse,
} from "@/api/types";

// ── Owner endpoints ───────────────────────────────────────────────────────

export const scheduleKycLivenessCall = (body: KycLivenessCallScheduleRequest) =>
  api.post<KycLivenessCallOut>("/ui/kyc/liveness-call", body);

export const listMyKycLivenessCalls = () =>
  api.get<KycLivenessCallListResponse>("/ui/kyc/liveness-call");

export const getKycLivenessCall = (callId: string) =>
  api.get<KycLivenessCallOut>(`/ui/kyc/liveness-call/${callId}`);

export const getKycLivenessCallStatusForCase = (caseId: string) =>
  api.get<KycLivenessCallStatusResponse>(`/ui/kyc/liveness-call/case/${caseId}`);

export const cancelMyKycLivenessCall = (callId: string) =>
  api.post<KycLivenessCallOut>(`/ui/kyc/liveness-call/${callId}/cancel`);

// ── Verifier / admin endpoints ────────────────────────────────────────────

export const listKycLivenessCallsByStatus = (status: KycLivenessCallStatus, limit = 100) =>
  api.get<KycLivenessCallListResponse>("/ui/kyc/liveness-call/admin/by-status", {
    status,
    limit: String(limit),
  });

export const adminGetKycLivenessCall = (callId: string) =>
  api.get<KycLivenessCallOut>(`/ui/kyc/liveness-call/admin/${callId}`);

export const conductKycLivenessCall = (callId: string) =>
  api.post<KycLivenessCallOut>(`/ui/kyc/liveness-call/admin/${callId}/conduct`);

export const recordKycLivenessCallResult = (
  callId: string,
  body: KycLivenessCallResultRequest,
) => api.post<KycLivenessCallOut>(`/ui/kyc/liveness-call/admin/${callId}/result`, body);

export const adminCancelKycLivenessCall = (callId: string) =>
  api.post<KycLivenessCallOut>(`/ui/kyc/liveness-call/admin/${callId}/cancel`);
