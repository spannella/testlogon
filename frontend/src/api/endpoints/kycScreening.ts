import { api } from "@/api/client";
import type {
  KycScreeningPendingReviewsResponse,
  KycScreeningRescreenResponse,
  KycScreeningResultOut,
  KycScreeningResultsListResponse,
  KycScreeningResultStatus,
  KycScreeningReviewRequest,
  KycScreeningRunRequest,
  KycScreeningUserHistoryResponse,
} from "@/api/types";

// ── Owner endpoint ──────────────────────────────────────────────────────────

export const getMyKycCaseScreening = (caseId: string) =>
  api.get<KycScreeningResultsListResponse>(
    `/ui/kyc/screening/cases/${encodeURIComponent(caseId)}`,
  );

// ── Reviewer / admin endpoints ────────────────────────────────────────────

export const runKycScreening = (body: KycScreeningRunRequest) =>
  api.post<KycScreeningRescreenResponse>("/ui/kyc/screening/run", body);

export const adminGetKycCaseScreening = (caseId: string) =>
  api.get<KycScreeningResultsListResponse>(
    `/ui/kyc/screening/admin/cases/${encodeURIComponent(caseId)}`,
  );

export const rescreenKycCase = (caseId: string) =>
  api.post<KycScreeningRescreenResponse>(
    `/ui/kyc/screening/admin/cases/${encodeURIComponent(caseId)}/rescreen`,
  );

export const listKycScreeningPending = (
  result: KycScreeningResultStatus = "potential_match",
  limit = 50,
) =>
  api.get<KycScreeningPendingReviewsResponse>("/ui/kyc/screening/admin/pending", {
    result,
    limit: String(limit),
  });

export const reviewKycScreeningMatch = (
  caseId: string,
  screenKey: string,
  body: KycScreeningReviewRequest,
) =>
  api.post<KycScreeningResultOut>(
    `/ui/kyc/screening/admin/cases/${encodeURIComponent(caseId)}/${encodeURIComponent(
      screenKey,
    )}/review`,
    body,
  );

export const getKycScreeningUserHistory = (userSub: string, limit = 50) =>
  api.get<KycScreeningUserHistoryResponse>(
    `/ui/kyc/screening/admin/users/${encodeURIComponent(userSub)}/history`,
    { limit: String(limit) },
  );
