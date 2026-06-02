import { api } from "@/api/client";
import type {
  AdminFaceComparison,
  FaceComparisonList,
  FaceComparisonOverrideRequest,
  FaceComparisonOverrideResult,
  FaceComparisonResult,
} from "@/api/types";

const BASE = "/v1/kyc/cases";

// ── Owner endpoints ─────────────────────────────────────────────────────────

/** Run a facial comparison (selfie vs ID photo) for a KYC case. */
export const compareFace = (caseId: string) =>
  api.post<FaceComparisonResult>(`${BASE}/${caseId}/compare-face`, {});

/** List all face-comparison attempts for a case (newest first). */
export const listFaceComparisons = (caseId: string) =>
  api.get<FaceComparisonList>(`${BASE}/${caseId}/face-comparisons`);

// ── Admin endpoints ─────────────────────────────────────────────────────────

/** Admin side-by-side comparison view (images + all attempts + best). */
export const adminGetFaceComparison = (caseId: string) =>
  api.get<AdminFaceComparison>(`${BASE}/admin/cases/${caseId}/face-comparison`);

/** Admin override of a comparison result. */
export const adminOverrideFaceComparison = (
  caseId: string,
  comparisonId: string,
  body: FaceComparisonOverrideRequest,
) =>
  api.post<FaceComparisonOverrideResult>(
    `${BASE}/admin/cases/${caseId}/face-comparison/${comparisonId}/override`,
    body,
  );
