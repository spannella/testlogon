import { api } from "@/api/client";
import type {
  AddressInput,
  AddressVerificationListResponse,
  AddressVerificationResponse,
  CrossReferenceResponse,
  PostalCodeValidationOut,
} from "@/api/types";

const BASE = "/v1/kyc/address-verification";

// ── Owner / user endpoints ────────────────────────────────────────────────

export const verifyKycCaseAddress = (caseId: string, address: AddressInput) =>
  api.post<AddressVerificationResponse>(`${BASE}/cases/${caseId}/verify`, {
    address,
  });

export const getKycCaseAddressVerification = (caseId: string) =>
  api.get<AddressVerificationResponse>(`${BASE}/cases/${caseId}`);

export const listKycCaseAddressAttempts = (caseId: string) =>
  api.get<AddressVerificationListResponse>(`${BASE}/cases/${caseId}/attempts`);

export const validateKycPostalCode = (postalCode: string, country: string) =>
  api.post<PostalCodeValidationOut>(`${BASE}/validate-postal-code`, {
    postal_code: postalCode,
    country,
  });

// ── Admin endpoints ───────────────────────────────────────────────────────

export const crossReferenceKycCaseAddress = (
  caseId: string,
  documentAddress: AddressInput,
) =>
  api.post<CrossReferenceResponse>(`${BASE}/cases/${caseId}/cross-reference`, {
    document_address: documentAddress,
  });

export const overrideKycCaseAddressDecision = (
  caseId: string,
  decision: "verified" | "needs_review" | "failed",
  note?: string,
) =>
  api.post<AddressVerificationResponse>(`${BASE}/cases/${caseId}/override`, {
    decision,
    note,
  });
