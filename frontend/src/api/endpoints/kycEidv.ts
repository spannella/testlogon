import { api } from "@/api/client";
import type {
  EidSchemesList,
  EidStatus,
  MockEidAssertion,
  StartEidVerificationResult,
} from "@/api/types";

const BASE = "/v1/kyc";

/** List supported eID schemes, optionally filtered by country. */
export const getEidSchemes = (country?: string) =>
  api.get<EidSchemesList>(`${BASE}/eid/schemes`, country ? { country } : undefined);

/** Start an eID verification session for a draft case. */
export const startEidVerification = (caseId: string, scheme: string) =>
  api.post<StartEidVerificationResult>(`${BASE}/cases/${caseId}/eid/start`, {
    scheme,
  });

/** Get the eID verification status for a case. */
export const getEidStatus = (caseId: string) =>
  api.get<EidStatus>(`${BASE}/cases/${caseId}/eid/status`);

/** Mock eID provider (dev mode) — returns a signed assertion for a session. */
export const mockEidVerify = (sessionId: string) =>
  api.post<MockEidAssertion>(`/mock/eid/verify`, { session_id: sessionId });

/** Complete the eID flow by hitting the callback with assertion + signature. */
export const completeEidCallback = (
  sessionId: string,
  assertion: string,
  signature: string,
) =>
  api.get(`${BASE}/eid/callback`, { session_id: sessionId, assertion, signature });
