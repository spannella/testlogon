/**
 * OBP PSD2 AIS/PIS Consents — CSN-001..CSN-006
 *
 * Backend prefix: /ui/consents
 * Gated by: OPEN_BANK_PROJECT_ENABLED AND PSD2_CONSENTS_ENABLED
 * When disabled, backend returns 404.
 *
 * All TS types defined inline (not added to shared api/types.ts).
 */

import { api } from "@/api/client";

// ─── Consent status / type ────────────────────────────────────────────────────

export type ConsentStatus =
  | "INITIATED"
  | "ACCEPTED"
  | "REVOKED"
  | "EXPIRED";

export type ConsentType = "AIS" | "PIS";

// ─── Domain models ─────────────────────────────────────────────────────────────

/** Full consent record returned from the backend. */
export interface ConsentOut {
  consent_id: string;
  owner_sub: string;
  consumer_ref: string;
  consent_type: ConsentType;
  /** Account identifiers the consent covers. */
  account_refs: string[];
  /** View-level permissions granted (owner, accountant, auditor, public). */
  view_refs: string[];
  status: ConsentStatus;
  valid_from: number;
  valid_until: number;
  sca_challenge_id: string | null;
  recurring: boolean;
  reason: string | null;
  created_at: number;
  updated_at: number;
  revoked_at: number | null;
  /** Only present on PIS consents. */
  payment_ref?: string;
}

/** Paginated list of consents. */
export interface ConsentListOut {
  consents: ConsentOut[];
  cursor: string | null;
  count: number;
}

/** Body for creating a new consent. */
export interface ConsentCreateBody {
  consumer_ref: string;
  consent_type?: ConsentType;
  account_refs: string[];
  view_refs?: string[];
  payment_ref?: string;
  valid_until?: number;
  recurring?: boolean;
  reason?: string;
}

/** Response from POST /{consent_id}/sca */
export interface ConsentScaOut {
  challenge_id: string;
  required_factors: string[];
  consent_id: string;
  status: string;
}

// ─── API wrappers ─────────────────────────────────────────────────────────────

const BASE = "/ui/consents";

/** List consents for the current authenticated user. */
export const listOwnConsents = (opts?: {
  status?: ConsentStatus;
  limit?: number;
  cursor?: string;
}) => {
  const p: Record<string, string> = {};
  if (opts?.status) p["status"] = opts.status;
  if (opts?.limit) p["limit"] = String(opts.limit);
  if (opts?.cursor) p["cursor"] = opts.cursor;
  return api.get<ConsentListOut>(BASE, p);
};

/** Get a single consent by ID. */
export const getConsent = (consentId: string) =>
  api.get<ConsentOut>(`${BASE}/${consentId}`);

/** Create a new AIS or PIS consent in INITIATED status. */
export const createConsent = (body: ConsentCreateBody) =>
  api.post<ConsentOut>(BASE, body);

/** Revoke a consent (INITIATED or ACCEPTED only). */
export const revokeConsent = (consentId: string) =>
  api.post<ConsentOut>(`${BASE}/${consentId}/revoke`);

/** Begin SCA challenge for a consent (CSN-002). */
export const beginConsentSca = (consentId: string) =>
  api.post<ConsentScaOut>(`${BASE}/${consentId}/sca`);

/** Accept a consent after SCA is complete (CSN-002). */
export const acceptConsent = (consentId: string) =>
  api.post<ConsentOut>(`${BASE}/${consentId}/accept`);

/** Root-only: list consents for a given consumer reference. */
export const listConsentsByConsumer = (
  consumerRef: string,
  opts?: { status?: ConsentStatus; limit?: number; cursor?: string },
) => {
  const p: Record<string, string> = {};
  if (opts?.status) p["status"] = opts.status;
  if (opts?.limit) p["limit"] = String(opts.limit);
  if (opts?.cursor) p["cursor"] = opts.cursor;
  return api.get<ConsentListOut>(`${BASE}/by-consumer/${encodeURIComponent(consumerRef)}`, p);
};
