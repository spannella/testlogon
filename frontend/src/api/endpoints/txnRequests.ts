/**
 * OBP Transaction Requests + SCA — TXR-001..TXR-005
 *
 * Backend prefix: /ui/txn-requests
 * Gated by: OPEN_BANK_PROJECT_ENABLED AND TXN_REQUESTS_ENABLED
 * When disabled, backend returns 404.
 *
 * All TS types defined inline (not added to shared api/types.ts).
 */

import { api } from "@/api/client";

// ─── Enums / constants ────────────────────────────────────────────────────────

export type TxnRequestType =
  | "WALLET_TRANSFER"
  | "COUNTERPARTY"
  | "PAYOUT"
  | "REFUND"
  | "FREE_FORM";

export type TxnRequestStatus =
  | "INITIATED"
  | "PENDING"
  | "IN_FLIGHT"
  | "COMPLETED"
  | "FAILED";

// ─── Domain models ─────────────────────────────────────────────────────────────

/** Full transaction-request record returned from the backend. */
export interface TxnRequestOut {
  request_id: string;
  type: TxnRequestType;
  /** Amount in currency minor units (e.g. cents for USD). */
  amount_cents: number;
  currency: string;
  /** Type-specific target fields (to_user_sub, counterparty_ref, etc.). */
  target: Record<string, unknown>;
  status: TxnRequestStatus;
  /** Present when SCA is required (status == PENDING). */
  sca_challenge_id: string | null;
  required_factors: string[] | null;
  sca_required_factors: string[] | null;
  ledger_refs: string[];
  created_at: number;
  updated_at: number;
  failure_reason: string | null;
}

export interface TxnRequestListOut {
  items: TxnRequestOut[];
  next_cursor: string | null;
}

// ─── Request bodies ───────────────────────────────────────────────────────────

export interface TxnRequestCreateIn {
  type: TxnRequestType;
  /** Amount in currency minor units (must be > 0). */
  amount_cents: number;
  currency?: string;
  /** Type-specific payload: to_user_sub, counterparty_ref, payout_method_id, etc. */
  target?: Record<string, unknown>;
  reason?: string;
  idempotency_key?: string;
}

// ─── SCA challenge verify responses ──────────────────────────────────────────

export interface ScaChallengeProgress {
  status: string;
  required_factors: string[];
  passed: Record<string, boolean>;
  remaining_factors: string[];
}

// ─── TXR API wrappers ─────────────────────────────────────────────────────────

const BASE = "/ui/txn-requests";

/** TXR-001: Create a new transaction request. */
export const createTxnRequest = (body: TxnRequestCreateIn) =>
  api.post<TxnRequestOut>(BASE, body);

/** TXR-002: List transaction requests (paginated). */
export const listTxnRequests = (opts?: {
  status?: TxnRequestStatus;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<TxnRequestListOut>(BASE, params);
};

/** TXR-002: Get a single transaction request by ID. */
export const getTxnRequest = (requestId: string) =>
  api.get<TxnRequestOut>(`${BASE}/${requestId}`);

/** TXR-004: Execute (authorise money movement) a transaction request. */
export const executeTxnRequest = (requestId: string) =>
  api.post<TxnRequestOut>(`${BASE}/${requestId}/execute`);

// ─── SCA/MFA factor wrappers (TXR-003) ───────────────────────────────────────

/** Trigger email OTP send for a pending SCA challenge. */
export const scaEmailBegin = (challengeId: string) =>
  api.post<{ status: string; sent_to: string[] }>("/ui/mfa/email/begin", {
    challenge_id: challengeId,
  });

/** Verify an email OTP code for an SCA challenge. */
export const scaEmailVerify = (challengeId: string, code: string) =>
  api.post<ScaChallengeProgress>("/ui/mfa/email/verify", {
    challenge_id: challengeId,
    code,
  });

/** Trigger SMS OTP send for a pending SCA challenge. */
export const scaSmsBegin = (challengeId: string) =>
  api.post<{ status: string; sent_to: string[] }>("/ui/mfa/sms/begin", {
    challenge_id: challengeId,
  });

/** Verify an SMS OTP code for an SCA challenge. */
export const scaSmsVerify = (challengeId: string, code: string) =>
  api.post<ScaChallengeProgress>("/ui/mfa/sms/verify", {
    challenge_id: challengeId,
    code,
  });

/** Verify a TOTP code for an SCA challenge. */
export const scaTotpVerify = (challengeId: string, totpCode: string) =>
  api.post<ScaChallengeProgress>("/ui/mfa/totp/verify", {
    challenge_id: challengeId,
    totp_code: totpCode,
  });
