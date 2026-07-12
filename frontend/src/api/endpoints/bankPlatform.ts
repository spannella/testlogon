/**
 * OBP Platform Surface API — PLT-001..PLT-005
 *
 * Covers:
 *   PLT-001  Per-consumer rate-limit config  (/ui/api_keys/self_limits)
 *   PLT-002  Metrics leaderboard             (/v1/admin/api-usage/leaderboard)
 *   PLT-003  Glossary                        (/v1/glossary)
 *   PLT-004  Sandbox data import             (/v1/admin/sandbox/data-import)
 *   PLT-005  Wallet threshold webhooks       (/ui/billing/wallet, /ui/billing/wallet/threshold)
 *
 * Flags gating each surface:
 *   Umbrella:  OPEN_BANK_PROJECT_ENABLED (default off) — 404 when off
 *   PLT-001:   API_CONSUMER_RATE_LIMIT_ENABLED
 *   PLT-002:   METRICS_LEADERBOARD_ENABLED
 *   PLT-003:   GLOSSARY_ENABLED
 *   PLT-004:   SANDBOX_IMPORT_ENABLED + DEV_MODE
 *   PLT-005:   ACCOUNT_LEDGER_WEBHOOKS_ENABLED + WEBHOOKS_ENABLED
 *
 * All TS types defined inline — NOT added to shared api/types.ts.
 */

import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// PLT-001: Per-consumer rate-limit overrides
// ─────────────────────────────────────────────────────────────────────────────

export interface ApiKeyRateLimitOverrides {
  minute?: number | null;
  hour?: number | null;
  day?: number | null;
  week?: number | null;
  month?: number | null;
}

export interface ApiKeySelfLimitsReq {
  key_id: string;
  monthly_calls_cap?: number | null;
  monthly_spend_cap_micros?: number | null;
  route_caps?: Record<string, { max_calls?: number | null; max_spend_micros?: number | null }>;
  rate_limit_overrides?: ApiKeyRateLimitOverrides | null;
}

export interface ApiKeyItem {
  key_id: string;
  label: string;
  user_sub: string;
  created_at: number;
  expires_at?: number | null;
  revoked?: boolean;
  monthly_calls_cap?: number | null;
  monthly_spend_cap_micros?: number | null;
  route_caps?: Record<string, unknown>;
  rate_limit_overrides?: ApiKeyRateLimitOverrides | null;
  capabilities?: string[];
}

export interface ApiKeyListResp {
  keys: ApiKeyItem[];
}

/** PLT-001: List API keys (includes rate_limit_overrides field). */
export const listApiKeys = () => api.get<ApiKeyListResp>("/ui/api_keys");

/** PLT-001: Set per-key rate-limit overrides alongside other self-limits. */
export const setApiKeySelfLimits = (body: ApiKeySelfLimitsReq) =>
  api.post<{ ok: boolean; monthly_calls_cap?: number | null; monthly_spend_cap_micros?: number | null; rate_limit_overrides?: ApiKeyRateLimitOverrides | null }>(
    "/ui/api_keys/self_limits",
    body,
  );

// ─────────────────────────────────────────────────────────────────────────────
// PLT-002: Metrics Leaderboard
// ─────────────────────────────────────────────────────────────────────────────

export type LeaderboardDimension = "consumers" | "endpoints";
export type LeaderboardMetric = "calls_total" | "cost_subtotal_micros" | "request_units_total";

export interface LeaderboardItem {
  rank: number;
  /** api_key_id (consumers) or route_id (endpoints) */
  id: string;
  /** empty string for platform-wide merged rows */
  user_sub: string;
  calls_total: number;
  billable_calls_total: number;
  request_units_total: number;
  cost_subtotal_micros: number;
  unit_price_micros: number;
}

export interface LeaderboardResponse {
  period_id: string;
  dimension: LeaderboardDimension;
  metric: LeaderboardMetric;
  top_n: number;
  scope: "platform" | "user";
  items: LeaderboardItem[];
  total_rows_scanned: number;
}

export interface LeaderboardParams {
  period_id?: string;
  dimension?: LeaderboardDimension;
  metric?: LeaderboardMetric;
  top_n?: number;
  user_sub_filter?: string;
}

/**
 * PLT-002: Admin-only leaderboard.
 * Gated by OPEN_BANK_PROJECT_ENABLED + METRICS_LEADERBOARD_ENABLED.
 * Returns 404 when disabled.
 */
export const getLeaderboard = (params?: LeaderboardParams) => {
  const p: Record<string, string> = {};
  if (params?.period_id) p.period_id = params.period_id;
  if (params?.dimension) p.dimension = params.dimension;
  if (params?.metric) p.metric = params.metric;
  if (params?.top_n != null) p.top_n = String(params.top_n);
  if (params?.user_sub_filter) p.user_sub_filter = params.user_sub_filter;
  return api.get<LeaderboardResponse>("/v1/admin/api-usage/leaderboard", p);
};

// ─────────────────────────────────────────────────────────────────────────────
// PLT-003: Glossary
// ─────────────────────────────────────────────────────────────────────────────

export interface GlossaryTermOut {
  term_id: string;
  term: string;
  definition: string;
  tags: string[];
  created_at: number;
  updated_at: number;
  updated_by: string;
}

export interface GlossaryListOut {
  terms: GlossaryTermOut[];
  next_cursor?: string | null;
  count: number;
}

export interface GlossaryListParams {
  search?: string;
  cursor?: string;
  limit?: number;
}

/**
 * PLT-003: Public glossary list.
 * Path: GET /v1/glossary
 * Gated: OPEN_BANK_PROJECT_ENABLED + GLOSSARY_ENABLED → 404 when off.
 */
export const listGlossaryTerms = (params?: GlossaryListParams) => {
  const p: Record<string, string> = {};
  if (params?.search) p.search = params.search;
  if (params?.cursor) p.cursor = params.cursor;
  if (params?.limit != null) p.limit = String(params.limit);
  return api.get<GlossaryListOut>("/v1/glossary", p);
};

/** PLT-003: Get a single glossary term by ID. */
export const getGlossaryTerm = (termId: string) =>
  api.get<GlossaryTermOut>(`/v1/glossary/${termId}`);

/** PLT-003: Admin — create a glossary term. */
export const createGlossaryTerm = (body: { term: string; definition: string; tags?: string[] }) =>
  api.post<GlossaryTermOut>("/v1/admin/glossary", body);

/** PLT-003: Admin — patch a glossary term. */
export const patchGlossaryTerm = (
  termId: string,
  body: { term?: string; definition?: string; tags?: string[] },
) => api.patch<GlossaryTermOut>(`/v1/admin/glossary/${termId}`, body);

/** PLT-003: Admin — delete a glossary term. */
export const deleteGlossaryTerm = (termId: string) =>
  api.del<void>(`/v1/admin/glossary/${termId}`);

// ─────────────────────────────────────────────────────────────────────────────
// PLT-004: Sandbox import (admin + dev mode only)
// ─────────────────────────────────────────────────────────────────────────────

export interface SandboxCustomerIn {
  user_sub?: string;
  email: string;
  full_name?: string;
  display_name?: string;
  bio?: string;
}

export interface SandboxAccountIn {
  user_sub: string;
  initial_balance_cents?: number;
  currency?: string;
}

export interface SandboxTransactionIn {
  user_sub: string;
  entry_type: "credit" | "debit" | "adjustment";
  amount_cents: number;
  state?: string;
  reason: string;
  currency?: string;
}

export interface SandboxImportPayload {
  customers?: SandboxCustomerIn[];
  accounts?: SandboxAccountIn[];
  transactions?: SandboxTransactionIn[];
}

export interface SandboxRowError {
  section: string;
  index: number;
  code: string;
  message: string;
}

export interface SandboxImportResult {
  customers_created: number;
  accounts_created: number;
  transactions_created: number;
  errors: SandboxRowError[];
  ok: boolean;
}

/**
 * PLT-004: Bulk-seed sandbox data (admin + DEV_MODE only).
 * Path: POST /v1/admin/sandbox/data-import
 * Returns 404 when SANDBOX_IMPORT_ENABLED=0 or DEV_MODE=0.
 */
export const sandboxImport = (body: SandboxImportPayload) =>
  api.post<SandboxImportResult>("/v1/admin/sandbox/data-import", body);

// ─────────────────────────────────────────────────────────────────────────────
// PLT-005: Wallet balance + threshold configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface WalletBalanceOut {
  wallet_balance_cents: number;
  currency: string;
  updated_at: number;
  threshold_cents?: number | null;
  threshold_active?: boolean | null;
  balance_threshold_cents?: number | null;
  last_threshold_crossed?: boolean | null;
}

export interface SetWalletThresholdReq {
  /** Cents. 0 = disable threshold. */
  threshold_cents: number;
}

export interface SetWalletThresholdResp {
  ok: boolean;
  threshold_cents: number;
  currency: string;
}

/** PLT-005: Get current wallet balance (includes threshold fields when PLT-005 enabled). */
export const getWalletBalance = () => api.get<WalletBalanceOut>("/ui/billing/wallet");

/**
 * PLT-005: Set or clear the low-balance alert threshold.
 * Path: PUT /ui/billing/wallet/threshold
 * Gated: OPEN_BANK_PROJECT_ENABLED + ACCOUNT_LEDGER_WEBHOOKS_ENABLED.
 * Returns 404 when disabled; the wallet itself is always available.
 */
export const setWalletThreshold = (body: SetWalletThresholdReq) =>
  api.put<SetWalletThresholdResp>("/ui/billing/wallet/threshold", body);
