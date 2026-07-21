import { api } from "@/api/client";

// ── GL: chart of accounts ────────────────────────────────────────────────────
export interface GLAccount {
  account_code: string;
  name: string;
  account_class: string;
  normal_balance: string;
  description?: string | null;
  is_active: boolean;
  is_system: boolean;
  created_at?: number;
  updated_at?: number;
  created_by?: string;
}

export interface GLJournalLine {
  seq?: number;
  account_code: string;
  account_name?: string;
  side: "debit" | "credit";
  amount_cents: number;
}

export interface GLJournalEntry {
  journal_entry_id: string;
  source_type: string;
  source_entry_id: string;
  ledger_date: string;
  posted_at: number;
  entry_type: string;
  memo: string;
  total_debit_cents: number;
  total_credit_cents: number;
  lines: GLJournalLine[];
}

export const listGLAccounts = (accountClass?: string, activeOnly = true) => {
  const params: Record<string, string> = { active_only: String(activeOnly) };
  if (accountClass) params.account_class = accountClass;
  return api.get<{ accounts: GLAccount[]; count: number }>("/v1/admin/gl/accounts", params);
};

export const getGLAccount = (code: string) =>
  api.get<GLAccount>(`/v1/admin/gl/accounts/${encodeURIComponent(code)}`);

export const createGLAccount = (body: {
  account_code: string;
  name: string;
  account_class: string;
  description?: string;
}) => api.post<GLAccount>("/v1/admin/gl/accounts", body);

export const updateGLAccount = (code: string, body: { name?: string; description?: string }) =>
  api.patch<GLAccount>(`/v1/admin/gl/accounts/${encodeURIComponent(code)}`, body);

export const disableGLAccount = (code: string) =>
  api.post<GLAccount>(`/v1/admin/gl/accounts/${encodeURIComponent(code)}/disable`);

export const enableGLAccount = (code: string) =>
  api.post<GLAccount>(`/v1/admin/gl/accounts/${encodeURIComponent(code)}/enable`);

// ── GL: journal ──────────────────────────────────────────────────────────────
export const listGLJournal = (startDate: string, endDate: string, limit = 50) =>
  api.get<{ entries: GLJournalEntry[]; count: number; cursor: string | null }>(
    "/v1/admin/gl/journal",
    { start_date: startDate, end_date: endDate, limit: String(limit) },
  );

export const getGLJournalEntry = (id: string) =>
  api.get<GLJournalEntry>(`/v1/admin/gl/journal/${encodeURIComponent(id)}`);

export const postGLJournal = (body: {
  lines: { account_code: string; side: "debit" | "credit"; amount_cents: number }[];
  source_type?: string;
  source_entity_id: string;
  memo?: string;
  gl_date: string;
  journal_id?: string;
}) => api.post<GLJournalEntry>("/v1/admin/gl/journal", body);

// ── AR: aging subledger ──────────────────────────────────────────────────────
export interface ARAgingItem {
  ref_id: string;
  user_sub: string;
  amount_cents: number;
  created_at: number;
  age_days: number;
  bucket: string;
  charge_status: string;
  kind: string;
}

export interface ARAging {
  current_cents: number;
  days_30_cents: number;
  days_60_cents: number;
  days_90_plus_cents: number;
  total_open_cents: number;
  open_item_count: number;
  as_of_ts: number;
  items: ARAgingItem[];
  source_invoice_count?: number;
}

export const getARAging = (opts?: { targetUserSub?: string; invoiceType?: string; limit?: number }) => {
  const params: Record<string, string> = { limit: String(opts?.limit ?? 200) };
  if (opts?.targetUserSub) params.target_user_sub = opts.targetUserSub;
  if (opts?.invoiceType) params.invoice_type = opts.invoiceType;
  return api.get<ARAging>("/v1/admin/ar/aging", params);
};

// ── Pricing rules ─────────────────────────────────────────────────────────────
export interface PricingRule {
  rule_id: string;
  name: string;
  description?: string | null;
  rule_type: string;
  stacking_mode: string;
  priority: number;
  active: boolean;
  created_at: number;
  updated_at: number;
  created_by: string;
  expires_at: number;
  max_uses: number;
  current_uses: number;
  applies_to_checkout_types: string[];
  scope_category_ids: string[];
  scope_skus: string[];
  rule_config: Record<string, unknown>;
}

export const listPricingRules = (creatorId: string, limit = 100) =>
  api.get<{ rules: PricingRule[]; cursor: string | null }>("/v1/admin/pricing-rules", {
    creator_id: creatorId,
    limit: String(limit),
  });

export const getPricingRule = (id: string) =>
  api.get<PricingRule>(`/v1/admin/pricing-rules/${encodeURIComponent(id)}`);

export const createPricingRule = (body: {
  creator_id: string;
  name: string;
  rule_type: string;
  stacking_mode: string;
  rule_config: Record<string, unknown>;
  priority?: number;
  description?: string;
}) => api.post<PricingRule>("/v1/admin/pricing-rules", body);

export const deactivatePricingRule = (id: string) =>
  api.post<PricingRule>(`/v1/admin/pricing-rules/${encodeURIComponent(id)}/deactivate`);
