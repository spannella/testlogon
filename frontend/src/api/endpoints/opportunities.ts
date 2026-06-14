import { api } from "@/api/client";

// ─── SuiteCRM Opportunities (OPP-002..OPP-006) ───────────────────────────────
// TS interfaces mirror the LIVE Pydantic models in app/models.py.
// Backend router prefix: /ui/sales  (admin: /ui/admin/sales)
// Feature flag: S.sales_pipeline_enabled → endpoints 503 when off
//               (feature-status never 503s).

// ─── Constants (mirror app/models.py + app/services/opportunities.py) ─────────

export const OPPORTUNITY_STAGES = [
  "prospecting",
  "qualification",
  "needs_analysis",
  "value_proposition",
  "id_decision_makers",
  "proposal_price_quote",
  "negotiation_review",
  "closed_won",
  "closed_lost",
] as const;
export type OpportunityStage = (typeof OPPORTUNITY_STAGES)[number];

export const LEAD_SOURCE_CHOICES = [
  "cold_call",
  "existing_customer",
  "self_generated",
  "employee",
  "partner",
  "public_relations",
  "direct_mail",
  "conference",
  "trade_show",
  "web_site",
  "word_of_mouth",
  "email",
  "campaign",
  "other",
] as const;
export type LeadSource = (typeof LEAD_SOURCE_CHOICES)[number];

export const CONTACT_ROLES = [
  "decision_maker",
  "evaluator",
  "influencer",
  "champion",
  "end_user",
  "executive_sponsor",
  "technical_buyer",
  "other",
] as const;
export type ContactRole = (typeof CONTACT_ROLES)[number];

export const PERIOD_TYPE_CHOICES = ["monthly", "quarterly", "annual"] as const;
export type PeriodType = (typeof PERIOD_TYPE_CHOICES)[number];

// ─── Model interfaces ─────────────────────────────────────────────────────────

export interface OppContactRoleOut {
  opp_id: string;
  contact_ref: string;
  contact_role: string;
  owner_sub: string;
  created_at: number;
}

export interface OppContactRoleIn {
  contact_ref: string;
  contact_role: ContactRole | string;
}

export interface OpportunityOut {
  opp_id: string;
  owner_sub: string;
  name: string;
  stage: string;
  amount_cents: number;
  weighted_amount_cents: number;
  close_date: number;
  probability: number;
  lead_source?: string | null;
  description?: string | null;
  account_party_id?: string | null;
  contact_party_id?: string | null;
  created_at: number;
  updated_at: number;
  contact_roles: OppContactRoleOut[];
}

export interface OpportunityCreateIn {
  name: string;
  stage: OpportunityStage | string;
  amount_cents: number;
  close_date: number;
  probability?: number;
  lead_source?: string | null;
  description?: string | null;
  account_party_id?: string | null;
  contact_party_id?: string | null;
}

export interface OpportunityUpdateIn {
  name?: string;
  stage?: OpportunityStage | string;
  amount_cents?: number;
  close_date?: number;
  probability?: number;
  lead_source?: string | null;
  description?: string | null;
  account_party_id?: string | null;
  contact_party_id?: string | null;
}

export interface OpportunityListResp {
  items: OpportunityOut[];
  next_cursor?: string | null;
}

export interface StageConfigItemOut {
  stage_key: string;
  label: string;
  probability_default: number;
  order: number;
  is_won: boolean;
  is_lost: boolean;
  color?: string | null;
}

export interface StageConfigOut {
  stages: StageConfigItemOut[];
  updated_at?: number | null;
  updated_by_sub?: string | null;
}

export interface StageConfigItemIn {
  stage_key: string;
  label: string;
  probability_default?: number;
  order?: number;
  is_won?: boolean;
  is_lost?: boolean;
  color?: string | null;
}

export interface StageConfigIn {
  stages: StageConfigItemIn[];
}

export interface PipelineStageMetric {
  stage: string;
  label: string;
  count: number;
  total_amount_cents: number;
  weighted_amount_cents: number;
  avg_close_date?: number | null;
}

export interface PipelineReportOut {
  stages: PipelineStageMetric[];
  total_amount_cents: number;
  total_weighted_cents: number;
  generated_at: number;
}

export interface ForecastWorksheetIn {
  committed_cents: number;
  best_case_cents: number;
  pipeline_cents: number;
  notes?: string | null;
}

export interface ForecastWorksheetOut {
  user_sub: string;
  period_key: string;
  committed_cents: number;
  best_case_cents: number;
  pipeline_cents: number;
  closed_cents: number;
  quota_cents: number;
  attainment_pct: number;
  notes?: string | null;
  created_at: number;
  updated_at: number;
}

export interface SalesQuotaIn {
  user_sub: string;
  period_type: PeriodType | string;
  period_key: string;
  target_amount_cents: number;
}

export interface SalesQuotaOut {
  user_sub: string;
  period_type: string;
  period_key: string;
  target_amount_cents: number;
  created_at: number;
  updated_at: number;
  set_by_sub: string;
}

export interface SalesQuotaListOut {
  items: SalesQuotaOut[];
  next_cursor?: string | null;
}

export interface FeatureStatus {
  enabled: boolean;
}

// ─── Feature status (OPP-003/006) ─────────────────────────────────────────────

export const getFeatureStatus = () =>
  api.get<FeatureStatus>("/ui/sales/feature-status");

// ─── OPP-002: Opportunity CRUD ────────────────────────────────────────────────

export const createOpportunity = (body: OpportunityCreateIn) =>
  api.post<OpportunityOut>("/ui/sales/opportunities", body);

export const listOpportunities = (opts?: {
  stage?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.stage) params["stage"] = opts.stage;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<OpportunityListResp>("/ui/sales/opportunities", params);
};

export const getOpportunity = (oppId: string, includeContacts = false) =>
  api.get<OpportunityOut>(
    `/ui/sales/opportunities/${encodeURIComponent(oppId)}`,
    includeContacts ? { include_contacts: "true" } : undefined,
  );

export const updateOpportunity = (oppId: string, body: OpportunityUpdateIn) =>
  api.patch<OpportunityOut>(
    `/ui/sales/opportunities/${encodeURIComponent(oppId)}`,
    body,
  );

export const deleteOpportunity = (oppId: string) =>
  api.del<void>(`/ui/sales/opportunities/${encodeURIComponent(oppId)}`);

// ─── OPP-004: Contact-role junction ──────────────────────────────────────────

export const addContactRole = (oppId: string, body: OppContactRoleIn) =>
  api.post<OppContactRoleOut>(
    `/ui/sales/opportunities/${encodeURIComponent(oppId)}/contacts`,
    body,
  );

export const listContactRoles = (oppId: string) =>
  api.get<OppContactRoleOut[]>(
    `/ui/sales/opportunities/${encodeURIComponent(oppId)}/contacts`,
  );

export const removeContactRole = (oppId: string, contactRef: string) =>
  api.del<void>(
    `/ui/sales/opportunities/${encodeURIComponent(oppId)}/contacts/${encodeURIComponent(contactRef)}`,
  );

// ─── OPP-003: Stage config ────────────────────────────────────────────────────

export const listStages = () =>
  api.get<StageConfigOut>("/ui/sales/stages");

export const updateStages = (body: StageConfigIn) =>
  api.put<StageConfigOut>("/ui/admin/sales/stages", body);

// ─── OPP-005: Forecast worksheet ──────────────────────────────────────────────

export const getForecast = (periodKey: string) =>
  api.get<ForecastWorksheetOut>(
    `/ui/sales/forecast/${encodeURIComponent(periodKey)}`,
  );

export const upsertForecast = (periodKey: string, body: ForecastWorksheetIn) =>
  api.put<ForecastWorksheetOut>(
    `/ui/sales/forecast/${encodeURIComponent(periodKey)}`,
    body,
  );

// ─── OPP-006: Pipeline report ─────────────────────────────────────────────────

export const getPipelineReport = (opts?: { from_ts?: number; to_ts?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.from_ts != null) params["from_ts"] = String(opts.from_ts);
  if (opts?.to_ts != null) params["to_ts"] = String(opts.to_ts);
  return api.get<PipelineReportOut>("/ui/sales/reports/pipeline", params);
};

export const getAdminPipelineReport = (opts?: {
  from_ts?: number;
  to_ts?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.from_ts != null) params["from_ts"] = String(opts.from_ts);
  if (opts?.to_ts != null) params["to_ts"] = String(opts.to_ts);
  return api.get<PipelineReportOut>("/ui/admin/sales/reports/pipeline", params);
};

// ─── OPP-005: Admin quota ─────────────────────────────────────────────────────

export const setQuota = (body: SalesQuotaIn) =>
  api.post<SalesQuotaOut>("/ui/admin/sales/quotas", body);

export const listUserQuotas = (
  userSub: string,
  opts?: { cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<SalesQuotaListOut>(
    `/ui/admin/sales/quotas/${encodeURIComponent(userSub)}`,
    params,
  );
};

// ─── Display helpers ──────────────────────────────────────────────────────────

export const STAGE_LABELS: Record<string, string> = {
  prospecting: "Prospecting",
  qualification: "Qualification",
  needs_analysis: "Needs Analysis",
  value_proposition: "Value Proposition",
  id_decision_makers: "Decision Makers",
  proposal_price_quote: "Proposal / Quote",
  negotiation_review: "Negotiation",
  closed_won: "Closed Won",
  closed_lost: "Closed Lost",
};

export function stageLabel(key: string): string {
  return STAGE_LABELS[key] ?? key.replace(/_/g, " ");
}

export function isWonStage(key: string): boolean {
  return key === "closed_won";
}

export function isLostStage(key: string): boolean {
  return key === "closed_lost";
}

export function isClosedStage(key: string): boolean {
  return isWonStage(key) || isLostStage(key);
}

/** Integer cents → "$1,234.56" */
export function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format((cents ?? 0) / 100);
}

export function formatDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}
