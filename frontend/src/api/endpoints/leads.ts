import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// SuiteCRM Leads (LED-001..LED-013) — endpoint wrappers + inline types.
// All routes live under /ui/leads (+ /ui/leads/admin/*). Backend gates on
// S.leads_enabled — when off, every endpoint returns 404 ("Leads module not
// enabled"). Callers should handle ApiError.status === 404 gracefully.
// ─────────────────────────────────────────────────────────────────────────────

// Valid lead statuses (LEAD_STATUSES in app/services/leads.py)
export const LEAD_STATUSES = [
  "new",
  "assigned",
  "in_process",
  "converted",
  "recycled",
  "dead",
] as const;
export type LeadStatus = (typeof LEAD_STATUSES)[number];

// Allowed status transitions (_LEAD_TRANSITIONS in app/services/leads.py)
export const LEAD_STATUS_TRANSITIONS: Record<LeadStatus, LeadStatus[]> = {
  new: ["assigned", "in_process", "recycled", "dead"],
  assigned: ["in_process", "recycled", "dead", "new"],
  in_process: ["converted", "recycled", "dead", "assigned"],
  recycled: ["new", "assigned", "dead"],
  dead: ["new"],
  converted: [],
};

// Valid lead sources (LEAD_SOURCES in app/models.py)
export const LEAD_SOURCES = [
  "web_site",
  "cold_call",
  "email",
  "campaign",
  "trade_show",
  "word_of_mouth",
  "other",
  "internal",
] as const;
export type LeadSource = (typeof LEAD_SOURCES)[number];

// CRM activity types (LED-012)
export const LEAD_ACTIVITY_TYPES = [
  "note",
  "call",
  "task",
  "email",
  "calendar_event",
] as const;
export type LeadActivityType = (typeof LEAD_ACTIVITY_TYPES)[number];

// ─── Pydantic-mirrored interfaces ───────────────────────────────────────────

export interface Lead {
  lead_id: string;
  first_name: string;
  last_name: string;
  email: string;
  phone?: string | null;
  company?: string | null;
  title?: string | null;
  lead_source: string;
  description?: string | null;
  status: string;
  assigned_to?: string | null;
  score: number;
  website?: string | null;
  attribution_code?: string | null;
  campaign_id?: string | null;
  created_by: string;
  created_at: number;
  updated_at: number;
  converted_at?: number | null;
  converted_party_id?: string | null;
  converted_org_id?: string | null;
  origin_questionnaire_id?: string | null;
  origin_response_session_id?: string | null;
  linked_entity_id?: string | null;
}

export interface LeadCreateIn {
  first_name: string;
  last_name: string;
  email: string;
  phone?: string;
  company?: string;
  title?: string;
  lead_source?: string;
  description?: string;
  assigned_to?: string;
  website?: string;
  attribution_code?: string;
  campaign_id?: string;
}

export interface LeadUpdateIn {
  first_name?: string;
  last_name?: string;
  email?: string;
  phone?: string;
  company?: string;
  title?: string;
  lead_source?: string;
  description?: string;
  assigned_to?: string;
  status?: string;
  website?: string;
  score?: number;
}

export interface LeadListResp {
  leads: Lead[];
  cursor?: string | null;
}

export interface LeadConversionIn {
  create_account?: boolean;
  account_name?: string;
  create_opportunity?: boolean;
  opportunity_name?: string;
  opportunity_amount_cents?: number;
}

export interface OpportunityStub {
  opportunity_id: string;
  name: string;
  amount_cents: number;
  currency: string;
  stage: string;
  created_at: number;
}

export interface LeadConversionResult {
  lead_id: string;
  status: string;
  converted_party_id: string;
  converted_org_id?: string | null;
  opportunity?: OpportunityStub | null;
  converted_at: number;
  pty_path_used: boolean;
}

export interface LeadScoreResult {
  lead_id: string;
  score: number;
  computed_at: number;
  trigger: string;
}

export interface LeadScoreHistoryEntry {
  score: number;
  trigger: string;
  computed_at: number;
  lead_id: string;
}

export interface LeadScoreHistoryResp {
  lead_id: string;
  entries: LeadScoreHistoryEntry[];
  cursor?: string | null;
}

export interface LeadScoreRule {
  field: string;
  operator: string;
  value: string;
  points: number;
}

export interface LeadScoreRules {
  rules: LeadScoreRule[];
  max_score: number;
  updated_at?: number;
}

export interface LeadActivity {
  activity_id: string;
  lead_id: string;
  activity_type: string;
  subject?: string | null;
  description?: string | null;
  actor_sub: string;
  created_at: number;
  metadata?: Record<string, unknown> | null;
}

export interface LeadActivityListResp {
  activities: LeadActivity[];
  cursor?: string | null;
}

export interface LeadLogActivityIn {
  activity_type: string;
  subject?: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface LeadDuplicatesResp {
  duplicates: Lead[];
}

export interface LeadSourceSummaryResp {
  sources: Record<string, number>;
}

// ─── Prospects (LED-007) ────────────────────────────────────────────────────

export interface Prospect {
  prospect_id: string;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  phone?: string | null;
  company?: string | null;
  suppressed: boolean;
  created_at: number;
  updated_at: number;
}

export interface ProspectCreateIn {
  email: string;
  first_name?: string;
  last_name?: string;
  phone?: string;
  company?: string;
}

export interface ProspectUpdateIn {
  first_name?: string;
  last_name?: string;
  phone?: string;
  company?: string;
}

export interface ProspectListResp {
  prospects: Prospect[];
  cursor?: string | null;
  count?: number;
}

// ─── Lead CRUD (LED-003 / LED-013) ──────────────────────────────────────────

export interface LeadListParams {
  status?: string;
  lead_source?: string;
  assigned_to?: string;
  created_after?: number;
  cursor?: string;
  limit?: number;
}

function buildParams(
  p?: Record<string, string | number | boolean | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!p) return out;
  for (const [k, v] of Object.entries(p)) {
    if (v !== undefined && v !== null && v !== "") out[k] = String(v);
  }
  return out;
}

export const listLeads = (params?: LeadListParams) =>
  api.get<LeadListResp>(
    "/ui/leads",
    buildParams(params as Record<string, string | number | undefined> | undefined),
  );

export const getLead = (leadId: string) =>
  api.get<Lead>(`/ui/leads/${encodeURIComponent(leadId)}`);

export const createLead = (body: LeadCreateIn) =>
  api.post<Lead>("/ui/leads", body);

export const updateLead = (leadId: string, body: LeadUpdateIn) =>
  api.patch<Lead>(`/ui/leads/${encodeURIComponent(leadId)}`, body);

export const deleteLead = (leadId: string) =>
  api.del<void>(`/ui/leads/${encodeURIComponent(leadId)}`);

// ─── Lead actions ────────────────────────────────────────────────────────────

export const convertLead = (leadId: string, body: LeadConversionIn) =>
  api.post<LeadConversionResult>(`/ui/leads/${encodeURIComponent(leadId)}/convert`, body);

export const assignLead = (leadId: string, assigneeSub: string) =>
  api.post<Lead>(`/ui/leads/${encodeURIComponent(leadId)}/assign`, { assignee_sub: assigneeSub });

export const computeLeadScore = (leadId: string) =>
  api.post<LeadScoreResult>(`/ui/leads/${encodeURIComponent(leadId)}/score`, {});

export const getScoreHistory = (leadId: string, opts?: { cursor?: string; limit?: number }) =>
  api.get<LeadScoreHistoryResp>(
    `/ui/leads/${encodeURIComponent(leadId)}/score-history`,
    buildParams(opts),
  );

export const mergeLeads = (primaryLeadId: string, secondaryLeadId: string) =>
  api.post<Lead>(`/ui/leads/${encodeURIComponent(primaryLeadId)}/merge`, {
    secondary_lead_id: secondaryLeadId,
  });

export const findDuplicates = (leadId: string) =>
  api.get<LeadDuplicatesResp>(`/ui/leads/${encodeURIComponent(leadId)}/duplicates`);

// ─── Activities (LED-012) ───────────────────────────────────────────────────

export const listActivities = (leadId: string, opts?: { cursor?: string; limit?: number }) =>
  api.get<LeadActivityListResp>(
    `/ui/leads/${encodeURIComponent(leadId)}/activities`,
    buildParams(opts),
  );

export const logActivity = (leadId: string, body: LeadLogActivityIn) =>
  api.post<LeadActivity>(`/ui/leads/${encodeURIComponent(leadId)}/activities`, body);

// ─── Prospects (LED-007) ────────────────────────────────────────────────────

export interface ProspectListParams {
  cursor?: string;
  limit?: number;
  include_suppressed?: boolean;
  include_deleted?: boolean;
}

export const listProspects = (params?: ProspectListParams) =>
  api.get<ProspectListResp>(
    "/ui/leads/prospects",
    buildParams({
      cursor: params?.cursor,
      limit: params?.limit,
      include_suppressed:
        params?.include_suppressed === undefined ? undefined : String(params.include_suppressed),
      include_deleted:
        params?.include_deleted === undefined ? undefined : String(params.include_deleted),
    }),
  );

export const getProspect = (prospectId: string) =>
  api.get<Prospect>(`/ui/leads/prospects/${encodeURIComponent(prospectId)}`);

export const createProspect = (body: ProspectCreateIn) =>
  api.post<Prospect>("/ui/leads/prospects", body);

export const updateProspect = (prospectId: string, body: ProspectUpdateIn) =>
  api.patch<Prospect>(`/ui/leads/prospects/${encodeURIComponent(prospectId)}`, body);

export const deleteProspect = (prospectId: string) =>
  api.del<void>(`/ui/leads/prospects/${encodeURIComponent(prospectId)}`);

// ─── Admin (LED-013) ────────────────────────────────────────────────────────

export const adminListAllLeads = (params?: {
  status?: string;
  lead_source?: string;
  cursor?: string;
  limit?: number;
}) => api.get<LeadListResp>("/ui/leads/admin/all", buildParams(params));

export const getScoringRules = () =>
  api.get<LeadScoreRules>("/ui/leads/admin/scoring-rules");

export const updateScoringRules = (body: { rules: LeadScoreRule[]; max_score: number }) =>
  api.post<LeadScoreRules>("/ui/leads/admin/scoring-rules", body);

export const getSourceSummary = () =>
  api.get<LeadSourceSummaryResp>("/ui/leads/sources/summary");
