import { api } from "@/api/client";

// ─── Types (inline, mirror app/models.py CrmCampaign* / Marketing* models) ────

export type CampaignType = "email" | "phone" | "mail" | "fax" | "sms";

export interface CrmCampaign {
  campaign_id: string;
  owner_id: string;
  name: string;
  status: string;
  objective?: string | null;
  budget_cents: number;
  contact_list_ids: string[];
  segment_ids: string[];
  tracking_code?: string | null;
  email_template_id?: string | null;
  questionnaire_id?: string | null;
  questionnaire_url?: string | null;
  campaign_type: CampaignType;
  variants?: Array<Record<string, unknown>> | null;
  created_at: number;
  updated_at: number;
}

export interface CrmCampaignCreateIn {
  name: string;
  objective?: string | null;
  budget_cents?: number;
  ad_campaign_id?: string | null;
  promo_code_ids?: string[];
  contact_list_ids?: string[];
  segment_ids?: string[];
  tracking_code?: string | null;
  start_date?: string | null;
  end_date?: string | null;
  campaign_type?: CampaignType;
  email_template_id?: string | null;
  questionnaire_id?: string | null;
  variants?: Array<Record<string, unknown>> | null;
}

export interface CrmCampaignUpdateIn {
  name?: string;
  objective?: string | null;
  budget_cents?: number;
  contact_list_ids?: string[];
  segment_ids?: string[];
  tracking_code?: string | null;
  start_date?: string | null;
  end_date?: string | null;
  campaign_type?: CampaignType;
  email_template_id?: string | null;
  questionnaire_id?: string | null;
  variants?: Array<Record<string, unknown>> | null;
}

export interface CampaignListOut {
  campaigns: CrmCampaign[];
  cursor?: string | null;
  count: number;
}

export interface CampaignSendIn {
  dry_run?: boolean;
  snapshot_ts?: number | null;
}

export interface CampaignSendOut {
  campaign_id: string;
  total_resolved: number;
  total_sent: number;
  total_skipped: number;
  dry_run: boolean;
  send_id?: string | null;
}

export interface CampaignAttribution {
  campaign_id: string;
  total_sent: number;
  email_sent: number;
  open_count: number;
  open_rate: number;
  click_count: number;
  click_rate: number;
}

export interface AbVariantStats {
  variant_id: string;
  label: string;
  sent: number;
  opens: number;
  clicks: number;
  open_rate: number;
  click_rate: number;
}

export interface AbResultsOut {
  campaign_id: string;
  variant_stats: AbVariantStats[];
  significance?: Record<string, unknown> | null;
}

export interface EmailTemplate {
  template_id: string;
  owner_id: string;
  name: string;
  subject_template: string;
  body_html_template: string;
  variables: string[];
  status: string;
  created_at: number;
  updated_at: number;
}

export interface EmailTemplateListOut {
  templates: EmailTemplate[];
  cursor?: string | null;
  count: number;
}

export interface EmailPreviewOut {
  subject: string;
  body_text: string;
  body_html?: string | null;
  merge_vars_used: Record<string, string>;
  merge_vars_missing: string[];
}

export interface WebLead {
  capture_id: string;
  first_name?: string;
  last_name?: string;
  email?: string;
  phone?: string;
  company?: string;
  message?: string;
  campaign_id?: string;
  source_ip?: string;
  created_at?: number;
  updated_at?: number;
  [key: string]: unknown;
}

export interface WebLeadListOut {
  leads: WebLead[];
  cursor?: string | null;
  count: number;
}

export interface WebLeadCaptureOut {
  capture_id: string;
  ok: boolean;
}

// ─── Campaign CRUD ───────────────────────────────────────────────────────────

export const listCampaigns = (opts?: {
  campaign_type?: CampaignType;
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.campaign_type) params["campaign_type"] = opts.campaign_type;
  if (opts?.status) params["status"] = opts.status;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CampaignListOut>("/ui/crm-marketing/campaigns", params);
};

export const getCampaign = (campaignId: string) =>
  api.get<CrmCampaign>(`/ui/crm-marketing/campaigns/${campaignId}`);

export const createCampaign = (body: CrmCampaignCreateIn) =>
  api.post<CrmCampaign>("/ui/crm-marketing/campaigns", body);

export const updateCampaign = (campaignId: string, body: CrmCampaignUpdateIn) =>
  api.patch<CrmCampaign>(`/ui/crm-marketing/campaigns/${campaignId}`, body);

export const deleteCampaign = (campaignId: string) =>
  api.del<{ ok: boolean }>(`/ui/crm-marketing/campaigns/${campaignId}`);

export const sendCampaign = (campaignId: string, body: CampaignSendIn) =>
  api.post<CampaignSendOut>(`/ui/crm-marketing/campaigns/${campaignId}/send`, body);

export const getCampaignAttribution = (campaignId: string) =>
  api.get<CampaignAttribution>(`/ui/crm-marketing/campaigns/${campaignId}/attribution`);

export const getAbResults = (campaignId: string) =>
  api.get<AbResultsOut>(`/ui/crm-marketing/campaigns/${campaignId}/ab-results`);

export const previewCampaignEmail = (
  campaignId: string,
  body: { sample_party_id?: string; sample_vars?: Record<string, string> },
) =>
  api.post<EmailPreviewOut>(
    `/ui/crm-marketing/campaigns/${campaignId}/preview-email`,
    body,
  );

// ─── Email templates (for campaign linkage; CMP-002) ──────────────────────────

export const listEmailTemplates = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<EmailTemplateListOut>("/ui/crm-marketing/email-templates", params);
};

// ─── Web-to-lead admin list (CMP-006) ─────────────────────────────────────────

export const adminListLeads = (opts?: {
  campaign_id?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.campaign_id) params["campaign_id"] = opts.campaign_id;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<WebLeadListOut>("/ui/admin/crm-marketing/leads", params);
};

// ─── Web-to-lead capture (public; CMP-006) ────────────────────────────────────

export const captureWebLead = (body: {
  first_name: string;
  last_name: string;
  email: string;
  phone?: string;
  company?: string;
  message?: string;
  campaign_id?: string;
  honeypot?: string;
  contact_list_id?: string;
}) => api.post<WebLeadCaptureOut>("/ui/crm-marketing/leads/capture", body);

// ─── Tracking URLs (public, no fetch needed — built client-side) ──────────────

export const openPixelUrl = (codeSlug: string) =>
  `/ui/crm-marketing/t/${codeSlug}/open.gif`;
