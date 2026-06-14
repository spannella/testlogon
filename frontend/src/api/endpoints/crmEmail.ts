import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// SuiteCRM EMAIL (EML) — endpoint wrappers + inline TS types.
//
// Backed by the LIVE marketing-campaigns router (app/routers/crm_campaigns.py).
// Base path: /ui/crm-marketing/*  (cookie session auth).
//
// Feature flag: S.crm_campaigns_enabled (default OFF) → endpoints return 404.
// Callers should treat ApiError.status === 404 as "feature not enabled".
// ─────────────────────────────────────────────────────────────────────────────

// ─── Email templates (CMP-002) ───────────────────────────────────────────────

export interface MarketingEmailTemplate {
  template_id: string;
  owner_id: string;
  name: string;
  subject_template: string;
  body_html_template: string;
  variables: string[];
  status: string; // "draft" | "active"
  created_at: number;
  updated_at: number;
}

export interface MarketingEmailTemplateListOut {
  templates: MarketingEmailTemplate[];
  cursor: string | null;
  count: number;
}

export interface MarketingEmailTemplateCreateIn {
  name: string;
  subject_template: string;
  body_html_template: string;
}

export interface MarketingEmailTemplateUpdateIn {
  name?: string;
  subject_template?: string;
  body_html_template?: string;
  status?: "draft" | "active";
}

export interface MarketingEmailTemplatePreviewOut {
  subject: string;
  body_html: string;
  variables: string[];
  missing_vars: string[];
}

// ─── Campaigns (CMP-001/008) ──────────────────────────────────────────────────

export type CampaignType = "email" | "phone" | "mail" | "fax" | "sms";

export interface CrmCampaign {
  campaign_id: string;
  owner_id: string;
  name: string;
  status: string; // "draft" | ...
  objective: string | null;
  budget_cents: number;
  contact_list_ids: string[];
  segment_ids: string[];
  tracking_code: string | null;
  email_template_id: string | null;
  questionnaire_id: string | null;
  questionnaire_url: string | null;
  campaign_type: CampaignType;
  variants: Array<Record<string, unknown>> | null;
  created_at: number;
  updated_at: number;
}

export interface MarketingCampaignListOut {
  campaigns: CrmCampaign[];
  cursor: string | null;
  count: number;
}

export interface CrmCampaignCreateIn {
  name: string;
  objective?: string;
  budget_cents?: number;
  contact_list_ids?: string[];
  segment_ids?: string[];
  tracking_code?: string;
  start_date?: string;
  end_date?: string;
  campaign_type?: CampaignType;
  email_template_id?: string | null;
  questionnaire_id?: string;
  variants?: Array<Record<string, unknown>>;
}

export interface CrmCampaignUpdateIn {
  name?: string;
  objective?: string;
  budget_cents?: number;
  contact_list_ids?: string[];
  segment_ids?: string[];
  tracking_code?: string;
  start_date?: string;
  end_date?: string;
  campaign_type?: CampaignType;
  email_template_id?: string | null;
  questionnaire_id?: string;
  variants?: Array<Record<string, unknown>>;
}

export interface MarketingCampaignSendIn {
  dry_run?: boolean;
  snapshot_ts?: number;
}

export interface MarketingCampaignSendOut {
  campaign_id: string;
  total_resolved: number;
  total_sent: number;
  total_skipped: number;
  dry_run: boolean;
  send_id?: string | null;
}

export interface MarketingCampaignAttributionOut {
  campaign_id: string;
  total_sent: number;
  email_sent: number;
  open_count: number;
  open_rate: number;
  click_count: number;
  click_rate: number;
}

export interface MarketingEmailPreviewIn {
  sample_party_id?: string;
  sample_vars?: Record<string, string>;
}

export interface MarketingEmailPreviewOut {
  subject: string;
  body_text: string;
  body_html: string | null;
  merge_vars_used: Record<string, string>;
  merge_vars_missing: string[];
}

// ─── Template endpoints ───────────────────────────────────────────────────────

export const listEmailTemplates = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<MarketingEmailTemplateListOut>("/ui/crm-marketing/email-templates", params);
};

export const getEmailTemplate = (templateId: string) =>
  api.get<MarketingEmailTemplate>(`/ui/crm-marketing/email-templates/${encodeURIComponent(templateId)}`);

export const createEmailTemplate = (body: MarketingEmailTemplateCreateIn) =>
  api.post<MarketingEmailTemplate>("/ui/crm-marketing/email-templates", body);

export const updateEmailTemplate = (templateId: string, body: MarketingEmailTemplateUpdateIn) =>
  api.patch<MarketingEmailTemplate>(
    `/ui/crm-marketing/email-templates/${encodeURIComponent(templateId)}`,
    body,
  );

export const deleteEmailTemplate = (templateId: string) =>
  api.del<{ ok: boolean }>(`/ui/crm-marketing/email-templates/${encodeURIComponent(templateId)}`);

export const previewEmailTemplate = (templateId: string, sampleVars: Record<string, string>) =>
  api.post<MarketingEmailTemplatePreviewOut>(
    `/ui/crm-marketing/email-templates/${encodeURIComponent(templateId)}/preview`,
    { sample_vars: sampleVars },
  );

// ─── Campaign endpoints ───────────────────────────────────────────────────────

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
  return api.get<MarketingCampaignListOut>("/ui/crm-marketing/campaigns", params);
};

export const getCampaign = (campaignId: string) =>
  api.get<CrmCampaign>(`/ui/crm-marketing/campaigns/${encodeURIComponent(campaignId)}`);

export const createCampaign = (body: CrmCampaignCreateIn) =>
  api.post<CrmCampaign>("/ui/crm-marketing/campaigns", body);

export const updateCampaign = (campaignId: string, body: CrmCampaignUpdateIn) =>
  api.patch<CrmCampaign>(`/ui/crm-marketing/campaigns/${encodeURIComponent(campaignId)}`, body);

export const deleteCampaign = (campaignId: string) =>
  api.del<{ ok: boolean }>(`/ui/crm-marketing/campaigns/${encodeURIComponent(campaignId)}`);

export const sendCampaign = (campaignId: string, body: MarketingCampaignSendIn = {}) =>
  api.post<MarketingCampaignSendOut>(
    `/ui/crm-marketing/campaigns/${encodeURIComponent(campaignId)}/send`,
    body,
  );

export const getCampaignAttribution = (campaignId: string) =>
  api.get<MarketingCampaignAttributionOut>(
    `/ui/crm-marketing/campaigns/${encodeURIComponent(campaignId)}/attribution`,
  );

export const previewCampaignEmail = (campaignId: string, body: MarketingEmailPreviewIn = {}) =>
  api.post<MarketingEmailPreviewOut>(
    `/ui/crm-marketing/campaigns/${encodeURIComponent(campaignId)}/preview-email`,
    body,
  );
