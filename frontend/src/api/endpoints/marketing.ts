import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz MARKETING (MKT) — endpoint wrappers + inline types.
// LIVE router: app/routers/marketing_campaigns.py
//   /ui/marketing/*  (require_ui_session, admin-oriented)
//   /ui/admin/marketing/*  (require_admin_or_root)
// Flag MARKETING_CAMPAIGNS_ENABLED defaults OFF → write endpoints 404.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Campaign types ──────────────────────────────────────────────────────────

export type CampaignObjective = "awareness" | "traffic" | "conversions" | "retention";

export type CampaignStatus =
  | "draft"
  | "scheduled"
  | "active"
  | "paused"
  | "completed"
  | "archived";

export interface MarketingCampaign {
  campaign_id: string;
  owner_id: string;
  name: string;
  objective: string;
  status: string;
  budget_cents: number;
  ad_campaign_id?: string | null;
  ad_account_id?: string | null;
  promo_code_ids: string[];
  contact_list_ids: string[];
  segment_ids: string[];
  tracking_code?: string | null;
  start_date?: number | null;
  end_date?: number | null;
  created_at: number;
  updated_at: number;
}

export interface MarketingCampaignCreateIn {
  name: string;
  objective: CampaignObjective;
  budget_cents: number;
  ad_campaign_id?: string | null;
  promo_code_ids?: string[];
  contact_list_ids?: string[];
  segment_ids?: string[];
  tracking_code?: string | null;
  start_date?: number | null;
  end_date?: number | null;
}

export interface MarketingCampaignUpdateIn {
  name?: string;
  objective?: CampaignObjective;
  budget_cents?: number;
  status?: string;
  ad_campaign_id?: string | null;
  promo_code_ids?: string[];
  contact_list_ids?: string[];
  segment_ids?: string[];
  tracking_code?: string | null;
  start_date?: number | null;
  end_date?: number | null;
}

export interface CampaignListResp {
  campaigns: MarketingCampaign[];
  cursor?: string | null;
}

export interface CampaignSendResp {
  campaign_id: string;
  sent_count: number;
  skipped_count: number;
  snapshot_ts: number;
}

export interface CampaignAttribution {
  campaign_id: string;
  ad_spend_cents: number;
  promo_discount_cents: number;
  promo_redemptions: number;
  tracking_visits: number;
  tracking_orders: number;
  as_of: number;
}

// ─── Contact-list types ──────────────────────────────────────────────────────

export interface ContactList {
  list_id: string;
  owner_id: string;
  name: string;
  description?: string | null;
  member_count: number;
  created_at: number;
  updated_at: number;
}

export interface ContactListCreateIn {
  name: string;
  description?: string | null;
}

export interface ContactListUpdateIn {
  name?: string;
  description?: string | null;
}

export interface ContactListMember {
  list_id: string;
  party_id: string;
  joined_at?: number;
  suppressed?: boolean;
  display_name?: string | null;
  // raw rows may carry pk/sk plus other denormalized fields
  [k: string]: unknown;
}

export interface SeedFromContactsResp {
  list_id: string;
  added: number;
  skipped: number;
}

// ─── Segment types ───────────────────────────────────────────────────────────

export type SegmentOperator = "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "in" | "not_in";

export const SEGMENT_ATTRIBUTES = [
  "subscription_tier",
  "total_spend_cents",
  "profile_country",
  "profile_city",
  "display_name",
  "first_name",
  "last_name",
  "gender",
  "location",
  "locale",
  "birthday",
  "has_active_subscription",
  "subscription_status",
  "order_count",
  "total_paid_cents",
  "last_order_at",
] as const;

export const SEGMENT_OPERATORS: SegmentOperator[] = [
  "eq",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "in",
  "not_in",
];

export interface SegmentPredicate {
  attribute: string;
  operator: string;
  value: unknown;
}

export interface PartySegment {
  segment_id: string;
  owner_id: string;
  name: string;
  description?: string | null;
  predicates: SegmentPredicate[];
  candidate_source?: string | null;
  created_at: number;
  updated_at: number;
}

export interface PartySegmentCreateIn {
  name: string;
  description?: string | null;
  predicates: SegmentPredicate[];
  candidate_source?: string | null;
}

export interface PartySegmentUpdateIn {
  name?: string;
  description?: string | null;
  predicates?: SegmentPredicate[];
  candidate_source?: string | null;
}

export interface SegmentEvalMember {
  party_id: string;
  opted_out: boolean;
}

export interface SegmentSnapshot {
  segment_id: string;
  snap_id: string;
  snap_ts: number;
  party_count: number;
  opted_out_count?: number;
  created_at?: number;
  [k: string]: unknown;
}

export interface SnapshotMember {
  party_id: string;
  snap_id: string;
  opted_out: boolean;
  snapped_at: number;
  [k: string]: unknown;
}

export interface SnapshotMembersResp {
  members: SnapshotMember[];
  cursor?: string | null;
}

// ─── Tracking-code types ─────────────────────────────────────────────────────

export interface TrackingCode {
  code_slug: string;
  campaign_id: string;
  owner_id: string;
  visit_count: number;
  order_count: number;
  created_at: number;
  [k: string]: unknown;
}

export interface TrackingCodeCreateIn {
  code_slug: string;
  campaign_id: string;
}

// ─── Campaign endpoints ──────────────────────────────────────────────────────

export const listCampaigns = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CampaignListResp>("/ui/marketing/campaigns", params);
};

export const getCampaign = (campaignId: string) =>
  api.get<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}`);

export const createCampaign = (body: MarketingCampaignCreateIn) =>
  api.post<MarketingCampaign>("/ui/marketing/campaigns", body);

export const updateCampaign = (campaignId: string, body: MarketingCampaignUpdateIn) =>
  api.patch<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}`, body);

export const transitionCampaign = (campaignId: string, targetStatus: string) =>
  api.post<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}/transition`, {
    target_status: targetStatus,
  });

export const sendCampaign = (campaignId: string) =>
  api.post<CampaignSendResp>(`/ui/marketing/campaigns/${campaignId}/send`, {});

export const getCampaignAttribution = (campaignId: string) =>
  api.get<CampaignAttribution>(`/ui/marketing/campaigns/${campaignId}/attribution`);

export const attachAdCampaign = (campaignId: string, adCampaignId: string) =>
  api.post<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}/ad-campaign`, undefined, {
    ad_campaign_id: adCampaignId,
  });

export const detachAdCampaign = (campaignId: string) =>
  api.del<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}/ad-campaign`);

export const attachPromoCode = (campaignId: string, codeId: string) =>
  api.post<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}/promo-codes/${codeId}`, {});

export const detachPromoCode = (campaignId: string, codeId: string) =>
  api.del<MarketingCampaign>(`/ui/marketing/campaigns/${campaignId}/promo-codes/${codeId}`);

// ─── Contact-list endpoints ──────────────────────────────────────────────────

export const listContactLists = () =>
  api.get<ContactList[]>("/ui/marketing/lists");

export const getContactList = (listId: string) =>
  api.get<ContactList>(`/ui/marketing/lists/${listId}`);

export const createContactList = (body: ContactListCreateIn) =>
  api.post<ContactList>("/ui/marketing/lists", body);

export const updateContactList = (listId: string, body: ContactListUpdateIn) =>
  api.patch<ContactList>(`/ui/marketing/lists/${listId}`, body);

export const deleteContactList = (listId: string) =>
  api.del<{ ok: boolean }>(`/ui/marketing/lists/${listId}`);

export const listContactListMembers = (listId: string, includeSuppressed = true) =>
  api.get<ContactListMember[]>(`/ui/marketing/lists/${listId}/members`, {
    include_suppressed: String(includeSuppressed),
  });

export const addContactListMember = (listId: string, partyId: string) =>
  api.post<ContactListMember>(`/ui/marketing/lists/${listId}/members`, { party_id: partyId });

export const removeContactListMember = (listId: string, partyId: string) =>
  api.del<{ ok: boolean }>(`/ui/marketing/lists/${listId}/members/${partyId}`);

export const seedListFromContacts = (listId: string) =>
  api.post<SeedFromContactsResp>(`/ui/marketing/lists/${listId}/seed-from-contacts`, {});

// ─── Segment endpoints ───────────────────────────────────────────────────────

export const listSegments = () =>
  api.get<PartySegment[]>("/ui/marketing/segments");

export const getSegment = (segmentId: string) =>
  api.get<PartySegment>(`/ui/marketing/segments/${segmentId}`);

export const createSegment = (body: PartySegmentCreateIn) =>
  api.post<PartySegment>("/ui/marketing/segments", body);

export const updateSegment = (segmentId: string, body: PartySegmentUpdateIn) =>
  api.patch<PartySegment>(`/ui/marketing/segments/${segmentId}`, body);

export const deleteSegment = (segmentId: string) =>
  api.del<{ ok: boolean }>(`/ui/marketing/segments/${segmentId}`);

export const evaluateSegment = (segmentId: string) =>
  api.get<SegmentEvalMember[]>(`/ui/marketing/segments/${segmentId}/evaluate`);

export const snapshotSegment = (segmentId: string) =>
  api.post<SegmentSnapshot>(`/ui/marketing/segments/${segmentId}/snapshot`, {});

export const listSegmentSnapshots = (segmentId: string, limit = 10) =>
  api.get<SegmentSnapshot[]>(`/ui/marketing/segments/${segmentId}/snapshots`, {
    limit: String(limit),
  });

export const listSnapshotMembers = (
  segmentId: string,
  snapId: string,
  includeOptedOut = true,
) =>
  api.get<SnapshotMembersResp>(
    `/ui/marketing/segments/${segmentId}/snapshots/${snapId}/members`,
    { include_opted_out: String(includeOptedOut) },
  );

// ─── Tracking-code endpoints ─────────────────────────────────────────────────

export const createTrackingCode = (body: TrackingCodeCreateIn) =>
  api.post<TrackingCode>("/ui/marketing/tracking-codes", body);

export const getTrackingCode = (codeSlug: string) =>
  api.get<TrackingCode>(`/ui/marketing/tracking-codes/${codeSlug}`);

// ─── Admin endpoints ─────────────────────────────────────────────────────────

export const adminListCampaigns = (status: string, limit = 50) =>
  api.get<MarketingCampaign[]>("/ui/admin/marketing/campaigns", {
    status,
    limit: String(limit),
  });

export const adminReviewCampaign = (campaignId: string, targetStatus: string) =>
  api.patch<MarketingCampaign>(`/ui/admin/marketing/campaigns/${campaignId}/review`, {
    target_status: targetStatus,
  });
