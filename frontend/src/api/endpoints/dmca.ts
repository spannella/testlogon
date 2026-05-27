import { api } from "../client";

// Types
export interface DmcaClaimIn {
  claimant_name: string;
  claimant_email: string;
  claimant_address: string;
  claimant_phone?: string;
  content_url: string;
  content_type: "feed_post" | "feed_media" | "message_media" | "video" | "other";
  content_id?: string;
  original_work_description: string;
  sworn_statement: boolean;
  good_faith_belief: boolean;
  signature: string;
}

export interface DmcaClaimOut {
  claim_id: string;
  status: string;
  claimant_name: string;
  claimant_email: string;
  content_url: string;
  content_type: string;
  content_id: string;
  target_user_id: string;
  original_work_description: string;
  created_at: number;
  updated_at: number;
  content_removed_at?: number;
  counter_notice_filed_at?: number;
  waiting_period_expires_at?: number;
  resolved_at?: number;
  resolution?: string;
  strike_number: number;
}

export interface DmcaClaimCreateOut {
  ok: boolean;
  claim_id: string;
  status: string;
  content_removed: boolean;
  strike_number: number;
  created_at: number;
}

export interface DmcaCounterNoticeIn {
  counter_notice_text: string;
  consent_to_jurisdiction: boolean;
  counter_notice_signature: string;
}

export interface DmcaCounterNoticeOut {
  ok: boolean;
  claim_id: string;
  status: string;
  waiting_period_expires_at: number;
  counter_notice_filed_at: number;
}

export interface DmcaClaimListOut {
  items: DmcaClaimOut[];
  next_cursor?: string;
}

export interface DmcaResolveIn {
  resolution: "restored" | "upheld" | "court_order" | "withdrawn";
  resolution_notes?: string;
}

export interface DmcaResolveOut {
  ok: boolean;
  claim_id: string;
  status: string;
  resolution: string;
  resolved_at: number;
}

export interface DmcaAgentConfig {
  agent_name: string;
  agent_email: string;
  agent_address: string;
  agent_phone?: string;
}

export interface RepeatInfringerStatus {
  user_id: string;
  total_claims: number;
  upheld_claims: number;
  strike_count: number;
  threshold: number;
  status: string;
  claim_history: Array<Record<string, unknown>>;
}

// Public endpoints
export const submitDmcaClaim = (data: DmcaClaimIn) =>
  api.post<DmcaClaimCreateOut>("/v1/dmca/claims", data);

export const getDmcaClaim = (claimId: string) =>
  api.get<DmcaClaimOut>(`/v1/dmca/claims/${claimId}`);

export const fileCounterNotice = (claimId: string, data: DmcaCounterNoticeIn) =>
  api.post<DmcaCounterNoticeOut>(`/v1/dmca/claims/${claimId}/counter-notice`, data);

export const getDmcaAgentInfo = () =>
  api.get<DmcaAgentConfig>("/v1/dmca/agent-info");

// Admin endpoints
export const listDmcaClaims = (params?: Record<string, string>) =>
  api.get<DmcaClaimListOut>("/v1/admin/dmca/claims", params);

export const getDmcaClaimDetail = (claimId: string) =>
  api.get<Record<string, unknown>>(`/v1/admin/dmca/claims/${claimId}`);

export const resolveDmcaClaim = (claimId: string, data: DmcaResolveIn) =>
  api.post<DmcaResolveOut>(`/v1/admin/dmca/claims/${claimId}/resolve`, data);

export const getInfringerStatus = (userId: string) =>
  api.get<RepeatInfringerStatus>(`/v1/admin/dmca/users/${userId}/infringer-status`);

export const updateDmcaAgentConfig = (data: DmcaAgentConfig) =>
  api.put<DmcaAgentConfig>("/v1/admin/dmca/agent-config", data);
