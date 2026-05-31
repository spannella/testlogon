import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export type BroadcastVisibility = "public" | "unlisted" | "private";

export interface BroadcastPrivacyState {
  session_id: string;
  visibility: BroadcastVisibility;
  updated_at: string | null;
  allowlist_count: number;
}

export interface BroadcastAllowlistEntry {
  viewer_id: string;
  added_by: string;
  created_at: number;
}

export interface BroadcastAllowlistResponse {
  session_id: string;
  entries: BroadcastAllowlistEntry[];
}

export interface BroadcastInviteToken {
  token: string;
  session_id: string;
  max_uses: number;
  use_count: number;
  created_at: number;
}

export interface BroadcastInviteTokenListResponse {
  session_id: string;
  tokens: BroadcastInviteToken[];
}

// ─── Visibility ─────────────────────────────────────────────────

export const getBroadcastPrivacy = (sessionId: string) =>
  api.get<BroadcastPrivacyState>(`/broadcast/sessions/${sessionId}/privacy`);

export const setBroadcastPrivacy = (sessionId: string, visibility: BroadcastVisibility) =>
  api.put<BroadcastPrivacyState>(`/broadcast/sessions/${sessionId}/privacy`, {
    visibility,
  });

// ─── Allowlist ──────────────────────────────────────────────────

export const listBroadcastAllowlist = (sessionId: string) =>
  api.get<BroadcastAllowlistResponse>(`/broadcast/sessions/${sessionId}/privacy/allowlist`);

export const addBroadcastAllowlistEntry = (sessionId: string, viewerId: string) =>
  api.post<BroadcastAllowlistEntry>(`/broadcast/sessions/${sessionId}/privacy/allowlist`, {
    viewer_id: viewerId,
  });

export const removeBroadcastAllowlistEntry = (sessionId: string, viewerId: string) =>
  api.del<{ ok: boolean; viewer_id: string }>(
    `/broadcast/sessions/${sessionId}/privacy/allowlist/${encodeURIComponent(viewerId)}`,
  );

// ─── Invite tokens ──────────────────────────────────────────────

export const listBroadcastInviteTokens = (sessionId: string) =>
  api.get<BroadcastInviteTokenListResponse>(`/broadcast/sessions/${sessionId}/privacy/tokens`);

export const createBroadcastInviteToken = (sessionId: string, maxUses = 1) =>
  api.post<BroadcastInviteToken>(`/broadcast/sessions/${sessionId}/privacy/tokens`, {
    max_uses: maxUses,
  });

export const revokeBroadcastInviteToken = (sessionId: string, token: string) =>
  api.del<{ ok: boolean; token: string }>(
    `/broadcast/sessions/${sessionId}/privacy/tokens/${encodeURIComponent(token)}`,
  );
