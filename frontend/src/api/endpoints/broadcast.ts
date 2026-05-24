import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export type BroadcastSessionStatus =
  | "draft"
  | "provisioning"
  | "ready"
  | "live"
  | "stopping"
  | "stopped"
  | "error";

export interface BroadcastProfile {
  id: string;
  name: string;
  region: string;
  rendition_preset: string;
  watermark_asset: string | null;
  drm_policy_id: string | null;
  drm_credentials_ref: string | null;
  drm_credentials_last_rotated_at: string | null;
  drm_credentials_rotation_interval_seconds: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface BroadcastSession {
  id: string;
  profile_id: string;
  status: BroadcastSessionStatus;
  ingest_url: string | null;
  stream_key_ref: string | null;
  stream_key_last_rotated_at: string | null;
  stream_key_rotation_interval_seconds: number;
  started_at: string | null;
  stopped_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  mediapackage_endpoint: string | null;
  cloudfront_playback_url: string | null;
  s3_archive_prefix: string | null;
  aws_input_arn: string | null;
  aws_channel_arn: string | null;
  provider_state_snapshot: Record<string, unknown>;
}

export interface BroadcastPlaybackUrl {
  session_id: string;
  playback_url: string;
  expires_at: number;
}

export interface BroadcastAuditEntry {
  audit_id: string;
  action: string;
  actor: string;
  correlation_id: string;
  resource_type: string;
  resource_id: string;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface SessionListResponse {
  items: BroadcastSession[];
  has_more: boolean;
}

export interface ProfileListResponse {
  items: BroadcastProfile[];
}

export interface AuditListResponse {
  items: BroadcastAuditEntry[];
}

export interface CreateProfileReq {
  name: string;
  region: string;
  rendition_preset: string;
  watermark_asset?: string | null;
  drm_policy_id?: string | null;
  drm_credentials_ref?: string | null;
  drm_credentials_rotation_interval_seconds?: number;
}

export interface CreateSessionReq {
  profile_id: string;
  ingest_url?: string | null;
  stream_key_ref?: string | null;
  stream_key_rotation_interval_seconds?: number;
}

export interface SessionActionReq {
  reason?: string;
}

// ─── API functions ──────────────────────────────────────────────

export const listSessions = (params?: { status?: string }) =>
  api.get<SessionListResponse>("/broadcast/sessions", params as Record<string, string>);

export const getSession = (id: string) =>
  api.get<BroadcastSession>(`/broadcast/sessions/${id}`);

export const listProfiles = () =>
  api.get<ProfileListResponse>("/broadcast/profiles");

export const createProfile = (body: CreateProfileReq) =>
  api.post<BroadcastProfile>("/broadcast/profiles", body);

export const createSession = (body: CreateSessionReq) =>
  api.post<BroadcastSession>("/broadcast/sessions", body);

export const startSession = (id: string, body?: SessionActionReq) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${id}/start`, body ?? { reason: "operator-request" });

export const stopSession = (id: string, body?: SessionActionReq) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${id}/stop`, body ?? { reason: "operator-request" });

export const deleteSession = (id: string) =>
  api.del<{ ok: boolean }>(`/broadcast/sessions/${id}`);

export const mintPlaybackUrl = (id: string) =>
  api.post<BroadcastPlaybackUrl>(`/broadcast/sessions/${id}/playback-url`);

export const getAuditLog = (params?: { actor?: string; limit?: number }) =>
  api.get<AuditListResponse>("/broadcast/admin/audit", params as Record<string, string>);

// ─── Viewer Count API ──────────────────────────────────────────────

export interface ViewerJoinResponse {
  viewer_id: string;
  session_id: string;
  viewer_count: number;
}

export interface ViewerHeartbeatResponse {
  ok: boolean;
  viewer_count: number;
}

export interface ViewerCountResponse {
  session_id: string;
  viewer_count: number;
}

export const viewerJoin = (sessionId: string) =>
  api.post<ViewerJoinResponse>(`/broadcast/sessions/${sessionId}/viewers/join`);

export const viewerHeartbeat = (sessionId: string, viewerId: string) =>
  api.post<ViewerHeartbeatResponse>(
    `/broadcast/sessions/${sessionId}/viewers/heartbeat`,
    null,
    { params: { viewer_id: viewerId } } as never,
  );

export const viewerLeave = (sessionId: string, viewerId: string) =>
  api.post<{ ok: boolean; viewer_count: number }>(
    `/broadcast/sessions/${sessionId}/viewers/leave`,
    null,
    { params: { viewer_id: viewerId } } as never,
  );

export const getViewerCount = (sessionId: string) =>
  api.get<ViewerCountResponse>(`/broadcast/sessions/${sessionId}/viewers/count`);

// ─── Health Metrics API ────────────────────────────────────────────

export interface BroadcastHealthReport {
  ingest_bitrate_kbps: number;
  ingest_framerate: number;
  dropped_frames: number;
  dropped_frames_pct: number;
  output_errors?: number;
  input_loss_seconds?: number;
}

export interface BroadcastHealthResponse {
  session_id: string;
  viewer_count: number;
  ingest_bitrate_kbps: number;
  ingest_framerate: number;
  dropped_frames: number;
  dropped_frames_pct: number;
  connection_quality: string;
  output_errors: number;
  input_loss_seconds: number;
  updated_at: number;
}

export interface BroadcastHealthHistoryResponse {
  session_id: string;
  snapshots: BroadcastHealthResponse[];
}

export const reportHealth = (sessionId: string, data: BroadcastHealthReport) =>
  api.post<BroadcastHealthResponse>(`/broadcast/sessions/${sessionId}/health/report`, data);

export const getHealth = (sessionId: string) =>
  api.get<BroadcastHealthResponse>(`/broadcast/sessions/${sessionId}/health`);

export const getHealthHistory = (sessionId: string, params?: { from_ts?: number; to_ts?: number; limit?: number }) =>
  api.get<BroadcastHealthHistoryResponse>(`/broadcast/sessions/${sessionId}/health/history`, params as Record<string, string>);
