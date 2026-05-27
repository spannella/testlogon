import { api } from "@/api/client";

// ── Types ────────────────────────────────────────────────────────

export interface RateLimitGlobalIpConfig {
  window_seconds: number;
  max_requests: number;
  enabled: boolean;
}

export interface RateLimitGroupConfig {
  description: string;
  paths: string[];
  window_seconds: number;
  max_requests_per_user: number;
  max_requests_per_ip: number;
  bypass_roles: string[];
  is_override: boolean;
}

export interface RateLimitConfigResponse {
  global_ip: RateLimitGlobalIpConfig;
  groups: Record<string, RateLimitGroupConfig>;
}

export interface RateLimitUpdateConfigReq {
  group: string;
  window_seconds?: number;
  max_requests_per_user?: number;
  max_requests_per_ip?: number;
  bypass_roles?: string[];
}

export interface RateLimitEvent {
  pk: string;
  sk: string;
  endpoint_group: string;
  identity_type: string;
  identity_value: string;
  endpoint: string;
  method: string;
  status: string;
  count: number;
  limit: number;
}

export interface RateLimitEventsResponse {
  events: RateLimitEvent[];
  count: number;
}

export interface TopOffenderIp {
  ip: string;
  rejected_count: number;
  last_seen: number;
}

export interface TopOffenderUser {
  user_sub: string;
  rejected_count: number;
  last_seen: number;
}

export interface TopOffendersResponse {
  top_ips: TopOffenderIp[];
  top_users: TopOffenderUser[];
}

export interface BlocklistEntry {
  pk: string;
  sk: string;
  added_by: string;
  added_at: number;
  reason: string;
  ttl_epoch?: number;
}

export interface AllowlistEntry {
  pk: string;
  sk: string;
  added_by: string;
  added_at: number;
  reason: string;
}

// ── API calls ────────────────────────────────────────────────────

export const getRateLimitConfig = () =>
  api.get<RateLimitConfigResponse>("/ui/admin/rate-limits/config");

export const updateRateLimitConfig = (body: RateLimitUpdateConfigReq) =>
  api.put<{ ok: boolean }>("/ui/admin/rate-limits/config", body);

export const getRateLimitEvents = (hours = 1, limit = 100) =>
  api.get<RateLimitEventsResponse>("/ui/admin/rate-limits/events", {
    hours: String(hours),
    limit: String(limit),
  });

export const getTopOffenders = (hours = 1, limit = 20) =>
  api.get<TopOffendersResponse>("/ui/admin/rate-limits/top-offenders", {
    hours: String(hours),
    limit: String(limit),
  });

export const addToBlocklist = (body: { ip: string; reason?: string; expires_in_hours?: number }) =>
  api.post<{ ok: boolean }>("/ui/admin/rate-limits/blocklist", body);

export const removeFromBlocklist = (entryId: string) =>
  api.del<{ ok: boolean }>(`/ui/admin/rate-limits/blocklist/${entryId}`);

export const addToAllowlist = (body: { cidr: string; reason?: string }) =>
  api.post<{ ok: boolean }>("/ui/admin/rate-limits/allowlist", body);

export const removeFromAllowlist = (entryId: string) =>
  api.del<{ ok: boolean }>(`/ui/admin/rate-limits/allowlist/${encodeURIComponent(entryId)}`);

export const getBlocklist = () =>
  api.get<{ entries: BlocklistEntry[] }>("/ui/admin/rate-limits/blocklist");

export const getAllowlist = () =>
  api.get<{ entries: AllowlistEntry[] }>("/ui/admin/rate-limits/allowlist");
