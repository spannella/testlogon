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

export interface RateLimitLiveSourceCount {
  source_ip: string;
  count: number;
}

export interface RateLimitLiveTimePoint {
  bucket: string;
  count: number;
}

export interface RateLimitLiveSummary {
  by_group: Record<string, number>;
  by_source: RateLimitLiveSourceCount[];
  time_series: RateLimitLiveTimePoint[];
  total_hits: number;
  window_hours: number;
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

// ── ADMIN-003: reset, live summary, CSV export ───────────────────

export const resetRateLimitConfig = (group: string) =>
  api.del<{ ok: boolean; group: string; is_override: boolean }>(
    `/ui/admin/rate-limits/config/${encodeURIComponent(group)}`,
  );

export const getRateLimitLiveSummary = (hours = 1) =>
  api.get<RateLimitLiveSummary>("/ui/admin/rate-limits/live-summary", {
    hours: String(hours),
  });

/**
 * Download the rate-limit event log as CSV.
 * Uses a raw fetch (the JSON api wrapper can't return a blob) and triggers a
 * browser download. Carries cookies + CSRF for the cookie-auth session.
 */
export async function exportRateLimitEvents(hours = 24, status?: string): Promise<void> {
  const params = new URLSearchParams({ hours: String(hours) });
  if (status) params.set("status", status);
  const res = await fetch(`/ui/admin/rate-limits/events/export?${params.toString()}`, {
    method: "GET",
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(`Export failed (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "rate-limit-events.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
