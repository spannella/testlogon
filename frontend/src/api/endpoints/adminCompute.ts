import { api } from "@/api/client";
import type {
  AdminInstanceListOut,
  AdminPodListOut,
  ComputeQuota,
  ForceTerminateReq,
  InstanceTypeStatsOut,
  PerUserSpendingOut,
  PlatformSpendingOut,
  SetQuotaReq,
} from "@/api/types";

const BASE = "/v1/admin/compute";

export const listAdminInstances = (params?: {
  status?: string;
  user_sub?: string;
  instance_type?: string;
  limit?: number;
  cursor?: string;
}) => {
  const p: Record<string, string> = {};
  if (params?.status) p.status = params.status;
  if (params?.user_sub) p.user_sub = params.user_sub;
  if (params?.instance_type) p.instance_type = params.instance_type;
  if (params?.limit != null) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<AdminInstanceListOut>(`${BASE}/instances`, p);
};

export const listAdminPods = (params?: {
  status?: string;
  user_sub?: string;
  limit?: number;
  cursor?: string;
}) => {
  const p: Record<string, string> = {};
  if (params?.status) p.status = params.status;
  if (params?.user_sub) p.user_sub = params.user_sub;
  if (params?.limit != null) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<AdminPodListOut>(`${BASE}/pods`, p);
};

export const forceTerminateInstance = (
  userSub: string,
  instanceId: string,
  body: ForceTerminateReq,
) =>
  api.post(
    `${BASE}/instances/${encodeURIComponent(userSub)}/${encodeURIComponent(instanceId)}/terminate`,
    body,
  );

export const forceTerminatePod = (
  userSub: string,
  podId: string,
  body: ForceTerminateReq,
) =>
  api.post(
    `${BASE}/pods/${encodeURIComponent(userSub)}/${encodeURIComponent(podId)}/terminate`,
    body,
  );

export const getPlatformSpending = (month?: string) =>
  api.get<PlatformSpendingOut>(`${BASE}/spending`, month ? { month } : undefined);

export const getPerUserSpending = (month?: string) =>
  api.get<PerUserSpendingOut>(`${BASE}/spending/users`, month ? { month } : undefined);

export const getInstanceTypeStats = () =>
  api.get<InstanceTypeStatsOut>(`${BASE}/stats/instance-types`);

export const getComputeQuota = (userSub: string) =>
  api.get<ComputeQuota>(`${BASE}/quotas/${encodeURIComponent(userSub)}`);

export const setComputeQuota = (userSub: string, body: SetQuotaReq) =>
  api.put<ComputeQuota>(`${BASE}/quotas/${encodeURIComponent(userSub)}`, body);

export const deleteComputeQuota = (userSub: string) =>
  api.del<{ ok: boolean }>(`${BASE}/quotas/${encodeURIComponent(userSub)}`);
