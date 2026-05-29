import { api } from "@/api/client";
import type { TenantOut, TenantCreateReq, TenantUpdateReq } from "@/api/types";

const BASE = "/v1/admin/tenants";

export async function createTenant(data: TenantCreateReq): Promise<TenantOut> {
  return api.post<TenantOut>(BASE, data);
}

export async function listTenants(params?: {
  limit?: number;
  cursor?: string;
  status?: string;
}): Promise<{ tenants: TenantOut[]; next_cursor: string | null }> {
  const qs: Record<string, string> = {};
  if (params?.limit) qs.limit = String(params.limit);
  if (params?.cursor) qs.cursor = params.cursor;
  if (params?.status) qs.status = params.status;
  return api.get<{ tenants: TenantOut[]; next_cursor: string | null }>(BASE, qs);
}

export async function getTenant(tenantId: string): Promise<TenantOut> {
  return api.get<TenantOut>(`${BASE}/${tenantId}`);
}

export async function updateTenant(
  tenantId: string,
  data: TenantUpdateReq,
): Promise<TenantOut> {
  return api.patch<TenantOut>(`${BASE}/${tenantId}`, data);
}

export async function deleteTenant(tenantId: string): Promise<TenantOut> {
  return api.del<TenantOut>(`${BASE}/${tenantId}`);
}

export async function addDomain(
  tenantId: string,
  domain: string,
): Promise<{ ok: boolean; tenant_id: string; domain: string }> {
  return api.post<{ ok: boolean; tenant_id: string; domain: string }>(`${BASE}/${tenantId}/domains`, { domain });
}

export async function removeDomain(
  tenantId: string,
  domain: string,
): Promise<void> {
  await api.del(`${BASE}/${tenantId}/domains/${encodeURIComponent(domain)}`);
}
