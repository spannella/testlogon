import { api } from "../client";
import type { SsoInfoOut, SsoProviderOut, SsoProviderStatsOut } from "../types";

// ── Public endpoints ───────────────────────────────────────────

export function getSsoInfo(tenant = "default"): Promise<SsoInfoOut> {
  return api.get<SsoInfoOut>("/ui/sso/info", { tenant });
}

// ── Admin endpoints ────────────────────────────────────────────

export function listSsoProviders(tenantId = "default"): Promise<{ providers: SsoProviderOut[] }> {
  return api.get<{ providers: SsoProviderOut[] }>("/v1/admin/sso/providers", { tenant_id: tenantId });
}

export function getSsoProvider(providerId: string, tenantId = "default"): Promise<SsoProviderOut> {
  return api.get<SsoProviderOut>(`/v1/admin/sso/providers/${providerId}`, { tenant_id: tenantId });
}

export function createSsoProvider(data: {
  display_name: string;
  protocol?: string;
  tenant_id?: string;
  metadata_xml?: string;
  sso_only?: boolean;
  jit_provisioning_enabled?: boolean;
  auto_update_profile?: boolean;
  auto_update_role?: boolean;
  default_role?: string;
  allowed_email_domains?: string[];
}): Promise<SsoProviderOut> {
  return api.post<SsoProviderOut>("/v1/admin/sso/providers", data);
}

export function updateSsoProvider(
  providerId: string,
  data: Record<string, unknown>,
): Promise<SsoProviderOut> {
  return api.patch<SsoProviderOut>(`/v1/admin/sso/providers/${providerId}`, data);
}

export function deleteSsoProvider(providerId: string, tenantId = "default"): Promise<{ ok: boolean }> {
  return api<{ ok: boolean }>(`/v1/admin/sso/providers/${providerId}?tenant_id=${tenantId}`, { method: "DELETE" });
}

export function uploadSsoMetadata(
  providerId: string,
  metadataXml: string,
  tenantId = "default",
): Promise<SsoProviderOut> {
  return api.post<SsoProviderOut>(
    `/v1/admin/sso/providers/${providerId}/metadata`,
    { metadata_xml: metadataXml, tenant_id: tenantId },
  );
}

export function setSsoRoleMappings(
  providerId: string,
  roleMappings: Array<{ idp_group: string; platform_role: string; admin_profile?: Record<string, unknown> }>,
  tenantId = "default",
): Promise<SsoProviderOut> {
  return api.post<SsoProviderOut>(
    `/v1/admin/sso/providers/${providerId}/role-mappings`,
    { role_mappings: roleMappings, tenant_id: tenantId },
  );
}

export function setSsoAttributeMappings(
  providerId: string,
  attributeMappings: Record<string, string>,
  tenantId = "default",
): Promise<SsoProviderOut> {
  return api.post<SsoProviderOut>(
    `/v1/admin/sso/providers/${providerId}/attribute-mappings`,
    { attribute_mappings: attributeMappings, tenant_id: tenantId },
  );
}

export function getSsoProviderStats(
  providerId: string,
  tenantId = "default",
): Promise<SsoProviderStatsOut> {
  return api.get<SsoProviderStatsOut>(
    `/v1/admin/sso/providers/${providerId}/stats`,
    { tenant_id: tenantId },
  );
}
