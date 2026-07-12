/**
 * Property Tenants API endpoint wrappers — TEN-001..TEN-004
 * Backend route prefix: /ui/property/tenants
 * Flag: PROPERTY_TENANTS_ENABLED (default false → 404 on all endpoints)
 */

import { api } from "@/api/client";

// ─── Inline TypeScript types (mirrors app/models.py TEN models) ──────────────

export interface PropertyTenantOut {
  tenant_id: string;
  owner_id: string;
  party_id: string;
  display_name: string;
  email: string | null;
  phone: string | null;
  status: "prospect" | "active" | "past";
  active_unit_id: string | null;
  created_at: number;
  updated_at: number;
}

export interface PropertyTenantListOut {
  tenants: PropertyTenantOut[];
  next_cursor: string | null;
  count: number;
}

export interface CreatePropertyTenantIn {
  display_name: string;
  email?: string | null;
  phone?: string | null;
  party_id?: string | null;
  correlation_id?: string | null;
}

export interface UpdatePropertyTenantIn {
  display_name?: string | null;
  email?: string | null;
  phone?: string | null;
  status?: "prospect" | "active" | "past" | null;
}

export interface EmploymentOut {
  employer_name?: string | null;
  job_title?: string | null;
  employment_type?: string | null;
  start_date?: string | null;
  employer_phone?: string | null;
}

export interface IncomeOut {
  annual_income_cents?: number | null;
  income_currency?: string;
  pay_frequency?: string | null;
  verification_status?: "unverified" | "pending" | "verified" | "rejected";
  verified_at?: number | null;
  verified_by?: string | null;
}

export interface EmergencyContactOut {
  ec_id: string;
  name: string;
  relationship?: string | null;
  phone?: string | null;
  email?: string | null;
}

export interface TenantProfileOut {
  employment: EmploymentOut;
  income: IncomeOut;
  emergency_contacts: EmergencyContactOut[];
  updated_at: number | null;
}

export interface TenantProfileIn {
  employment?: Partial<EmploymentOut> | null;
  income?: Partial<IncomeOut> | null;
  emergency_contacts?: Array<Partial<EmergencyContactOut> & { name: string }> | null;
}

export interface IncomeDocOut {
  doc_id: string;
  tenant_id: string;
  file_node_path: string;
  file_name: string;
  content_type: string;
  size_bytes: number;
  doc_kind: string;
  uploaded_at: number;
  uploaded_by: string;
}

export interface IncomeDocListOut {
  docs: IncomeDocOut[];
  next_cursor: string | null;
  count: number;
}

export interface TenantLeaseSummaryOut {
  lease_id: string;
  unit_id: string;
  status: "draft" | "upcoming" | "active" | "ended";
  start_date: number;
  end_date: number | null;
  monthly_rent_cents: number;
  security_deposit_cents: number;
  currency: string;
  lease_number?: string | null;
}

export interface TenantLeaseListOut {
  leases: TenantLeaseSummaryOut[];
  next_cursor: string | null;
  count: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "/ui/property/tenants";

// ─── Directory ───────────────────────────────────────────────────────────────

export const listPropertyTenants = (opts?: {
  status?: string;
  q?: string;
  cursor?: string;
  limit?: number;
}): Promise<PropertyTenantListOut> => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.q) params.q = opts.q;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit != null) params.limit = String(opts.limit);
  return api.get<PropertyTenantListOut>(BASE, params);
};

export const createPropertyTenant = (body: CreatePropertyTenantIn): Promise<PropertyTenantOut> =>
  api.post<PropertyTenantOut>(BASE, body);

export const getPropertyTenant = (tenantId: string): Promise<PropertyTenantOut> =>
  api.get<PropertyTenantOut>(`${BASE}/${tenantId}`);

export const updatePropertyTenant = (
  tenantId: string,
  body: UpdatePropertyTenantIn,
): Promise<PropertyTenantOut> =>
  api.patch<PropertyTenantOut>(`${BASE}/${tenantId}`, body);

// ─── Profile ─────────────────────────────────────────────────────────────────

export const getTenantProfile = (tenantId: string): Promise<TenantProfileOut> =>
  api.get<TenantProfileOut>(`${BASE}/${tenantId}/profile`);

export const updateTenantProfile = (
  tenantId: string,
  body: TenantProfileIn,
): Promise<TenantProfileOut> =>
  api.put<TenantProfileOut>(`${BASE}/${tenantId}/profile`, body);

export const setIncomeVerification = (tenantId: string, status: string): Promise<TenantProfileOut> =>
  api.put<TenantProfileOut>(`${BASE}/${tenantId}/income-verification`, { status });

export const setActiveUnit = (
  tenantId: string,
  propertyId: string | null,
  unitId: string | null,
): Promise<PropertyTenantOut> =>
  api.put<PropertyTenantOut>(`${BASE}/${tenantId}/active-unit`, {
    property_id: propertyId,
    unit_id: unitId,
  });

// ─── Income docs ──────────────────────────────────────────────────────────────

export const listIncomeDocs = (
  tenantId: string,
  opts?: { cursor?: string; limit?: number },
): Promise<IncomeDocListOut> => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit != null) params.limit = String(opts.limit);
  return api.get<IncomeDocListOut>(`${BASE}/${tenantId}/income-docs`, params);
};

export const uploadIncomeDoc = (
  tenantId: string,
  file: File,
  docKind: string,
): Promise<IncomeDocOut> => {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("doc_kind", docKind);
  return api.upload<IncomeDocOut>(`${BASE}/${tenantId}/income-docs`, fd);
};

export const deleteIncomeDoc = (tenantId: string, docId: string): Promise<void> =>
  api.del<void>(`${BASE}/${tenantId}/income-docs/${docId}`);

// ─── Lease history ────────────────────────────────────────────────────────────

export const listTenantLeases = (
  tenantId: string,
  opts?: { cursor?: string; limit?: number },
): Promise<TenantLeaseListOut> => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit != null) params.limit = String(opts.limit);
  return api.get<TenantLeaseListOut>(`${BASE}/${tenantId}/leases`, params);
};
