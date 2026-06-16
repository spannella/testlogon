/**
 * Property Management Dashboard & Rent-Policy API endpoints (PMD-001..PMD-003).
 *
 * Flag-gated: PROPERTY_DASHBOARD_ENABLED (default OFF).
 * When the flag is off the backend returns HTTP 404 for every endpoint.
 * Callers should handle ApiError.status === 404 as "feature not enabled".
 *
 * Routes under /ui/portfolio and /ui/rent-policy are proxied by Vite → backend.
 * Routes under /ui/property-documents are likewise proxied.
 */

import { api } from "@/api/client";

// ─── Inline TypeScript interfaces (mirrors app/models.py PMD models) ───────

// PMD-003 — Portfolio KPIs
export interface PortfolioKpis {
  occupancy_rate: number;       // 0.0–1.0; 0.0 when no units
  unit_count: number;
  occupied_units: number;
  active_lease_count: number;
  outstanding_rent_cents: number;
  open_work_order_count: number;
  computed_at: number;          // Unix seconds
}

// PMD-003 — Monthly rent snapshot
export interface RentSnapshot {
  year: number;
  month: number;
  charged_cents: number;
  collected_cents: number;
  outstanding_cents: number;
  overdue_cents: number;
  rent_due_day: number;
  grace_period_days: number;
  computed_at: number;
}

// PMD-003 — Single priority item (polymorphic)
export interface PriorityItem {
  kind: string;                   // "lease_expiring" | "open_work_order" | "open_ticket"
  // Lease-expiring fields
  lease_id?: string;
  lease_number?: string;
  unit_id?: string;
  property_id?: string;
  tenant_id?: string;
  end_date?: number;              // Unix seconds
  monthly_rent_cents?: number;
  // Work-order / ticket fields
  work_order_id?: string;
  ticket_id?: string;
  subject?: string;
  title?: string;
  status?: string;
  priority?: string;
  updated_at?: number;
}

export interface PriorityItems {
  upcoming_expirations: PriorityItem[];
  open_work_orders: PriorityItem[];
  items: PriorityItem[];
  count: number;
}

// PMD-001 — Rent policy
export interface RentPolicy {
  rent_due_day: number;           // 1–28
  late_fee_cents: number;         // >= 0
  grace_period_days: number;      // >= 0
  currency: string;               // lowercase ISO-4217, e.g. "usd"
  updated_at: number | null;
  updated_by: string | null;
  is_default: boolean;
}

export interface RentPolicyUpdateIn {
  rent_due_day: number;
  late_fee_cents: number;
  grace_period_days: number;
  currency: string;
}

// PMD-001 — Audit log
export interface RentPolicyAuditEntry {
  actor_sub: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown>;
  created_at: number;
}

export interface RentPolicyAuditOut {
  entries: RentPolicyAuditEntry[];
  count: number;
  cursor?: string | null;
}

// PMD-002 — Property document link
export type PropertyDocumentRecordType = "property" | "unit" | "lease" | "tenant";

export interface PropertyDocumentLink {
  doc_id: string;
  record_type: string;
  record_id: string;
  file_path: string;
  crm_category: string;
  crm_description: string;
  linked_at: number | null;
  owner_sub: string;
}

export interface PropertyDocumentListOut {
  items: PropertyDocumentLink[];
  count: number;
  cursor?: string | null;
}

export interface PropertyDocumentLinkIn {
  record_type: PropertyDocumentRecordType;
  record_id: string;
  doc_id: string;
  file_path?: string;
  crm_category?: string;
  crm_description?: string;
}

export interface PropertyDocumentUnlinkIn {
  record_type: string;
  record_id: string;
  doc_id: string;
}

// ─── PMD-003 Portfolio KPI / snapshot / priority (GET /ui/portfolio/*) ───────

export const getPortfolioKpis = () =>
  api.get<PortfolioKpis>("/ui/portfolio/kpis");

export const getRentSnapshot = (year: number, month: number) =>
  api.get<RentSnapshot>("/ui/portfolio/rent-snapshot", {
    year: String(year),
    month: String(month),
  });

export const getPriorityItems = (limit = 20) =>
  api.get<PriorityItems>("/ui/portfolio/priority-items", {
    limit: String(limit),
  });

// ─── PMD-001 Rent policy (GET/PUT /ui/rent-policy) ────────────────────────────

export const getRentPolicy = () =>
  api.get<RentPolicy>("/ui/rent-policy");

export const updateRentPolicy = (body: RentPolicyUpdateIn) =>
  api.put<RentPolicy>("/ui/rent-policy", body);

export const getRentPolicyAudit = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<RentPolicyAuditOut>("/ui/rent-policy/audit", params);
};

// ─── PMD-002 Property documents (GET/POST/DELETE /ui/property-documents) ─────

export const linkPropertyDocument = (body: PropertyDocumentLinkIn) =>
  api.post<PropertyDocumentLink>("/ui/property-documents/link", body);

export const unlinkPropertyDocument = (body: PropertyDocumentUnlinkIn) =>
  api<void>("/ui/property-documents/link", {
    method: "DELETE",
    body: JSON.stringify(body),
  });

export const listPropertyDocuments = (
  recordType: PropertyDocumentRecordType,
  recordId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<PropertyDocumentListOut>(
    `/ui/property-documents/${recordType}/${recordId}`,
    params,
  );
};
