/**
 * Maintenance Work Orders + Vendor Directory API wrappers — WOV-001..WOV-005
 * Backend route prefix: /ui  (cookie-session auth)
 * Master flag: MAINTENANCE_ORDERS_ENABLED (default false → 404 on all endpoints)
 *
 * Mutations (assign, schedule, transition, create vendor) require admin/root role.
 * Reads are available to any authenticated session.
 */

import { api } from "@/api/client";

// ─── Inline TypeScript types (mirrors app/models.py WOV models) ──────────────

export type WoPriority = "urgent" | "high" | "normal" | "low";
export type WoStatus = "open" | "assigned" | "in_progress" | "completed" | "cancelled";

export interface MaintenanceOrderOut {
  work_order_id: string;
  property_id: string;
  unit_id: string | null;
  vendor_id: string | null;
  assignee_sub: string | null;
  title: string;
  description: string | null;
  priority: WoPriority;
  wo_status: WoStatus;
  scheduled_for: number | null;   // Unix ts
  cost_cents: number | null;
  created_at: number;             // Unix ts
  updated_at: number;             // Unix ts
  completed_at: number | null;    // Unix ts
  correlation_id: string;
  actor_sub: string;
  escrow_amount_cents: number | null;  // WOV-003
  escrow_status: string | null;        // WOV-003: "held" | "released" | "refunded"
}

export interface WoListOut {
  items: MaintenanceOrderOut[];
  count: number;
  cursor: string | null;
}

export interface MaintenanceOrderIn {
  title: string;
  description?: string;
  priority?: WoPriority;
  property_id: string;
  unit_id?: string;
  scheduled_for?: number;
  correlation_id?: string;
  /** WOV-003 optional escrow amount in cents (ignored when escrow sub-flag off) */
  amount_cents?: number;
}

export interface MaintenanceOrderAssignIn {
  property_id: string;
  vendor_id?: string;
  unit_id?: string;
  assignee_sub?: string;
}

export interface MaintenanceOrderScheduleIn {
  property_id: string;
  scheduled_for: number;
}

export interface MaintenanceOrderTransitionIn {
  property_id: string;
  target_status: "assigned" | "in_progress" | "completed" | "cancelled";
  cost_cents?: number;
  assignee_sub?: string;
  vendor_id?: string;
}

export interface WoBoardColumn {
  column_id: string;
  title: string;
  status_key: WoStatus;
  order: number;
}

// ─── Vendor types ─────────────────────────────────────────────────────────────

export type VendorStatus = "active" | "inactive";
export type VendorTradeCategory =
  | "plumbing"
  | "electrical"
  | "hvac"
  | "handyman"
  | "cleaning"
  | "landscaping"
  | "general";

export interface VendorOut {
  vendor_id: string;
  name: string;
  status: VendorStatus;
  trade_category: string;
  source: string;
  email: string | null;
  phone: string | null;
  address: Record<string, unknown> | null;
  default_currency: string;
  payment_terms_days: number;
  user_sub: string | null;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface VendorListOut {
  vendors: VendorOut[];
  count: number;
  cursor: string | null;
}

export interface VendorCreateIn {
  name: string;
  trade_category: string;
  email?: string;
  phone?: string;
  address?: Record<string, unknown>;
  default_currency?: string;
  payment_terms_days?: number;
  user_sub?: string;
}

export interface VendorPatchIn {
  name?: string;
  trade_category?: string;
  email?: string;
  phone?: string;
  address?: Record<string, unknown>;
  default_currency?: string;
  payment_terms_days?: number;
  user_sub?: string;
}

// ─── Work-order board columns ─────────────────────────────────────────────────

export const getBoardColumns = () =>
  api.get<{ columns: WoBoardColumn[] }>("/ui/maintenance/work-orders/board-columns");

// ─── Work-order list (system-wide, by status or assignee) ────────────────────

export const listWorkOrders = (params?: {
  wo_status?: WoStatus;
  assignee_sub?: string;
  cursor?: string;
  limit?: number;
}) => {
  const p: Record<string, string> = {};
  if (params?.wo_status) p["wo_status"] = params.wo_status;
  if (params?.assignee_sub) p["assignee_sub"] = params.assignee_sub;
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit != null) p["limit"] = String(params.limit);
  return api.get<WoListOut>("/ui/maintenance/work-orders", p);
};

// ─── Property-scoped work orders ─────────────────────────────────────────────

export const createWorkOrder = (propertyId: string, body: MaintenanceOrderIn) =>
  api.post<MaintenanceOrderOut>(`/ui/properties/${propertyId}/work-orders`, body);

export const listPropertyWorkOrders = (
  propertyId: string,
  params?: { wo_status?: WoStatus; cursor?: string; limit?: number },
) => {
  const p: Record<string, string> = {};
  if (params?.wo_status) p["wo_status"] = params.wo_status;
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit != null) p["limit"] = String(params.limit);
  return api.get<WoListOut>(`/ui/properties/${propertyId}/work-orders`, p);
};

export const getWorkOrder = (propertyId: string, workOrderId: string) =>
  api.get<MaintenanceOrderOut>(`/ui/properties/${propertyId}/work-orders/${workOrderId}`);

// ─── Work-order mutations ─────────────────────────────────────────────────────

export const assignWorkOrder = (workOrderId: string, body: MaintenanceOrderAssignIn) =>
  api.patch<MaintenanceOrderOut>(`/ui/maintenance/work-orders/${workOrderId}/assign`, body);

export const scheduleWorkOrder = (workOrderId: string, body: MaintenanceOrderScheduleIn) =>
  api.patch<MaintenanceOrderOut>(`/ui/maintenance/work-orders/${workOrderId}/schedule`, body);

export const transitionWorkOrder = (workOrderId: string, body: MaintenanceOrderTransitionIn) =>
  api.patch<MaintenanceOrderOut>(`/ui/maintenance/work-orders/${workOrderId}`, body);

// ─── Vendor directory ─────────────────────────────────────────────────────────

export const listVendorCategories = () =>
  api.get<{ categories: string[] }>("/ui/maintenance/vendors/categories");

export const createVendor = (body: VendorCreateIn) =>
  api.post<VendorOut>("/ui/maintenance/vendors", body);

export const listVendors = (params?: {
  status?: VendorStatus;
  trade_category?: string;
  cursor?: string;
  limit?: number;
}) => {
  const p: Record<string, string> = { status: params?.status ?? "active" };
  if (params?.trade_category) p["trade_category"] = params.trade_category;
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit != null) p["limit"] = String(params.limit);
  return api.get<VendorListOut>("/ui/maintenance/vendors", p);
};

export const getVendor = (vendorId: string) =>
  api.get<VendorOut>(`/ui/maintenance/vendors/${vendorId}`);

export const updateVendor = (vendorId: string, body: VendorPatchIn) =>
  api.patch<VendorOut>(`/ui/maintenance/vendors/${vendorId}`, body);

export const setVendorStatus = (vendorId: string, status: VendorStatus) =>
  api.post<VendorOut>(`/ui/maintenance/vendors/${vendorId}/status`, { status });
