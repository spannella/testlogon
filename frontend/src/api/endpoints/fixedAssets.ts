import { api } from "@/api/client";

// ─── Types (mirror app/models.py FixedAsset* / Depreciation* / AssetMaintenanceOrder*) ───

export type FixedAssetStatus = "active" | "fully_depreciated" | "disposed";
export type DepreciationMethod = "straight_line";
export type ScheduleStatus = "scheduled" | "posted" | "cancelled";
export type WorkOrderStatus = "open" | "in_progress" | "completed" | "cancelled";

export interface FixedAsset {
  asset_id: string;
  owner_sub: string;
  name: string;
  asset_class: string;
  acquisition_cost_cents: number;
  salvage_value_cents: number;
  useful_life_months: number;
  acquired_at: number;
  depreciation_method: string;
  status: string;
  accumulated_depreciation_cents: number;
  net_book_value_cents: number;
  gl_asset_account_id: string | null;
  gl_accum_depr_account_id: string | null;
  gl_depr_expense_account_id: string | null;
  gl_gain_account_id: string | null;
  gl_loss_account_id: string | null;
  created_at: number;
  updated_at: number;
  correlation_id: string | null;
}

export interface FixedAssetIn {
  name: string;
  asset_class: string;
  acquisition_cost_cents: number;
  salvage_value_cents: number;
  useful_life_months: number;
  acquired_at: number;
  depreciation_method?: DepreciationMethod;
  correlation_id?: string;
  gl_asset_account_id?: string;
  gl_accum_depr_account_id?: string;
  gl_depr_expense_account_id?: string;
  gl_gain_account_id?: string;
  gl_loss_account_id?: string;
}

export interface FixedAssetPatchIn {
  name?: string;
  asset_class?: string;
  gl_asset_account_id?: string;
  gl_accum_depr_account_id?: string;
  gl_depr_expense_account_id?: string;
  gl_gain_account_id?: string;
  gl_loss_account_id?: string;
}

export interface FixedAssetDisposeIn {
  disposal_reason?: string;
  proceeds_payment_intent_id?: string;
  proceeds_amount_cents?: number;
  correlation_id?: string;
}

export interface DepreciationPeriod {
  period: number;
  period_start_ts: number;
  period_end_ts: number;
  amount_cents: number;
  schedule_status: string;
  journal_entry_id: string | null;
  posted_at: number | null;
}

export interface DepreciationSchedule {
  asset_id: string;
  periods: DepreciationPeriod[];
  total_periods: number;
  posted_periods: number;
  remaining_periods: number;
}

export interface AssetMaintenanceOrder {
  work_order_id: string;
  asset_id: string;
  title: string;
  description: string | null;
  wo_status: string;
  assignee_sub: string | null;
  cost_cents: number | null;
  scheduled_for: number | null;
  created_at: number;
  completed_at: number | null;
  correlation_id: string | null;
}

export interface AssetMaintenanceOrderIn {
  title: string;
  description?: string;
  assignee_sub?: string;
  scheduled_for?: number;
  correlation_id?: string;
}

export interface AssetMaintenanceOrderTransitionIn {
  target_status: "in_progress" | "completed" | "cancelled";
  cost_cents?: number;
  assignee_sub?: string;
}

export interface ListResp<T> {
  items: T[];
  count: number;
  cursor: string | null;
}

export interface PostPeriodResp {
  period: number;
  period_start_ts: number;
  period_end_ts: number;
  amount_cents: number;
  schedule_status: string;
  journal_entry_id: string | null;
  posted_at: number | null;
}

const BASE = "/ui/fixed-assets";

// ─── Asset register ──────────────────────────────────────────────────────────

export const createAsset = (body: FixedAssetIn) => api.post<FixedAsset>(BASE, body);

export const listAssets = (opts?: {
  owner_sub?: string;
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.owner_sub) params["owner_sub"] = opts.owner_sub;
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<ListResp<FixedAsset>>(BASE, params);
};

export const getAsset = (assetId: string) =>
  api.get<FixedAsset>(`${BASE}/${encodeURIComponent(assetId)}`);

export const updateAsset = (assetId: string, body: FixedAssetPatchIn) =>
  api.patch<FixedAsset>(`${BASE}/${encodeURIComponent(assetId)}`, body);

export const disposeAsset = (assetId: string, body: FixedAssetDisposeIn) =>
  api.post<FixedAsset>(`${BASE}/${encodeURIComponent(assetId)}/dispose`, body);

// ─── Depreciation schedule ───────────────────────────────────────────────────

export const getSchedule = (assetId: string) =>
  api.get<DepreciationSchedule>(`${BASE}/${encodeURIComponent(assetId)}/schedule`);

export const generateSchedule = (assetId: string) =>
  api.post<DepreciationSchedule>(`${BASE}/${encodeURIComponent(assetId)}/schedule/generate`, {});

export const postPeriod = (assetId: string, period: number) =>
  api.post<PostPeriodResp>(
    `${BASE}/${encodeURIComponent(assetId)}/schedule/${period}/post`,
    {},
  );

// ─── Maintenance work orders ─────────────────────────────────────────────────

export const listWorkOrderQueue = (opts?: {
  wo_status?: string;
  assignee_sub?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.wo_status) params["wo_status"] = opts.wo_status;
  if (opts?.assignee_sub) params["assignee_sub"] = opts.assignee_sub;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<ListResp<AssetMaintenanceOrder>>(`${BASE}/work-orders`, params);
};

export const listWorkOrdersForAsset = (
  assetId: string,
  opts?: { cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<ListResp<AssetMaintenanceOrder>>(
    `${BASE}/${encodeURIComponent(assetId)}/work-orders`,
    params,
  );
};

export const createWorkOrder = (assetId: string, body: AssetMaintenanceOrderIn) =>
  api.post<AssetMaintenanceOrder>(
    `${BASE}/${encodeURIComponent(assetId)}/work-orders`,
    body,
  );

export const transitionWorkOrder = (
  workOrderId: string,
  assetId: string,
  body: AssetMaintenanceOrderTransitionIn,
) =>
  api.patch<AssetMaintenanceOrder>(
    `${BASE}/work-orders/${encodeURIComponent(workOrderId)}?asset_id=${encodeURIComponent(assetId)}`,
    body,
  );
