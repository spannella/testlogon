import { api } from "@/api/client";

// ─── Types (mirror app/models.py manufacturing models) ────────────────

export interface BomComponentIn {
  component_sku: string;
  quantity_per: number;
  scrap_pct?: number;
  unit_of_measure?: string;
}

export interface BomComponentOut {
  component_sku: string;
  quantity_per: number;
  scrap_pct: number;
  unit_of_measure: string;
  seq: number;
}

export interface BomOut {
  bom_id: string;
  product_sku: string;
  name: string;
  output_quantity: number;
  status: string;
  created_at: number;
  updated_at: number;
  created_by: string;
  components: BomComponentOut[];
}

export interface BomCreateIn {
  product_sku: string;
  name: string;
  output_quantity?: number;
  components?: BomComponentIn[];
  correlation_id?: string;
}

export interface BomUpdateIn {
  name?: string;
  status?: string;
}

export interface ExplodedComponentOut {
  component_sku: string;
  required_qty: number;
  depth: number;
}

export interface BomExplosionOut {
  bom_id: string;
  build_qty: number;
  components: ExplodedComponentOut[];
}

// Routing tasks (MFG-005)

export interface RoutingTaskIn {
  work_center_id: string;
  sequence: number;
  setup_minutes?: number;
  run_minutes_per_unit?: number;
  description?: string;
}

export interface RoutingTaskOut {
  bom_id: string;
  sequence: number;
  work_center_id: string;
  description: string;
  setup_minutes: number;
  run_minutes_per_unit: number;
  created_at: number;
  updated_at: number;
}

export interface RoutingCostTaskOut {
  sequence: number;
  work_center_id: string;
  task_minutes: number;
  cost_per_hour_cents: number;
  task_cost_cents: number;
}

export interface RoutingCostOut {
  bom_id: string;
  quantity: number;
  total_setup_minutes: number;
  total_run_minutes: number;
  total_minutes: number;
  total_labor_cost_cents: number;
  tasks: RoutingCostTaskOut[];
}

// Work centers

export interface WorkCenterOut {
  work_center_id: string;
  name: string;
  capacity_per_hour: number;
  cost_per_hour_cents: number;
  status: string;
  created_at: number;
  updated_at: number;
}

export interface WorkCenterCreateIn {
  name: string;
  capacity_per_hour?: number;
  cost_per_hour_cents?: number;
  correlation_id?: string;
}

export interface WorkCenterUpdateIn {
  name?: string;
  capacity_per_hour?: number;
  cost_per_hour_cents?: number;
  status?: string;
}

// Work orders

export interface IssueRowOut {
  component_sku: string;
  required_quantity: number;
  issued_quantity: number;
  location_id: string;
  issued_at: number;
}

export interface WorkOrderOut {
  work_order_id: string;
  product_sku: string;
  quantity: number;
  produced_qty: number;
  bom_id: string;
  work_center_id: string;
  status: string;
  correlation_id: string;
  issues_guard: string;
  produce_guard: string;
  created_at: number;
  updated_at: number;
  user_sub: string;
  issues: IssueRowOut[];
  catalog_category_id: string;
  catalog_item_id: string;
}

export interface WorkOrderCreateIn {
  product_sku: string;
  quantity: number;
  bom_id?: string;
  work_center_id?: string;
  correlation_id?: string;
  catalog_category_id?: string;
  catalog_item_id?: string;
}

export interface WorkOrderCompleteIn {
  produced_qty?: number;
  location_id?: string;
}

export interface WorkOrderCancelIn {
  reason?: string;
}

export interface WorkOrderCatalogStockOut {
  work_order_id: string;
  product_sku: string;
  inventory_available: number | null;
  inventory_on_hand: number | null;
  catalog_stock_count: number | null;
  in_sync: boolean | null;
}

// MRP

export interface MrpRunIn {
  horizon_days?: number;
  location_id?: string;
  correlation_id?: string;
}

export interface MrpRequirementOut {
  sku: string;
  gross_requirement: number;
  on_hand_available: number;
  scheduled_receipts: number;
  net_requirement: number;
  suggested_action: string;
  suggested_quantity: number;
  depth: number;
  bom_id: string;
}

export interface MrpRunOut {
  mrp_run_id: string;
  status: string;
  horizon_days: number;
  location_id: string;
  created_at: number;
  completed_at: number;
  requirement_count: number;
  user_sub: string;
  requirements: MrpRequirementOut[];
}

const BASE = "/ui/manufacturing";

// ─── BOM endpoints ────────────────────────────────────────────────────

export const listBoms = (productSku?: string) =>
  api.get<{ boms: BomOut[] }>(`${BASE}/boms`, productSku ? { product_sku: productSku } : undefined);

export const getBom = (bomId: string) =>
  api.get<BomOut>(`${BASE}/boms/${encodeURIComponent(bomId)}`);

export const createBom = (body: BomCreateIn) =>
  api.post<BomOut>(`${BASE}/boms`, body);

export const updateBom = (bomId: string, body: BomUpdateIn) =>
  api.patch<BomOut>(`${BASE}/boms/${encodeURIComponent(bomId)}`, body);

export const deactivateBom = (bomId: string) =>
  api.del<BomOut>(`${BASE}/boms/${encodeURIComponent(bomId)}`);

export const explodeBom = (bomId: string, buildQty = 1) =>
  api.get<BomExplosionOut>(`${BASE}/boms/${encodeURIComponent(bomId)}/explode`, {
    build_qty: String(buildQty),
  });

// ─── Routing tasks ────────────────────────────────────────────────────

export const listRoutingTasks = (bomId: string) =>
  api.get<{ tasks: RoutingTaskOut[] }>(`${BASE}/boms/${encodeURIComponent(bomId)}/routing-tasks`);

export const addRoutingTask = (bomId: string, body: RoutingTaskIn) =>
  api.post<RoutingTaskOut>(`${BASE}/boms/${encodeURIComponent(bomId)}/routing-tasks`, body);

export const deleteRoutingTask = (bomId: string, sequence: number) =>
  api.del<{ ok: boolean; bom_id: string; sequence: number }>(
    `${BASE}/boms/${encodeURIComponent(bomId)}/routing-tasks/${sequence}`,
  );

export const getRoutingCost = (bomId: string, quantity = 1) =>
  api.get<RoutingCostOut>(`${BASE}/boms/${encodeURIComponent(bomId)}/routing-cost`, {
    quantity: String(quantity),
  });

// ─── Work centers ─────────────────────────────────────────────────────

export const listWorkCenters = (status = "active") =>
  api.get<{ work_centers: WorkCenterOut[] }>(`${BASE}/work-centers`, { status });

export const createWorkCenter = (body: WorkCenterCreateIn) =>
  api.post<WorkCenterOut>(`${BASE}/work-centers`, body);

export const updateWorkCenter = (workCenterId: string, body: WorkCenterUpdateIn) =>
  api.patch<WorkCenterOut>(`${BASE}/work-centers/${encodeURIComponent(workCenterId)}`, body);

// ─── Work orders ──────────────────────────────────────────────────────

export const listWorkOrders = (status?: string) =>
  api.get<{ work_orders: WorkOrderOut[] }>(`${BASE}/work-orders`, status ? { status } : undefined);

export const getWorkOrder = (workOrderId: string) =>
  api.get<WorkOrderOut>(`${BASE}/work-orders/${encodeURIComponent(workOrderId)}`);

export const createWorkOrder = (body: WorkOrderCreateIn) =>
  api.post<WorkOrderOut>(`${BASE}/work-orders`, body);

export const releaseWorkOrder = (workOrderId: string, locationId = "warehouse") =>
  api.post<WorkOrderOut>(
    `${BASE}/work-orders/${encodeURIComponent(workOrderId)}/release`,
    undefined,
    { location_id: locationId },
  );

export const startWorkOrder = (workOrderId: string) =>
  api.post<WorkOrderOut>(`${BASE}/work-orders/${encodeURIComponent(workOrderId)}/start`);

export const completeWorkOrder = (workOrderId: string, body: WorkOrderCompleteIn) =>
  api.post<WorkOrderOut>(`${BASE}/work-orders/${encodeURIComponent(workOrderId)}/complete`, body);

export const cancelWorkOrder = (workOrderId: string, body: WorkOrderCancelIn) =>
  api.post<WorkOrderOut>(`${BASE}/work-orders/${encodeURIComponent(workOrderId)}/cancel`, body);

export const getWorkOrderIssues = (workOrderId: string) =>
  api.get<{ issues: IssueRowOut[] }>(`${BASE}/work-orders/${encodeURIComponent(workOrderId)}/issues`);

export const getWorkOrderCatalogStock = (workOrderId: string) =>
  api.get<WorkOrderCatalogStockOut>(
    `${BASE}/work-orders/${encodeURIComponent(workOrderId)}/catalog-stock`,
  );

// ─── MRP ──────────────────────────────────────────────────────────────

export const runMrp = (body: MrpRunIn) =>
  api.post<MrpRunOut>(`${BASE}/mrp/run`, body);

export const getMrpRun = (mrpRunId: string) =>
  api.get<MrpRunOut>(`${BASE}/mrp/runs/${encodeURIComponent(mrpRunId)}`);

// ─── Helpers ──────────────────────────────────────────────────────────

/** Render integer cents as a USD currency string. */
export const formatCents = (cents: number | null | undefined): string => {
  if (cents == null) return "—";
  return (cents / 100).toLocaleString(undefined, { style: "currency", currency: "USD" });
};
