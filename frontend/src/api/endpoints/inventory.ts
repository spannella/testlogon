import { api } from "@/api/client";
import type {
  InventoryRecord,
  InventoryLowStockResp,
  InventorySetOnHandIn,
  InventoryAdjustIn,
} from "@/api/types";

// ─── Inventory admin (ADR-001 OFB-003/004 / OFB-INV-UI) ──────────────
// All endpoints are flag-gated server-side (INVENTORY_RESERVATIONS_ENABLED,
// default OFF) and 404 when the flag is off. Mutations are admin/root-gated.

export const getInventoryItem = (sku: string) =>
  api.get<InventoryRecord>(`/ui/inventory/items/${encodeURIComponent(sku)}`);

export const setInventoryOnHand = (body: InventorySetOnHandIn) =>
  api.put<InventoryRecord>("/ui/inventory/items", body);

export const adjustInventory = (body: InventoryAdjustIn) =>
  api.post<InventoryRecord>("/ui/inventory/items/adjust", body);

export const listLowStock = (
  status: "low_stock" | "out_of_stock" | "in_stock" = "low_stock",
) => api.get<InventoryLowStockResp>("/ui/inventory/low-stock", { status });
