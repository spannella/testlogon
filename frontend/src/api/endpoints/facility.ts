import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz FACILITY / FULFILLMENT (FAC cluster) endpoint wrappers.
//
// Live routers:
//   app/routers/facilities.py
//     facilities_router   prefix /ui/facilities      (FAC-005 facility + location CRUD)
//     fulfillment_router  prefix /ui/fulfillment      (FAC-006..010 transfers/receiving/
//                                                       picklists/shipments)
//
// All endpoints are gated by the backend flag `facility_fulfillment_enabled`.
// When the flag is OFF every endpoint returns HTTP 404 ("Facility fulfillment is
// not enabled") — pages handle that via ApiError.status === 404.
//
// Mutations require admin/root + CSRF (require_admin_or_root_csrf). Reads use the
// ordinary UI session.
//
// TS interfaces below mirror the live Pydantic models in app/models.py.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Shared types ────────────────────────────────────────────────────────────

export type FacilityType = "warehouse" | "retail" | "virtual" | "drop_ship";
export type FacilityStatus = "active" | "archived";
export type LocationType =
  | "bulk"
  | "bin"
  | "aisle"
  | "shelf"
  | "staging"
  | "receiving"
  | "shipping";

export interface FacilityAddress {
  [key: string]: unknown;
}

export interface Facility {
  facility_id: string;
  name: string;
  facility_type: FacilityType;
  description?: string | null;
  address?: FacilityAddress | null;
  owner_sub?: string | null;
  status: FacilityStatus;
  created_at: number;
  updated_at: number;
}

export interface FacilityListOut {
  facilities: Facility[];
  next_cursor?: string | null;
}

export interface FacilityIn {
  name: string;
  facility_type?: FacilityType;
  description?: string | null;
  address?: FacilityAddress | null;
  owner_sub?: string | null;
  idempotency_key?: string | null;
}

export interface FacilityLocation {
  facility_id: string;
  location_id: string;
  name: string;
  location_type: LocationType;
  description?: string | null;
  parent_location_id?: string | null;
  status: FacilityStatus;
  created_at: number;
}

export interface FacilityLocationListOut {
  locations: FacilityLocation[];
}

export interface FacilityLocationIn {
  name: string;
  location_type?: LocationType;
  description?: string | null;
  parent_location_id?: string | null;
}

// ─── Transfers ───────────────────────────────────────────────────────────────

export type TransferStatus = "requested" | "in_transit" | "completed" | "cancelled";

export interface TransferItemIn {
  sku: string;
  quantity: number;
}

export interface TransferItem {
  sku: string;
  quantity: number;
  picked_quantity: number;
  status: string; // pending | moved | short
}

export interface TransferIn {
  from_facility_id: string;
  from_location_id: string;
  to_facility_id: string;
  to_location_id: string;
  lines: TransferItemIn[];
  notes?: string | null;
  idempotency_key?: string | null;
}

export interface Transfer {
  transfer_id: string;
  from_facility_id: string;
  from_location_id: string;
  to_facility_id: string;
  to_location_id: string;
  status: TransferStatus;
  notes?: string | null;
  lines: TransferItem[];
  created_by?: string | null;
  created_at: number;
  updated_at: number;
  completed_at?: number | null;
}

export interface TransferListOut {
  transfers: Transfer[];
  next_cursor?: string | null;
}

// ─── Receiving ───────────────────────────────────────────────────────────────

export interface ReceiveLineIn {
  sku: string;
  quantity: number;
  unit_cost_cents?: number | null;
  lot_label?: string | null;
  serials?: string[];
}

export interface ReceiveIn {
  facility_id: string;
  location_id: string;
  lines: ReceiveLineIn[];
  po_id?: string | null;
  notes?: string | null;
  correlation_id: string;
}

export interface ReceiptLine {
  sku: string;
  ordered_quantity: number;
  received_quantity: number;
  unit_cost_cents: number;
  receipt_status: string; // received | short | over
  lot_id?: string | null;
}

export interface Receipt {
  receipt_id: string;
  facility_id: string;
  location_id: string;
  po_id?: string | null;
  correlation_id: string;
  status: string; // received | partial | over | cancelled
  notes?: string | null;
  lines: ReceiptLine[];
  received_by?: string | null;
  created_at: number;
}

export interface ReceiptListOut {
  receipts: Receipt[];
  next_cursor?: string | null;
}

// ─── Picklists ───────────────────────────────────────────────────────────────

export type PicklistStatus = "pending" | "picking" | "picked" | "packed" | "cancelled";

export interface PickLine {
  line_id: string;
  order_line_id: string;
  sku: string;
  requested_quantity: number;
  picked_quantity: number;
  from_facility_id: string;
  from_location_id: string;
  reservation_id?: string | null;
  status: string; // pending | picked | short | cancelled
}

export interface Picklist {
  picklist_id: string;
  order_id: string;
  status: PicklistStatus;
  lines: PickLine[];
  created_by?: string | null;
  created_at: number;
  updated_at: number;
  packed_at?: number | null;
}

// ─── Shipments ───────────────────────────────────────────────────────────────

export type ShipmentStatus = "draft" | "packed" | "shipped" | "delivered" | "cancelled";

export interface PackageLineIn {
  order_line_id: string;
  sku: string;
  quantity: number;
}

export interface PackageIn {
  weight_grams?: number | null;
  length_mm?: number | null;
  width_mm?: number | null;
  height_mm?: number | null;
  contents: PackageLineIn[];
  notes?: string | null;
}

export interface PackageOut {
  package_id: string;
  weight_grams: number;
  length_mm: number;
  width_mm: number;
  height_mm: number;
  contents: PackageLineIn[];
  notes?: string | null;
}

export interface ShipmentIn {
  picklist_id: string;
  carrier: string;
  tracking_number: string;
  service_level?: string | null;
  packages: PackageIn[];
  notes?: string | null;
  idempotency_key?: string | null;
}

export interface Shipment {
  shipment_id: string;
  order_id: string;
  picklist_id: string;
  status: ShipmentStatus;
  carrier?: string | null;
  tracking_number?: string | null;
  service_level?: string | null;
  packages: PackageOut[];
  notes?: string | null;
  created_by?: string | null;
  created_at: number;
  shipped_at?: number | null;
  delivered_at?: number | null;
}

export interface ShipmentListOut {
  shipments: Shipment[];
  next_cursor?: string | null;
}

// ═════════════════════════════════════════════════════════════════════════════
// Facilities (FAC-005)
// ═════════════════════════════════════════════════════════════════════════════

export const listFacilities = (opts?: {
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<FacilityListOut>("/ui/facilities", params);
};

export const listFacilitiesAdminQueue = (opts?: {
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<FacilityListOut>("/ui/facilities/admin/queue", params);
};

export const getFacility = (facilityId: string) =>
  api.get<Facility>(`/ui/facilities/${encodeURIComponent(facilityId)}`);

export const createFacility = (body: FacilityIn) =>
  api.post<Facility>("/ui/facilities", body);

export const updateFacility = (facilityId: string, body: FacilityIn) =>
  api.put<Facility>(`/ui/facilities/${encodeURIComponent(facilityId)}`, body);

export const archiveFacility = (facilityId: string) =>
  api.del<Facility>(`/ui/facilities/${encodeURIComponent(facilityId)}`);

export const listFacilityLocations = (facilityId: string) =>
  api.get<FacilityLocationListOut>(
    `/ui/facilities/${encodeURIComponent(facilityId)}/locations`,
  );

export const getFacilityLocation = (facilityId: string, locationId: string) =>
  api.get<FacilityLocation>(
    `/ui/facilities/${encodeURIComponent(facilityId)}/locations/${encodeURIComponent(locationId)}`,
  );

export const createFacilityLocation = (facilityId: string, body: FacilityLocationIn) =>
  api.post<FacilityLocation>(
    `/ui/facilities/${encodeURIComponent(facilityId)}/locations`,
    body,
  );

// ═════════════════════════════════════════════════════════════════════════════
// Transfers (FAC-006)
// ═════════════════════════════════════════════════════════════════════════════

export const createTransfer = (body: TransferIn) =>
  api.post<Transfer>("/ui/fulfillment/transfers", body);

export const listTransfers = (opts?: {
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<TransferListOut>("/ui/fulfillment/transfers", params);
};

export const getTransfer = (transferId: string) =>
  api.get<Transfer>(`/ui/fulfillment/transfers/${encodeURIComponent(transferId)}`);

export const advanceTransfer = (transferId: string) =>
  api.post<Transfer>(
    `/ui/fulfillment/transfers/${encodeURIComponent(transferId)}/advance`,
  );

export const completeTransfer = (transferId: string) =>
  api.post<Transfer>(
    `/ui/fulfillment/transfers/${encodeURIComponent(transferId)}/complete`,
  );

export const cancelTransfer = (transferId: string) =>
  api.post<Transfer>(
    `/ui/fulfillment/transfers/${encodeURIComponent(transferId)}/cancel`,
  );

// ═════════════════════════════════════════════════════════════════════════════
// Receiving (FAC-007)
// ═════════════════════════════════════════════════════════════════════════════

export const receiveShipment = (body: ReceiveIn) =>
  api.post<Receipt>("/ui/fulfillment/receiving", body);

export const getReceipt = (receiptId: string) =>
  api.get<Receipt>(`/ui/fulfillment/receiving/${encodeURIComponent(receiptId)}`);

export const listReceipts = (opts?: {
  facility_id?: string;
  po_id?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.facility_id) params["facility_id"] = opts.facility_id;
  if (opts?.po_id) params["po_id"] = opts.po_id;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<ReceiptListOut>("/ui/fulfillment/receiving", params);
};

// ═════════════════════════════════════════════════════════════════════════════
// Picklists — pick & pack (FAC-008/009)
// ═════════════════════════════════════════════════════════════════════════════

export const generatePicklist = (opts: {
  order_id: string;
  facility_id: string;
  location_id?: string;
}) => {
  const params: Record<string, string> = {
    order_id: opts.order_id,
    facility_id: opts.facility_id,
  };
  if (opts.location_id) params["location_id"] = opts.location_id;
  return api.post<Picklist>("/ui/fulfillment/picklists", undefined, params);
};

export const getPicklist = (picklistId: string) =>
  api.get<Picklist>(`/ui/fulfillment/picklists/${encodeURIComponent(picklistId)}`);

export const confirmPick = (picklistId: string, lineNo: number, pickedQty: number) =>
  api.post<Picklist>(
    `/ui/fulfillment/picklists/${encodeURIComponent(picklistId)}/confirm-pick/${lineNo}`,
    undefined,
    { picked_qty: String(pickedQty) },
  );

export const packPicklist = (picklistId: string, body: ShipmentIn) =>
  api.post<Shipment>(
    `/ui/fulfillment/picklists/${encodeURIComponent(picklistId)}/pack`,
    body,
  );

// ═════════════════════════════════════════════════════════════════════════════
// Shipments — ship lifecycle (FAC-010)
// ═════════════════════════════════════════════════════════════════════════════

export const getShipment = (shipmentId: string) =>
  api.get<Shipment>(`/ui/fulfillment/shipments/${encodeURIComponent(shipmentId)}`);

export const listShipmentsForOrder = (opts: {
  order_id: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = { order_id: opts.order_id };
  if (opts.cursor) params["cursor"] = opts.cursor;
  if (opts.limit) params["limit"] = String(opts.limit);
  return api.get<ShipmentListOut>("/ui/fulfillment/shipments", params);
};

export const shipShipment = (shipmentId: string, body: ShipmentIn) =>
  api.post<Shipment>(
    `/ui/fulfillment/shipments/${encodeURIComponent(shipmentId)}/ship`,
    body,
  );

export const cancelShipment = (shipmentId: string, reason?: string) =>
  api.post<Shipment>(
    `/ui/fulfillment/shipments/${encodeURIComponent(shipmentId)}/cancel`,
    undefined,
    reason ? { reason } : undefined,
  );
