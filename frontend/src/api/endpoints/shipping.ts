import { api } from "@/api/client";

// ─── Types (mirror app/models.py SHP-003 / Phase 8 Module H) ─────────────────

export type CarrierCode = "ups" | "fedex" | "usps" | "dhl" | "manual";
export type MethodCode =
  | "ground"
  | "express"
  | "overnight"
  | "economy"
  | "flat_rate";

export type ShipmentStatus =
  | "pending_fulfillment"
  | "label_created"
  | "picked_up"
  | "in_transit"
  | "out_for_delivery"
  | "delivered"
  | "exception"
  | "returned"
  | "cancelled";

export interface CarrierIn {
  carrier_code: CarrierCode;
  display_name: string;
}

export interface CarrierOut {
  carrier_id: string;
  carrier_code: CarrierCode;
  display_name: string;
  online_tracking: boolean;
  enabled: boolean;
  created_at: number;
  updated_at: number;
}

export interface ShipmentMethodIn {
  method_code: MethodCode;
  method_label: string;
  base_rate_cents: number;
  currency?: string;
  transit_days_min?: number | null;
  transit_days_max?: number | null;
}

export interface ShipmentMethodOut {
  carrier_id: string;
  carrier_code: CarrierCode;
  method_code: MethodCode;
  method_label: string;
  base_rate_cents: number;
  currency: string;
  transit_days_min?: number | null;
  transit_days_max?: number | null;
  enabled: boolean;
}

export interface ShippingRateRequest {
  carrier_code: CarrierCode;
  method_code: MethodCode;
  weight_oz: number;
  destination_zip: string;
  origin_zip?: string | null;
}

export interface ShippingRateOption {
  carrier_code: CarrierCode;
  method_code: MethodCode;
  rate_cents: number;
  currency: string;
  transit_days_min?: number | null;
  transit_days_max?: number | null;
  estimated_delivery?: string | null;
}

export interface ShippingRateQuote {
  request_id: string;
  options: ShippingRateOption[];
  currency: string;
  generated_at: number;
}

export interface ShipmentItemOut {
  item_id: string;
  sku?: string | null;
  quantity: number;
  order_id?: string | null;
}

export interface ShipmentPackageOut {
  package_seq: string;
  weight_oz: number;
  length_in?: number | null;
  width_in?: number | null;
  height_in?: number | null;
  contents: Array<Record<string, unknown>>;
  billed_weight_oz?: number | null;
}

export interface ShipmentPackageIn {
  weight_oz: number;
  length_in?: number | null;
  width_in?: number | null;
  height_in?: number | null;
  contents?: Array<Record<string, unknown>>;
}

export interface ShipmentIn {
  order_id: string;
  carrier_code: CarrierCode;
  method_code: MethodCode;
  ship_to_address: Record<string, unknown>;
  line_items: Array<Record<string, unknown>>;
  packages?: ShipmentPackageIn[];
  correlation_id?: string | null;
  ship_group_seq?: number;
  purchase_txn_id?: string | null;
}

export interface ShipmentOut {
  shipment_id: string;
  order_id: string;
  user_id: string;
  status: ShipmentStatus;
  carrier_code: CarrierCode;
  method_code: MethodCode;
  ship_method_id?: string | null;
  tracking_number?: string | null;
  tracking_url?: string | null;
  ship_to_address: Record<string, unknown>;
  ship_group_seq: number;
  estimated_delivery?: string | null;
  shipped_at?: number | null;
  delivered_at?: number | null;
  created_at: number;
  updated_at: number;
  version: number;
  items: ShipmentItemOut[];
  packages: ShipmentPackageOut[];
}

export interface OrderShipmentsOut {
  shipments: ShipmentOut[];
  count: number;
}

export interface ShipmentTrackingUpdateIn {
  tracking_number: string;
  carrier_code?: CarrierCode | null;
}

export interface ShipmentAdvanceIn {
  target_status: ShipmentStatus;
  reason?: string | null;
}

export interface ShipmentCancelIn {
  reason?: string;
  refund_shipping?: boolean;
}

const BASE = "/ui/shop/shipping";

// ─── Carriers ────────────────────────────────────────────────────────────────

export const listCarriers = (enabledOnly = true) =>
  api.get<CarrierOut[]>(`${BASE}/carriers`, {
    enabled_only: enabledOnly ? "true" : "false",
  });

export const getCarrier = (carrierId: string) =>
  api.get<CarrierOut>(`${BASE}/carriers/${encodeURIComponent(carrierId)}`);

export const createCarrier = (body: CarrierIn) =>
  api.post<CarrierOut>(`${BASE}/carriers`, body);

export const updateCarrier = (
  carrierId: string,
  patch: Partial<Pick<CarrierOut, "display_name" | "enabled" | "online_tracking">>,
) => api.patch<CarrierOut>(`${BASE}/carriers/${encodeURIComponent(carrierId)}`, patch);

export const disableCarrier = (carrierId: string) =>
  api.post<{ ok: boolean }>(
    `${BASE}/carriers/${encodeURIComponent(carrierId)}/disable`,
    {},
  );

// ─── Carrier methods ───────────────────────────────────────────────────────────

export const listMethods = (carrierId: string, enabledOnly = true) =>
  api.get<ShipmentMethodOut[]>(
    `${BASE}/carriers/${encodeURIComponent(carrierId)}/methods`,
    { enabled_only: enabledOnly ? "true" : "false" },
  );

export const addMethod = (carrierId: string, body: ShipmentMethodIn) =>
  api.post<ShipmentMethodOut>(
    `${BASE}/carriers/${encodeURIComponent(carrierId)}/methods`,
    body,
  );

export const updateMethod = (
  carrierId: string,
  methodCode: string,
  patch: Partial<
    Pick<
      ShipmentMethodOut,
      | "method_label"
      | "base_rate_cents"
      | "currency"
      | "transit_days_min"
      | "transit_days_max"
      | "enabled"
    >
  >,
) =>
  api.patch<ShipmentMethodOut>(
    `${BASE}/carriers/${encodeURIComponent(carrierId)}/methods/${encodeURIComponent(methodCode)}`,
    patch,
  );

// ─── Rate estimation ───────────────────────────────────────────────────────────

export const estimateRates = (body: ShippingRateRequest) =>
  api.post<ShippingRateQuote>(`${BASE}/estimate`, body);

export const estimateRatesGet = (params: {
  carrier_code: CarrierCode;
  method_code: MethodCode;
  weight_oz?: number;
  destination_zip?: string;
}) =>
  api.get<ShippingRateQuote>(`${BASE}/estimate`, {
    carrier_code: params.carrier_code,
    method_code: params.method_code,
    weight_oz: String(params.weight_oz ?? 0),
    destination_zip: params.destination_zip ?? "",
  });

// ─── Shipments ─────────────────────────────────────────────────────────────────

export const createShipment = (body: ShipmentIn) =>
  api.post<ShipmentOut>(`${BASE}/shipments`, body);

export const getShipment = (shipmentId: string) =>
  api.get<ShipmentOut>(`${BASE}/shipments/${encodeURIComponent(shipmentId)}`);

export const listOrderShipments = (orderId: string) =>
  api.get<OrderShipmentsOut>(
    `${BASE}/orders/${encodeURIComponent(orderId)}/shipments`,
  );

export const updateTracking = (
  shipmentId: string,
  body: ShipmentTrackingUpdateIn,
) =>
  api.patch<ShipmentOut>(
    `${BASE}/shipments/${encodeURIComponent(shipmentId)}/tracking`,
    body,
  );

export const advanceShipment = (shipmentId: string, body: ShipmentAdvanceIn) =>
  api.post<ShipmentOut>(
    `${BASE}/shipments/${encodeURIComponent(shipmentId)}/advance`,
    body,
  );

export const cancelShipment = (shipmentId: string, body: ShipmentCancelIn) =>
  api.post<ShipmentOut>(
    `${BASE}/shipments/${encodeURIComponent(shipmentId)}/cancel`,
    body,
  );
