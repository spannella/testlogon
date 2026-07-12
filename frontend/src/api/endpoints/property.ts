/**
 * Property management API endpoints (open-property vertical, PROP-001..PROP-005).
 *
 * Flag-gated: PROPERTY_MGMT_ENABLED (default OFF). When the flag is off the backend
 * returns HTTP 404 for every endpoint. Callers should handle ApiError.status === 404
 * as "feature not enabled".
 *
 * All routes are under /ui/properties (proxied by Vite → backend).
 */

import { api } from "@/api/client";

// ─── Inline TypeScript interfaces (mirrors app/models.py) ─────────────────────

export interface PropertyAddress {
  line1: string;
  line2?: string | null;
  city: string;
  region: string;
  postal_code: string;
  country: string;
}

export type PropertyType = "single_family" | "multi_family" | "apartment" | "commercial";
export type OccupancyStatus = "vacant" | "partial" | "occupied";
export type PropertyStatus = "active" | "archived";
export type UnitOccupancyStatus = "vacant" | "occupied" | "turnover" | "unavailable";

export interface PropertyOut {
  property_id: string;
  owner_sub: string;
  name: string;
  property_type: PropertyType;
  address: PropertyAddress;
  color_tags: string[];
  occupancy_status: OccupancyStatus;
  unit_count: number;
  status: PropertyStatus;
  created_at: number;
  updated_at: number;
}

export interface PropertyListOut {
  properties: PropertyOut[];
  count: number;
  cursor?: string | null;
}

export interface PropertyIn {
  name: string;
  property_type: PropertyType;
  address: PropertyAddress;
  color_tags?: string[];
}

export interface PropertyUpdateIn {
  name?: string;
  property_type?: PropertyType;
  address?: PropertyAddress;
  color_tags?: string[];
}

export interface UnitOut {
  property_id: string;
  unit_id: string;
  label: string;
  bedrooms: number;
  bathrooms: number;
  square_footage: number;
  market_rent_cents: number;
  occupancy_status: UnitOccupancyStatus;
  created_at: number;
  updated_at: number;
}

export interface UnitIn {
  label: string;
  bedrooms: number;
  bathrooms: number;
  square_footage: number;
  market_rent_cents: number;
  occupancy_status?: UnitOccupancyStatus;
}

export interface UnitUpdateIn {
  label?: string;
  bedrooms?: number;
  bathrooms?: number;
  square_footage?: number;
  market_rent_cents?: number;
  occupancy_status?: UnitOccupancyStatus;
}

export interface PropertyOccupancyOut {
  property_id: string;
  total: number;
  occupied: number;
  vacant: number;
  turnover: number;
  unavailable: number;
  occupancy_status: OccupancyStatus;
  occupancy_rate: number;
}

export interface PortfolioOccupancyOut {
  property_count: number;
  unit_count: number;
  occupied: number;
  vacant: number;
  turnover: number;
  unavailable: number;
  occupancy_rate: number;
}

// ─── Property endpoints ───────────────────────────────────────────────────────

const BASE = "/ui/properties";

export const listProperties = (opts?: {
  status?: string;
  property_type?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.property_type) params["property_type"] = opts.property_type;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit !== undefined) params["limit"] = String(opts.limit);
  return api.get<PropertyListOut>(BASE, params);
};

export const getProperty = (propertyId: string) =>
  api.get<PropertyOut>(`${BASE}/${propertyId}`);

export const createProperty = (body: PropertyIn) =>
  api.post<PropertyOut>(BASE, body);

export const updateProperty = (propertyId: string, body: PropertyUpdateIn) =>
  api.put<PropertyOut>(`${BASE}/${propertyId}`, body);

export const archiveProperty = (propertyId: string) =>
  api.del<PropertyOut>(`${BASE}/${propertyId}`);

export const getPropertyOccupancy = (propertyId: string) =>
  api.get<PropertyOccupancyOut>(`${BASE}/${propertyId}/occupancy`);

export const getPortfolioOccupancy = () =>
  api.get<PortfolioOccupancyOut>(`${BASE}/portfolio/occupancy`);

// ─── Unit endpoints ───────────────────────────────────────────────────────────

export const listUnits = (propertyId: string) =>
  api.get<UnitOut[]>(`${BASE}/${propertyId}/units`);

export const getUnit = (propertyId: string, unitId: string) =>
  api.get<UnitOut>(`${BASE}/${propertyId}/units/${unitId}`);

export const createUnit = (propertyId: string, body: UnitIn) =>
  api.post<UnitOut>(`${BASE}/${propertyId}/units`, body);

export const updateUnit = (propertyId: string, unitId: string, body: UnitUpdateIn) =>
  api.put<UnitOut>(`${BASE}/${propertyId}/units/${unitId}`, body);

export const deleteUnit = (propertyId: string, unitId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/${propertyId}/units/${unitId}`);
