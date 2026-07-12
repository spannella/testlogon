import { api } from "@/api/client";

// ─── Inline TS types (mirror LIVE app/models.py) ─────────────────────────────

/** EVT-005: A single geocoded address item. */
export interface GeocodedAddress {
  address_id: string;
  lat: number;
  lng: number;
  geocoded_at: number;
  line1?: string | null;
  city?: string | null;
  state?: string | null;
  postal_code?: string | null;
  country?: string | null;
}

/** EVT-005: List envelope for geocoded addresses. */
export interface GeocodedAddressList {
  addresses: GeocodedAddress[];
  count: number;
}

/** EVT-006: A single result item from a proximity search. */
export interface ProximityResultItem {
  entity_type: string;
  entity_id: string;
  name: string;
  lat: number;
  lng: number;
  distance_km: number;
  address_id?: string | null;
  city?: string | null;
  country?: string | null;
}

/** EVT-006: Proximity search response envelope. */
export interface ProximitySearchResult {
  results: ProximityResultItem[];
  count: number;
  center_lat: number;
  center_lng: number;
  radius_km: number;
  entity_type: string;
}

/** EVT-007: Feature flags + map defaults served to the frontend. */
export interface CrmMapFeatureFlags {
  crm_geocoding_enabled: boolean;
  default_lat: number;
  default_lng: number;
  default_radius_km: number;
  max_radius_km: number;
  max_pins: number;
}

export interface ProximitySearchParams {
  lat: number;
  lng: number;
  radius_km: number;
  limit?: number;
  entity_type?: string;
}

// ─── Endpoint wrappers (EXACT live paths) ────────────────────────────────────

/** EVT-007 — ungated: always returns flag state + map defaults. */
export const getCrmMapFeatureFlags = () =>
  api.get<CrmMapFeatureFlags>("/ui/crm/maps/feature-flags");

/** EVT-005 — list all of the caller's addresses that carry coordinates. */
export const getGeocodedAddresses = () =>
  api.get<GeocodedAddressList>("/ui/crm/geocoding/addresses");

/** EVT-005 — explicit on-demand re-geocode of a saved address. */
export const regeocodeAddress = (addressId: string) =>
  api.patch<GeocodedAddress>(`/ui/crm/geocoding/addresses/${encodeURIComponent(addressId)}`);

/** EVT-006 — Haversine radius search for nearby contacts/addresses. */
export const searchProximityContacts = (p: ProximitySearchParams) => {
  const params: Record<string, string> = {
    lat: String(p.lat),
    lng: String(p.lng),
    radius_km: String(p.radius_km),
  };
  if (p.limit != null) params["limit"] = String(p.limit);
  if (p.entity_type) params["entity_type"] = p.entity_type;
  return api.get<ProximitySearchResult>("/ui/crm/maps/contacts/proximity", params);
};
