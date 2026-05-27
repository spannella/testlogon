import { api } from "@/api/client";
import type {
  GeoRestrictionRequest,
  GeoRestrictionOut,
  GeoCountriesListOut,
  MyCountryOut,
  GeoCheckResult,
} from "@/api/types";

// ─── Country list ─────────────────────────────────────────────────

export const listCountries = () =>
  api.get<GeoCountriesListOut>("/ui/geo/countries");

export const getMyCountry = () =>
  api.get<MyCountryOut>("/ui/geo/my-country");

// ─── Per-video geo CRUD ───────────────────────────────────────────

export const getVideoGeo = (videoId: string) =>
  api.get<{ geo_mode: string | null; geo_countries: string[] | null }>(
    `/ui/geo/videos/${videoId}`
  );

export const setVideoGeo = (videoId: string, body: GeoRestrictionRequest) =>
  api.patch<GeoRestrictionOut>(`/ui/geo/videos/${videoId}`, body);

// ─── Per-broadcast geo CRUD ───────────────────────────────────────

export const setBroadcastGeo = (sessionId: string, body: GeoRestrictionRequest) =>
  api.patch<GeoRestrictionOut>(`/ui/geo/broadcasts/${sessionId}`, body);

// ─── Per-catalog-item geo CRUD ────────────────────────────────────

export const setCatalogGeo = (itemId: string, body: GeoRestrictionRequest) =>
  api.patch<GeoRestrictionOut>(`/ui/geo/catalog/${itemId}`, body);

// ─── Dry-run check ────────────────────────────────────────────────

export const checkGeoDryRun = (params: {
  geo_mode?: string;
  geo_countries?: string;
}) =>
  api.get<GeoCheckResult>("/ui/geo/check", params);

// ─── Cache management ─────────────────────────────────────────────

export const clearGeoCache = () =>
  api.post<{ ok: boolean; evicted: number }>("/ui/geo/clear-cache", {});
