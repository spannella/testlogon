import { api } from "@/api/client";
import type {
  CompareResponse,
  DropOffResponse,
  FunnelResponse,
  GeographicResponse,
  ProcessingTimesResponse,
  RejectionReasonsResponse,
  ScreeningHitsResponse,
  SnapshotResponse,
  TrendsResponse,
} from "@/api/types";

const toParams = (obj: Record<string, string | number | undefined>): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null && v !== "") {
      out[k] = String(v);
    }
  }
  return out;
};

export const getFunnel = (params: {
  from: number;
  to: number;
  country?: string;
  tier?: string;
}) => api.get<FunnelResponse>("/v1/kyc/analytics/funnel", toParams(params));

export const getSnapshot = (params: {
  from: number;
  to: number;
  country?: string;
  tier?: string;
}) => api.get<SnapshotResponse>("/v1/kyc/analytics/snapshot", toParams(params));

export const getTrends = (params: { granularity: string; periods: number }) =>
  api.get<TrendsResponse>("/v1/kyc/analytics/trends", toParams(params));

export const getProcessingTimes = (params: {
  from: number;
  to: number;
  bucket_hours?: number;
}) => api.get<ProcessingTimesResponse>("/v1/kyc/analytics/processing-times", toParams(params));

export const getRejectionReasons = (params: { from: number; to: number }) =>
  api.get<RejectionReasonsResponse>("/v1/kyc/analytics/rejection-reasons", toParams(params));

export const getScreeningHits = (params: { granularity: string; periods: number }) =>
  api.get<ScreeningHitsResponse>("/v1/kyc/analytics/screening-hits", toParams(params));

export const getGeographic = (params: { from: number; to: number }) =>
  api.get<GeographicResponse>("/v1/kyc/analytics/geographic", toParams(params));

export const getDropOff = (params: { from: number; to: number }) =>
  api.get<DropOffResponse>("/v1/kyc/analytics/drop-off", toParams(params));

export const comparePeriods = (params: {
  current_from: number;
  current_to: number;
  previous_from: number;
  previous_to: number;
}) => api.get<CompareResponse>("/v1/kyc/analytics/compare", toParams(params));
