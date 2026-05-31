import { api } from "@/api/client";
import { withApiBase } from "@/api/client";
import type {
  PlatformFinancialKpis,
  PlatformFinancialProviderResponse,
  PlatformFinancialRollupOut,
  PlatformFinancialTopCreatorsResponse,
  PlatformFinancialTrendsResponse,
  PlatformFinancialTypeResponse,
} from "@/api/types";

const BASE = "/ui/admin/financial-dashboard";

export const getFinancialDashboardKpis = (params: { start_date: string; end_date: string }) =>
  api.get<PlatformFinancialKpis>(`${BASE}/kpis`, params);

export const getFinancialDashboardTrends = (params: {
  start_date: string;
  end_date: string;
  granularity?: string;
}) =>
  api.get<PlatformFinancialTrendsResponse>(`${BASE}/trends`, {
    start_date: params.start_date,
    end_date: params.end_date,
    granularity: params.granularity ?? "daily",
  });

export const getFinancialDashboardProviders = (params: { start_date: string; end_date: string }) =>
  api.get<PlatformFinancialProviderResponse>(`${BASE}/providers`, params);

export const getFinancialDashboardTypes = (params: { start_date: string; end_date: string }) =>
  api.get<PlatformFinancialTypeResponse>(`${BASE}/types`, params);

export const getFinancialDashboardTopCreators = (params: {
  start_date: string;
  end_date: string;
  limit?: number;
}) =>
  api.get<PlatformFinancialTopCreatorsResponse>(`${BASE}/top-creators`, {
    start_date: params.start_date,
    end_date: params.end_date,
    ...(params.limit != null ? { limit: String(params.limit) } : {}),
  });

export const triggerFinancialDashboardRollup = (body: { date?: string }) =>
  api.post<PlatformFinancialRollupOut>(`${BASE}/rollup`, body);

/**
 * CSV export returns raw text, so bypass the JSON client and fetch directly.
 * Returns a Blob suitable for download.
 */
export const exportFinancialDashboardCsv = async (params: {
  start_date: string;
  end_date: string;
}): Promise<Blob> => {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(withApiBase(`${BASE}/export/csv?${qs}`), {
    method: "GET",
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(`CSV export failed (${res.status})`);
  }
  return res.blob();
};
