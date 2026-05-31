import { api } from "@/api/client";
import type {
  PaymentHealthConfigUpdate,
  PaymentHealthErrorDrilldown,
  PaymentHealthIncident,
  PaymentHealthProviderConfig,
  PaymentHealthProviderStatus,
  PaymentHealthTimeline,
  PaymentHealthToggleIn,
  PaymentHealthToggleOut,
  PaymentHealthUptimeReport,
} from "@/api/types";

const BASE = "/ui/admin/payment-health";

export const getAllProviderStatus = (params?: { hours?: number }) =>
  api.get<PaymentHealthProviderStatus[]>(
    BASE,
    params?.hours != null ? { hours: String(params.hours) } : undefined,
  );

export const getProviderStatus = (provider: string, params?: { hours?: number }) =>
  api.get<PaymentHealthProviderStatus>(
    `${BASE}/${provider}`,
    params?.hours != null ? { hours: String(params.hours) } : undefined,
  );

export const getProviderTimeline = (provider: string, params?: { hours?: number }) =>
  api.get<PaymentHealthTimeline>(
    `${BASE}/${provider}/timeline`,
    params?.hours != null ? { hours: String(params.hours) } : undefined,
  );

export const getProviderErrors = (provider: string, params?: { hours?: number }) =>
  api.get<PaymentHealthErrorDrilldown>(
    `${BASE}/${provider}/errors`,
    params?.hours != null ? { hours: String(params.hours) } : undefined,
  );

export const getProviderUptime = (provider: string, params?: { days?: number }) =>
  api.get<PaymentHealthUptimeReport>(
    `${BASE}/${provider}/uptime`,
    params?.days != null ? { days: String(params.days) } : undefined,
  );

export const getProviderConfig = (provider: string) =>
  api.get<PaymentHealthProviderConfig>(`${BASE}/${provider}/config`);

export const updateProviderConfig = (provider: string, data: PaymentHealthConfigUpdate) =>
  api.patch<PaymentHealthProviderConfig>(`${BASE}/${provider}/config`, data);

export const toggleProvider = (provider: string, data: PaymentHealthToggleIn) =>
  api.post<PaymentHealthToggleOut>(`${BASE}/${provider}/toggle`, data);

export const getIncidents = (params?: { provider?: string; limit?: number }) => {
  const q: Record<string, string> = {};
  if (params?.provider) q.provider = params.provider;
  if (params?.limit != null) q.limit = String(params.limit);
  return api.get<PaymentHealthIncident[]>(
    `${BASE}/incidents`,
    Object.keys(q).length ? q : undefined,
  );
};
