import { api } from "@/api/client";
import type {
  BillingConfigOut,
  BillingConfigUpdate,
  BillingConfigAuditLog,
  BillingConfigPreview,
} from "@/api/types";

const BASE = "/ui/admin/billing-config";

export const getBillingConfig = () => api.get<BillingConfigOut>(BASE);

export const updateBillingConfig = (data: BillingConfigUpdate) =>
  api.patch<BillingConfigOut>(BASE, data);

export const resetBillingConfig = (keys?: string[]) =>
  api.post<BillingConfigOut>(`${BASE}/reset`, { keys: keys ?? null });

export const previewBillingConfig = (data: BillingConfigUpdate) =>
  api.post<BillingConfigPreview>(`${BASE}/preview`, data);

export const getBillingConfigAudit = (params?: { limit?: number; cursor?: string }) => {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<BillingConfigAuditLog>(`${BASE}/audit`, q);
};
