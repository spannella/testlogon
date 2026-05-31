import { api } from "@/api/client";
import type {
  AdFraudEvent,
  AdFraudAccountRisk,
  AdFraudSummary,
} from "@/api/types";

export const getFraudEvents = (opts?: { date?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.date) params["date"] = opts.date;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<AdFraudEvent[]>("/ui/ads/fraud/events", params);
};

export const getFraudEvent = (eventId: string) =>
  api.get<AdFraudEvent>(`/ui/ads/fraud/events/${eventId}`);

export const reviewFraudEvent = (eventId: string, decision: "confirm" | "dismiss") =>
  api.post<AdFraudEvent>(`/ui/ads/fraud/events/${eventId}/review`, { decision });

export const getFraudSummary = () =>
  api.get<AdFraudSummary>("/ui/ads/fraud/summary");

export const getFraudAccounts = () =>
  api.get<AdFraudAccountRisk[]>("/ui/ads/fraud/accounts");

export const getFraudAccount = (accountId: string) =>
  api.get<AdFraudAccountRisk>(`/ui/ads/fraud/accounts/${accountId}`);

export const suspendFraudAccount = (accountId: string, reason = "") =>
  api.post<{ ok: boolean; status: string }>(
    `/ui/ads/fraud/accounts/${accountId}/suspend`,
    { reason },
  );

export const unsuspendFraudAccount = (accountId: string) =>
  api.post<{ ok: boolean; status: string }>(
    `/ui/ads/fraud/accounts/${accountId}/unsuspend`,
  );
