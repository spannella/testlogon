import { api } from "@/api/client";
import type {
  WebhookEndpointOut,
  WebhookEndpointCreateReq,
  WebhookEndpointUpdateReq,
  WebhookDeliveryOut,
  WebhookTestResult,
  WebhookHealthSummary,
  WebhookEventType,
} from "@/api/types";

// ─── User endpoints ─────────────────────────────────────────────

export const createWebhookEndpoint = (body: WebhookEndpointCreateReq) =>
  api.post<WebhookEndpointOut>("/ui/webhooks", body);

export const listWebhookEndpoints = () =>
  api.get<WebhookEndpointOut[]>("/ui/webhooks");

export const getWebhookEndpoint = (endpointId: string) =>
  api.get<WebhookEndpointOut>(`/ui/webhooks/${endpointId}`);

export const updateWebhookEndpoint = (endpointId: string, body: WebhookEndpointUpdateReq) =>
  api.patch<WebhookEndpointOut>(`/ui/webhooks/${endpointId}`, body);

export const deleteWebhookEndpoint = (endpointId: string) =>
  api.del(`/ui/webhooks/${endpointId}`);

export const testWebhookEndpoint = (endpointId: string) =>
  api.post<WebhookTestResult>(`/ui/webhooks/${endpointId}/test`, {});

export const rotateWebhookSecret = (endpointId: string) =>
  api.post<{ secret: string }>(`/ui/webhooks/${endpointId}/rotate-secret`, {});

export const listWebhookDeliveries = (
  endpointId: string,
  opts?: { limit?: number; cursor?: string },
) =>
  api.get<{ deliveries: WebhookDeliveryOut[]; cursor: string | null }>(
    `/ui/webhooks/${endpointId}/deliveries`,
    {
      ...(opts?.limit ? { limit: String(opts.limit) } : {}),
      ...(opts?.cursor ? { cursor: opts.cursor } : {}),
    },
  );

export const listWebhookEventTypes = () =>
  api.get<{ event_types: WebhookEventType[] }>("/ui/webhooks/event-types");

// ─── Admin endpoints ────────────────────────────────────────────

export const adminListWebhookEndpoints = () =>
  api.get<{ endpoints: WebhookEndpointOut[] }>("/ui/admin/webhooks/endpoints");

export const adminGetWebhookHealth = () =>
  api.get<WebhookHealthSummary>("/ui/admin/webhooks/health");

export const adminListDeadLetters = () =>
  api.get<{ deliveries: WebhookDeliveryOut[] }>("/ui/admin/webhooks/dead-letter");

export const adminDisableWebhookEndpoint = (endpointId: string, reason: string) =>
  api.post<{ ok: boolean }>(`/ui/admin/webhooks/endpoints/${endpointId}/disable`, { reason });
