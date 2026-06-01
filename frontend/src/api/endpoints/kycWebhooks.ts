import { api } from "@/api/client";
import type {
  KycWebhookEventTypesOut,
  KycWebhookPrefsOut,
  KycWebhookPrefsUpdateRequest,
  KycWebhookNotificationsOut,
  KycWebhookEmitRequest,
  KycWebhookEmitResult,
} from "@/api/types";

// KYC Webhooks & Notifications (KYC-011)

export const listKycWebhookEventTypes = () =>
  api.get<KycWebhookEventTypesOut>("/ui/kyc/webhooks/event-types");

export const getKycWebhookPrefs = () =>
  api.get<KycWebhookPrefsOut>("/ui/kyc/webhooks/preferences");

export const updateKycWebhookPrefs = (body: KycWebhookPrefsUpdateRequest) =>
  api.patch<KycWebhookPrefsOut>("/ui/kyc/webhooks/preferences", body);

export const getKycWebhookNotifications = (limit = 50) =>
  api.get<KycWebhookNotificationsOut>("/ui/kyc/webhooks/notifications", {
    limit: String(limit),
  });

// Admin/root test-emit.
export const emitKycWebhookEvent = (body: KycWebhookEmitRequest) =>
  api.post<KycWebhookEmitResult>("/ui/kyc/webhooks/test-emit", body);
