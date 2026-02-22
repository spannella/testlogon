import { api } from "@/api/client";
import type {
  ApiKey,
  ApiKeyCreated,
  CreateApiKeyReq,
  RevokeApiKeyReq,
  ApiKeyIpRulesReq,
  AccountState,
  AccountStatusReq,
  AccountClosureFinalizeReq,
  DeviceTrust,
  OkResp,
  TotpDevice,
  TotpDeviceBeginReq,
  TotpDeviceBeginResp,
  TotpDeviceConfirmReq,
  SmsDevice,
  SmsDeviceBeginReq,
  SmsDeviceBeginResp,
  SmsDeviceConfirmReq,
  EmailDevice,
  EmailDeviceBeginReq,
  EmailDeviceBeginResp,
  EmailDeviceConfirmReq,
  DeviceRemoveConfirmReq,
} from "@/api/types";

// ─── API Keys ────────────────────────────────────────────────────

export const getApiKeys = () =>
  api.get<{ keys: ApiKey[] }>("/ui/api_keys");

export const createApiKey = (body: CreateApiKeyReq) =>
  api.post<ApiKeyCreated>("/ui/api_keys", body);

export const revokeApiKey = (body: RevokeApiKeyReq) =>
  api.post<OkResp>("/ui/api_keys/revoke", body);

export const setApiKeyIpRules = (body: ApiKeyIpRulesReq) =>
  api.post<{ ok: boolean; allow_cidrs: string[]; deny_cidrs: string[] }>(
    "/ui/api_keys/ip_rules",
    body,
  );

// ─── Account Status ──────────────────────────────────────────────

export const getAccountStatus = () =>
  api.get<AccountState>("/ui/account/status");

export const suspendAccount = (body?: AccountStatusReq) =>
  api.post<AccountState>("/ui/account/suspend", body);

export const reactivateAccount = (body?: AccountStatusReq) =>
  api.post<AccountState>("/ui/account/reactivate", body);

// ─── Account Closure ─────────────────────────────────────────────

export const startAccountClosure = () =>
  api.post<{ auth_required: boolean; challenge_id: string; required_factors: string[] }>(
    "/ui/account/closure/start",
  );

export const finalizeAccountClosure = (body: AccountClosureFinalizeReq) =>
  api.post<{ status: string }>("/ui/account/closure/finalize", body);

// ─── Device Trust ────────────────────────────────────────────────

export const getDevices = () =>
  api.get<{ devices: DeviceTrust[] }>("/ui/devices");

export const trustDevice = (deviceId: string) =>
  api.post<{ status: string }>(`/ui/devices/${deviceId}/trust`);

export const revokeDevice = (deviceId: string) =>
  api.post<{ status: string }>(`/ui/devices/${deviceId}/revoke`);

// ─── MFA Devices ─────────────────────────────────────────────────

export const getTotpDevices = () =>
  api.get<{ devices: TotpDevice[] }>("/ui/mfa/totp/devices");

export const beginTotpEnrollment = (body: TotpDeviceBeginReq) =>
  api.post<TotpDeviceBeginResp>("/ui/mfa/totp/devices/begin", body);

export const confirmTotpEnrollment = (body: TotpDeviceConfirmReq) =>
  api.post<{ ok: boolean; recovery_codes: string[] }>("/ui/mfa/totp/devices/confirm", body);

export const removeTotpDevice = (deviceId: string, totpCode: string) =>
  api.post<OkResp>(`/ui/mfa/totp/devices/${deviceId}/remove`, { totp_code: totpCode });

export const getSmsDevices = () =>
  api.get<{ devices: SmsDevice[] }>("/ui/mfa/sms/devices");

export const beginSmsEnrollment = (body: SmsDeviceBeginReq) =>
  api.post<SmsDeviceBeginResp>("/ui/mfa/sms/devices/begin", body);

export const confirmSmsEnrollment = (body: SmsDeviceConfirmReq) =>
  api.post<{ ok: boolean; sms_device_id: string; recovery_codes: string[] }>(
    "/ui/mfa/sms/devices/confirm",
    body,
  );

export const beginSmsRemoval = (smsDeviceId: string) =>
  api.post<{ challenge_id: string; sent_to: string[] }>(
    `/ui/mfa/sms/devices/${smsDeviceId}/remove/begin`,
  );

export const confirmSmsRemoval = (body: DeviceRemoveConfirmReq) =>
  api.post<OkResp>("/ui/mfa/sms/devices/remove/confirm", body);

export const getEmailDevices = () =>
  api.get<{ devices: EmailDevice[] }>("/ui/mfa/email/devices");

export const beginEmailEnrollment = (body: EmailDeviceBeginReq) =>
  api.post<EmailDeviceBeginResp>("/ui/mfa/email/devices/begin", body);

export const confirmEmailEnrollment = (body: EmailDeviceConfirmReq) =>
  api.post<{ ok: boolean; email_device_id: string; recovery_codes: string[] }>(
    "/ui/mfa/email/devices/confirm",
    body,
  );

export const beginEmailRemoval = (emailDeviceId: string) =>
  api.post<{ challenge_id: string; sent_to: string[] }>(
    `/ui/mfa/email/devices/${emailDeviceId}/remove/begin`,
  );

export const confirmEmailRemoval = (body: DeviceRemoveConfirmReq) =>
  api.post<OkResp>("/ui/mfa/email/devices/remove/confirm", body);
