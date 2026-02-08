import { api } from "@/api/client";
import type {
  SessionStartReq,
  SessionStartResp,
  SessionFinalizeReq,
  SessionFinalizeResp,
  MeResp,
  SessionInfo,
  TotpVerifyReq,
  SmsBeginReq,
  SmsVerifyReq,
  EmailBeginReq,
  EmailVerifyReq,
  RecoveryReq,
  MfaVerifyResp,
  OkResp,
  StatusResp,
  ChallengeResp,
  PasswordRecoveryStartReq,
  PasswordRecoveryStartResp,
  PasswordRecoveryConfirmReq,
  PasswordlessStartReq,
  PasswordlessStartResp,
  PasswordlessVerifyReq,
  PasswordlessVerifyResp,
} from "@/api/types";

// ─── Session ─────────────────────────────────────────────────────

export const sessionStart = (body: SessionStartReq) =>
  api.post<SessionStartResp>("/ui/session/start", body);

export const sessionFinalize = (body: SessionFinalizeReq) =>
  api.post<SessionFinalizeResp>("/ui/session/finalize", body);

export const getMe = () =>
  api.get<MeResp>("/ui/me");

export const getSessions = () =>
  api.get<{ sessions: SessionInfo[] }>("/ui/sessions");

export const revokeSession = (sessionId: string) =>
  api.post<StatusResp>("/ui/sessions/revoke", { session_id: sessionId });

export const revokeOtherSessions = () =>
  api.post<StatusResp>("/ui/sessions/revoke_others");

export const logout = () =>
  api.post<StatusResp>("/ui/session/logout");

export const refreshSession = () =>
  api.post<StatusResp>("/ui/session/refresh");

// ─── MFA Verification (login flow) ──────────────────────────────

export const verifyTotp = (body: TotpVerifyReq) =>
  api.post<MfaVerifyResp>("/ui/mfa/totp/verify", body);

export const beginSms = (body: SmsBeginReq) =>
  api.post<ChallengeResp>("/ui/mfa/sms/begin", body);

export const verifySms = (body: SmsVerifyReq) =>
  api.post<MfaVerifyResp>("/ui/mfa/sms/verify", body);

export const beginEmail = (body: EmailBeginReq) =>
  api.post<ChallengeResp>("/ui/mfa/email/begin", body);

export const verifyEmail = (body: EmailVerifyReq) =>
  api.post<MfaVerifyResp>("/ui/mfa/email/verify", body);

export const useRecoveryCode = (factor: string, body: RecoveryReq) =>
  api.post<MfaVerifyResp>(`/ui/mfa/recovery/${factor}`, body);

// ─── Password Recovery ───────────────────────────────────────────

export const passwordRecoveryStart = (body: PasswordRecoveryStartReq) =>
  api.post<PasswordRecoveryStartResp>("/ui/password-recovery/start", body);

export const passwordRecoveryConfirm = (body: PasswordRecoveryConfirmReq) =>
  api.post<OkResp>("/ui/password-recovery/confirm", body);

// ─── Passwordless (Magic Link) ──────────────────────────────────

export const passwordlessStart = (body: PasswordlessStartReq) =>
  api.post<PasswordlessStartResp>("/ui/passwordless/start", body);

export const passwordlessVerify = (body: PasswordlessVerifyReq) =>
  api.post<PasswordlessVerifyResp>("/ui/passwordless/verify", body);
