import { api } from "@/api/client";
import type {
  WebAuthnRegisterBeginReq,
  WebAuthnRegisterBeginResp,
  WebAuthnRegisterFinishReq,
  WebAuthnRegisterFinishResp,
  WebAuthnAuthBeginReq,
  WebAuthnAuthBeginResp,
  WebAuthnAuthFinishReq,
  WebAuthnAuthFinishResp,
} from "@/api/types";

// ─── Registration (authenticated) ──────────────────────────────

export const registerBegin = (body: WebAuthnRegisterBeginReq) =>
  api.post<WebAuthnRegisterBeginResp>("/ui/webauthn/register/begin", body);

export const registerFinish = (body: WebAuthnRegisterFinishReq) =>
  api.post<WebAuthnRegisterFinishResp>("/ui/webauthn/register/finish", body);

// ─── Authentication (public) ────────────────────────────────────

export const authenticateBegin = (body: WebAuthnAuthBeginReq) =>
  api.post<WebAuthnAuthBeginResp>("/ui/webauthn/authenticate/begin", body);

export const authenticateFinish = (body: WebAuthnAuthFinishReq) =>
  api.post<WebAuthnAuthFinishResp>("/ui/webauthn/authenticate/finish", body);
