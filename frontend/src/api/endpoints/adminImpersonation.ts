import { api } from "@/api/client";

export interface ImpersonationStartReq {
  target_user_sub: string;
  reason?: string;
  ticket_id?: string;
  duration_seconds?: number;
}

export interface ImpersonationStartResp {
  ok: boolean;
  impersonation_id: string;
  actor_sub: string;
  effective_sub: string;
  token: string;
  expires_at: number;
  ttl_seconds: number;
  reason?: string;
  ticket_id?: string;
}

export interface ImpersonationStopResp {
  ok: boolean;
  impersonation_id: string;
  stopped?: boolean;
  already_stopped?: boolean;
}

export const startImpersonation = (body: ImpersonationStartReq) =>
  api.post<ImpersonationStartResp>("/admin/impersonation/start", body);

export const stopImpersonation = (body: { impersonation_id: string }) =>
  api.post<ImpersonationStopResp>("/admin/impersonation/stop", body);
