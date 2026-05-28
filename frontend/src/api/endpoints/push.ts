import { api } from "@/api/client";
import type {
  PushDevice,
  PushRegisterReq,
  PushRevokeReq,
  OkResp,
} from "@/api/types";

export const getVapidKey = () =>
  api.get<{ vapid_public_key: string }>("/ui/push/vapid-key");

export const listPushDevices = () =>
  api.get<{ devices: PushDevice[] }>("/ui/push/devices");

export const registerPush = (body: PushRegisterReq) =>
  api.post<PushDevice>("/ui/push/register", body);

export const revokePush = (body: PushRevokeReq) =>
  api.post<OkResp>("/ui/push/revoke", body);

export const testPush = () =>
  api.post<OkResp>("/ui/push/test");
