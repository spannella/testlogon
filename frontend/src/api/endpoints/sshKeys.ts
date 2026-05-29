import { api } from "@/api/client";
import type {
  SshKeyOut,
  SshKeyListOut,
  PublicKeyOut,
  GenerateSshKeyIn,
  UploadSshKeyIn,
} from "@/api/types";

const BASE = "/ui/remote/ssh-keys";

export const listSshKeys = () => api.get<SshKeyListOut>(BASE);

export const getSshKey = (keyId: string) =>
  api.get<SshKeyOut>(`${BASE}/${keyId}`);

export const generateSshKey = (body: GenerateSshKeyIn) =>
  api.post<SshKeyOut>(`${BASE}/generate`, body);

export const uploadSshKey = (body: UploadSshKeyIn) =>
  api.post<SshKeyOut>(BASE, body);

export const deleteSshKey = (keyId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/${keyId}`);

export const getPublicKey = (keyId: string) =>
  api.get<PublicKeyOut>(`${BASE}/${keyId}/public`);

export const associateKeyWithHost = (keyId: string, hostId: string) =>
  api.post<{ ok: boolean }>(`${BASE}/${keyId}/associate`, { host_id: hostId });

export const disassociateKeyFromHost = (keyId: string, hostId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/${keyId}/associate/${hostId}`);
