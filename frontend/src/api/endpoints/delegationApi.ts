import { api } from "@/api/client";
import type {
  DelegationApiKeyCreateReq,
  DelegationApiKeyOut,
  DelegationApiKeyScopeOut,
} from "@/api/types";

const BASE = "/ui/delegation-api";

export async function createDelegationApiKey(
  req: DelegationApiKeyCreateReq,
): Promise<DelegationApiKeyOut> {
  return api.post<DelegationApiKeyOut>(`${BASE}/keys`, req);
}

export async function listMyDelegationApiKeys(): Promise<DelegationApiKeyOut[]> {
  return api.get<DelegationApiKeyOut[]>(`${BASE}/keys`);
}

export async function revokeMyDelegationApiKey(keyId: string): Promise<void> {
  return api.del<void>(`${BASE}/keys/${keyId}`);
}

export async function getDelegationApiKeyScope(
  keyId: string,
): Promise<DelegationApiKeyScopeOut> {
  return api.get<DelegationApiKeyScopeOut>(`${BASE}/keys/${keyId}/scope`);
}

export async function listCreatorDelegationApiKeys(): Promise<DelegationApiKeyOut[]> {
  return api.get<DelegationApiKeyOut[]>(`${BASE}/creator-keys`);
}

export async function revokeCreatorDelegationApiKey(keyId: string): Promise<void> {
  return api.del<void>(`${BASE}/creator-keys/${keyId}`);
}
