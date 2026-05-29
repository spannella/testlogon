import { api } from "@/api/client";
import type {
  LlmKeyOut,
  LlmKeyListOut,
  LlmKeyCreateIn,
  LlmKeyRotateIn,
  LlmKeyAssignIn,
  LlmKeyTestOut,
  LlmKeyUsageOut,
  LlmProviderListOut,
} from "@/api/types";

// ─── Providers ───────────────────────────────────────────────────

export const listProviders = () =>
  api.get<LlmProviderListOut>("/ui/agent/llm-providers");

// ─── Keys CRUD ───────────────────────────────────────────────────

export const listKeys = () =>
  api.get<LlmKeyListOut>("/ui/agent/llm-keys");

export const getKey = (keyId: string) =>
  api.get<LlmKeyOut>(`/ui/agent/llm-keys/${keyId}`);

export const addKey = (body: LlmKeyCreateIn) =>
  api.post<LlmKeyOut>("/ui/agent/llm-keys", body);

export const deleteKey = (keyId: string) =>
  api.del<{ ok: boolean }>(`/ui/agent/llm-keys/${keyId}`);

// ─── Test / Rotate / Usage ───────────────────────────────────────

export const testKey = (keyId: string) =>
  api.post<LlmKeyTestOut>(`/ui/agent/llm-keys/${keyId}/test`);

export const rotateKey = (keyId: string, body: LlmKeyRotateIn) =>
  api.post<LlmKeyOut>(`/ui/agent/llm-keys/${keyId}/rotate`, body);

export const getKeyUsage = (keyId: string) =>
  api.get<LlmKeyUsageOut>(`/ui/agent/llm-keys/${keyId}/usage`);

// ─── Worker assignment ───────────────────────────────────────────

export const assignKey = (keyId: string, body: LlmKeyAssignIn) =>
  api.post<LlmKeyOut>(`/ui/agent/llm-keys/${keyId}/assign`, body);

export const unassignKey = (keyId: string, workerId: string) =>
  api.del<LlmKeyOut>(`/ui/agent/llm-keys/${keyId}/assign/${workerId}`);

// ─── Admin ───────────────────────────────────────────────────────

export const adminListKeys = () =>
  api.get<LlmKeyListOut>("/ui/admin/agent/llm-keys");
