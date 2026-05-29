import { api } from "@/api/client";
import type {
  CollaborationCreateIn,
  CollaborationCounterIn,
  CollaborationOut,
  CollaborationListOut,
  CollaborationRevisionOut,
  CollaborationSettingsOut,
  CollaborationSettingsIn,
} from "@/api/types";

const BASE = "/ui/collaborations";

export async function createCollaboration(data: CollaborationCreateIn): Promise<CollaborationOut> {
  return api.post<CollaborationOut>(BASE, data);
}

export async function listCollaborations(params?: {
  role?: string;
  status?: string;
  cursor?: string;
  limit?: number;
}): Promise<CollaborationListOut> {
  return api.get<CollaborationListOut>(BASE, params);
}

export async function getCollaboration(collabId: string): Promise<CollaborationOut> {
  return api.get<CollaborationOut>(`${BASE}/${collabId}`);
}

export async function acceptCollaboration(collabId: string): Promise<CollaborationOut> {
  return api.post<CollaborationOut>(`${BASE}/${collabId}/accept`, {});
}

export async function rejectCollaboration(collabId: string): Promise<CollaborationOut> {
  return api.post<CollaborationOut>(`${BASE}/${collabId}/reject`, {});
}

export async function counterCollaboration(
  collabId: string,
  data: CollaborationCounterIn,
): Promise<CollaborationOut> {
  return api.post<CollaborationOut>(`${BASE}/${collabId}/counter`, data);
}

export async function cancelCollaboration(collabId: string): Promise<CollaborationOut> {
  return api.post<CollaborationOut>(`${BASE}/${collabId}/cancel`, {});
}

export async function terminateCollaboration(
  collabId: string,
  reason?: string,
): Promise<CollaborationOut> {
  return api.post<CollaborationOut>(`${BASE}/${collabId}/terminate`, { reason });
}

export async function getCollabRevisions(collabId: string): Promise<CollaborationRevisionOut[]> {
  return api.get<CollaborationRevisionOut[]>(`${BASE}/${collabId}/revisions`);
}

export async function getCollabSettings(): Promise<CollaborationSettingsOut> {
  return api.get<CollaborationSettingsOut>(`${BASE}/settings`);
}

export async function updateCollabSettings(
  data: CollaborationSettingsIn,
): Promise<CollaborationSettingsOut> {
  return api.put<CollaborationSettingsOut>(`${BASE}/settings`, data);
}
