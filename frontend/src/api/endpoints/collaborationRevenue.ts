import { api } from "@/api/client";
import type {
  CollabContentAssignIn,
  CollabContentListOut,
  CollabContentSplitTriggerIn,
  CollabDisputeIn,
  CollabDisputeListOut,
  CollabDisputeResolveIn,
  CollabSplitHistoryOut,
} from "@/api/types";

const BASE = "/ui/collaborations";

export async function assignContent(
  collabId: string,
  data: CollabContentAssignIn,
): Promise<{ ok: boolean; content_id: string; collaboration_id: string }> {
  return api.post(`${BASE}/${collabId}/content`, data);
}

export async function listAssignedContent(collabId: string): Promise<CollabContentListOut> {
  return api.get<CollabContentListOut>(`${BASE}/${collabId}/content`);
}

export async function unassignContent(
  collabId: string,
  contentId: string,
): Promise<{ ok: boolean; content_id: string; collaboration_id: string }> {
  return api.del(`${BASE}/${collabId}/content/${contentId}`);
}

export async function recordRevenueEvent(
  collabId: string,
  contentId: string,
  data: CollabContentSplitTriggerIn,
): Promise<{ ok: boolean; split: Record<string, unknown> }> {
  return api.post(`${BASE}/${collabId}/content/${contentId}/revenue-event`, data);
}

export async function getSplitHistory(
  collabId: string,
  params?: { limit?: number; cursor?: string },
): Promise<CollabSplitHistoryOut> {
  const p: Record<string, string> = {};
  if (params?.limit != null) p.limit = String(params.limit);
  if (params?.cursor) p.cursor = params.cursor;
  return api.get<CollabSplitHistoryOut>(`${BASE}/${collabId}/splits`, p);
}

export async function fileDispute(
  collabId: string,
  splitId: string,
  data: CollabDisputeIn,
): Promise<{ ok: boolean; dispute_status: string }> {
  return api.post(`${BASE}/${collabId}/splits/${splitId}/dispute`, data);
}

export async function listDisputes(
  collabId: string,
  status?: string,
): Promise<CollabDisputeListOut> {
  const p: Record<string, string> = {};
  if (status) p.status = status;
  return api.get<CollabDisputeListOut>(`${BASE}/${collabId}/disputes`, p);
}

export async function resolveDispute(
  collabId: string,
  disputeId: string,
  data: CollabDisputeResolveIn,
): Promise<{ ok: boolean; status: string; dispute: Record<string, unknown> }> {
  return api.post(`${BASE}/${collabId}/disputes/${disputeId}/resolve`, data);
}
