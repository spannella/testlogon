import { api } from "@/api/client";
import type {
  CallRecordIn,
  CallRecordOut,
  CallHistoryResponse,
  CallStatsOut,
} from "@/api/types";

const BASE = "/ui/calls";

/** List paginated call history (newest first). */
export const listCallHistory = (params?: { cursor?: string; limit?: number }) => {
  const query: Record<string, string> = {};
  if (params?.cursor) query.cursor = params.cursor;
  if (params?.limit != null) query.limit = String(params.limit);
  return api.get<CallHistoryResponse>(`${BASE}/history`, Object.keys(query).length ? query : undefined);
};

/** Get a single call record by ID. */
export const getCallDetail = (callId: string) =>
  api.get<CallRecordOut>(`${BASE}/history/${callId}`);

/** Delete a call record from history. */
export const deleteCallRecord = (callId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/history/${callId}`);

/** Get aggregate call statistics. */
export const getCallStats = () =>
  api.get<CallStatsOut>(`${BASE}/stats`);

/** Record a call (internal/test endpoint). */
export const recordCall = (body: CallRecordIn) =>
  api.post<CallRecordOut>(`${BASE}/record`, body);
