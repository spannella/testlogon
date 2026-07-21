/**
 * Group Video Call API endpoints (CALL-012).
 */
import { api } from "../client";
import type {
  GroupCallOut,
  GroupCallJoinOut,
  GroupCallLeaveOut,
  GroupCallEndOut,
  GroupCallParticipantsOut,
  GroupCallActiveOut,
  GroupCallHistoryOut,
  GroupCallSignalOut,
  GroupCallMediaUpdateOut,
  GroupCallLiveKitToken,
} from "../types";

const BASE = "/ui/calls/group";

export async function createGroupCall(params: {
  conversation_id: string;
  mode?: "audio" | "video";
  max_participants?: number;
}): Promise<GroupCallOut> {
  return api.post<GroupCallOut>(`${BASE}/create`, params);
}

export async function joinGroupCall(callId: string): Promise<GroupCallJoinOut> {
  return api.post<GroupCallJoinOut>(`${BASE}/${callId}/join`);
}

export async function leaveGroupCall(callId: string): Promise<GroupCallLeaveOut> {
  return api.post<GroupCallLeaveOut>(`${BASE}/${callId}/leave`);
}

export async function endGroupCall(callId: string): Promise<GroupCallEndOut> {
  return api.post<GroupCallEndOut>(`${BASE}/${callId}/end`);
}

export async function getGroupCall(callId: string): Promise<GroupCallOut> {
  return api.get<GroupCallOut>(`${BASE}/${callId}`);
}

export async function getGroupCallParticipants(callId: string): Promise<GroupCallParticipantsOut> {
  return api.get<GroupCallParticipantsOut>(`${BASE}/${callId}/participants`);
}

export async function getActiveGroupCall(conversationId: string): Promise<GroupCallActiveOut> {
  return api.get<GroupCallActiveOut>(`${BASE}/active/${conversationId}`);
}

export async function getGroupCallHistory(conversationId: string): Promise<GroupCallHistoryOut> {
  return api.get<GroupCallHistoryOut>(`${BASE}/history/${conversationId}`);
}

export async function sendGroupCallSignal(
  callId: string,
  params: { type: string; target_user_id: string; payload: Record<string, unknown> },
): Promise<GroupCallSignalOut> {
  return api.post<GroupCallSignalOut>(`${BASE}/${callId}/signal`, params);
}

export async function updateGroupCallMedia(
  callId: string,
  params: { audio?: boolean; video?: boolean; screen?: boolean },
): Promise<GroupCallMediaUpdateOut> {
  return api.patch<GroupCallMediaUpdateOut>(`${BASE}/${callId}/media`, params);
}

/**
 * Fetch a LiveKit SFU join token for a group call. Only valid when the join
 * response advertised sfu_provider==="livekit". Returns 503 when LiveKit is not
 * configured server-side (caller should fall back to mesh).
 */
export async function getGroupCallLiveKitToken(
  callId: string,
): Promise<GroupCallLiveKitToken> {
  return api.get<GroupCallLiveKitToken>(`${BASE}/${callId}/livekit-token`);
}
