import { api } from "@/api/client";
import type {
  BroadcastMuteReq,
  BroadcastBanReq,
  BroadcastAnnouncementReq,
  BroadcastScheduleReq,
  BroadcastModeratorOut,
  BroadcastBanOut,
  BroadcastModerationLogEntry,
} from "@/api/types";

const BASE = "/ui/broadcast/delegate";

// -- Chat moderation --

export async function pinMessage(
  creatorId: string,
  sessionId: string,
  messageId: string,
): Promise<{ ok: boolean; message_id: string; pinned: boolean }> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/chat/${messageId}/pin`, {});
}

export async function unpinMessage(
  creatorId: string,
  sessionId: string,
  messageId: string,
): Promise<{ ok: boolean; message_id: string; pinned: boolean }> {
  return api.del(`${BASE}/${creatorId}/sessions/${sessionId}/chat/${messageId}/pin`);
}

export async function deleteMessage(
  creatorId: string,
  sessionId: string,
  messageId: string,
): Promise<{ ok: boolean; message_id: string }> {
  return api.del(`${BASE}/${creatorId}/sessions/${sessionId}/chat/${messageId}`);
}

export async function muteViewer(
  creatorId: string,
  sessionId: string,
  req: BroadcastMuteReq,
): Promise<Record<string, unknown>> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/mute`, req);
}

export async function banViewer(
  creatorId: string,
  sessionId: string,
  req: BroadcastBanReq,
): Promise<Record<string, unknown>> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/ban`, req);
}

export async function unbanViewer(
  creatorId: string,
  sessionId: string,
  userId: string,
): Promise<{ ok: boolean }> {
  return api.del(`${BASE}/${creatorId}/sessions/${sessionId}/ban/${userId}`);
}

export async function postAnnouncement(
  creatorId: string,
  sessionId: string,
  req: BroadcastAnnouncementReq,
): Promise<{ ok: boolean; message_id: string; is_announcement: boolean }> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/announcement`, req);
}

// -- Broadcast control --

export async function startBroadcast(
  creatorId: string,
  sessionId: string,
): Promise<{ ok: boolean; session_id: string; status: string }> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/start`, {});
}

export async function stopBroadcast(
  creatorId: string,
  sessionId: string,
): Promise<{ ok: boolean; session_id: string; status: string }> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/stop`, {});
}

export async function scheduleBroadcast(
  creatorId: string,
  req: BroadcastScheduleReq,
): Promise<{ ok: boolean; session_id: string; status: string; title: string }> {
  return api.post(`${BASE}/${creatorId}/sessions/schedule`, req);
}

// -- Moderator management --

export async function registerModerator(
  creatorId: string,
  sessionId: string,
): Promise<BroadcastModeratorOut> {
  return api.post(`${BASE}/${creatorId}/sessions/${sessionId}/moderator/register`, {});
}

export async function listModerators(
  creatorId: string,
  sessionId: string,
): Promise<BroadcastModeratorOut[]> {
  return api.get(`${BASE}/${creatorId}/sessions/${sessionId}/moderators`);
}

export async function listBans(
  creatorId: string,
  sessionId: string,
): Promise<BroadcastBanOut[]> {
  return api.get(`${BASE}/${creatorId}/sessions/${sessionId}/bans`);
}

export async function getModerationLog(
  creatorId: string,
  sessionId: string,
  limit = 100,
): Promise<BroadcastModerationLogEntry[]> {
  return api.get(`${BASE}/${creatorId}/sessions/${sessionId}/moderation-log?limit=${limit}`);
}
