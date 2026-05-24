import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export interface ChatMessage {
  message_id: string;
  session_id: string;
  sender_id: string;
  sender_display_name: string;
  text: string;
  created_at: number;
  deleted: boolean;
}

export interface ChatHistoryResponse {
  messages: ChatMessage[];
  has_more: boolean;
  oldest_sort_key: string | null;
}

export interface ChatMuteResponse {
  target_user_id: string;
  muted_until: number;
  session_id: string;
}

// ─── API functions ──────────────────────────────────────────────

export const sendChatMessage = (sessionId: string, text: string) =>
  api.post<ChatMessage>(`/broadcast/sessions/${sessionId}/chat`, { text });

export const getChatHistory = (
  sessionId: string,
  params?: { limit?: number; before?: string },
) =>
  api.get<ChatHistoryResponse>(
    `/broadcast/sessions/${sessionId}/chat`,
    params as Record<string, string>,
  );

export const deleteChatMessage = (sessionId: string, messageId: string) =>
  api.del<{ ok: boolean; message_id: string }>(
    `/broadcast/sessions/${sessionId}/chat/${messageId}`,
  );

export const muteChatUser = (
  sessionId: string,
  targetUserId: string,
  durationSeconds: number,
) =>
  api.post<ChatMuteResponse>(`/broadcast/sessions/${sessionId}/chat/mute`, {
    target_user_id: targetUserId,
    duration_seconds: durationSeconds,
  });
