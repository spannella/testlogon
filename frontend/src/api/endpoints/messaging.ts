import { api } from "@/api/client";
import type {
  Conversation,
  Message,
  SendTextMessageReq,
  StartConversationReq,
  StartGroupConversationReq,
  PresenceStatus,
  TypingUser,
  UserSearchResult,
} from "@/api/types";

export const getConversations = (cursor?: string) =>
  api.get<{ conversations: Conversation[]; next_cursor?: string }>(
    "/messaging/conversations",
    cursor ? { cursor } : undefined,
  );

export const getConversation = (id: string) =>
  api.get<Conversation>(`/messaging/conversations/${id}`);

export const startConversation = (body: StartConversationReq) =>
  api.post<Conversation>("/messaging/conversations/start", body);

export const startGroupConversation = (body: StartGroupConversationReq) =>
  api.post<Conversation>("/messaging/conversations/group", body);

export const getMessages = (conversationId: string, cursor?: string) =>
  api.get<{ messages: Message[]; next_cursor?: string }>(
    `/messaging/conversations/${conversationId}/messages`,
    cursor ? { cursor } : undefined,
  );

export const sendTextMessage = (conversationId: string, body: SendTextMessageReq) =>
  api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/text`,
    body,
  );

export const sendImageMessage = (conversationId: string, formData: FormData) =>
  api.upload<Message>(
    `/messaging/conversations/${conversationId}/messages/image`,
    formData,
  );

export const editMessage = (conversationId: string, messageId: string, body: { body: string }) =>
  api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/edit`,
    body,
  );

export const reactToMessage = (conversationId: string, messageId: string, emoji: string) =>
  api.post(`/messaging/conversations/${conversationId}/messages/${messageId}/react`, { emoji });

export const deleteMessage = (conversationId: string, messageId: string) =>
  api.del(`/messaging/conversations/${conversationId}/messages/${messageId}`);

export const markRead = (conversationId: string, messageId: string) =>
  api.post(`/messaging/conversations/${conversationId}/mark-read`, { last_read_message_id: messageId });

export const muteConversation = (conversationId: string, muted: boolean) =>
  api.put(`/messaging/conversations/${conversationId}/mute`, { muted });

export const updateConversation = (conversationId: string, body: { title?: string }) =>
  api.patch<Conversation>(`/messaging/conversations/${conversationId}`, body);

// ─── Presence ──────────────────────────────────────────────────

export const sendHeartbeat = (device?: string) =>
  api.post<{ ok: boolean; user_id: string; online: boolean; last_seen_at: number }>(
    "/messaging/presence/heartbeat",
    { device },
  );

export const getPresence = (userIds: string[]) =>
  api.get<PresenceStatus[]>(
    "/messaging/presence",
    { user_ids: userIds.join(",") },
  );

// ─── Typing ────────────────────────────────────────────────────

export const sendTyping = (conversationId: string, isTyping = true) =>
  api.post<{ ok: boolean; is_typing: boolean; ttl: number }>(
    `/messaging/conversations/${conversationId}/typing`,
    { is_typing: isTyping },
  );

export const getTyping = (conversationId: string) =>
  api.get<TypingUser[]>(`/messaging/conversations/${conversationId}/typing`);

// ─── User Search ───────────────────────────────────────────────

export const searchUsers = (q: string, limit?: number) => {
  const qs: Record<string, string> = { q };
  if (limit) qs.limit = String(limit);
  return api.get<UserSearchResult[]>("/messaging/contacts/search", qs);
};
