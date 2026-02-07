import { api } from "@/api/client";
import type {
  Conversation,
  Message,
  SendTextMessageReq,
  StartConversationReq,
  StartGroupConversationReq,
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
