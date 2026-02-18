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
  MessageViewer,
  ForwardMessageReq,
  AddParticipantsReq,
  UpdateRoleReq,
} from "@/api/types";
import { adaptConversation, adaptMessage } from "./messagingAdapter";

export const getConversations = async (cursor?: string) => {
  const res = await api.get<{ conversations: Conversation[]; next_cursor?: string }>(
    "/messaging/conversations",
    cursor ? { cursor } : undefined,
  );
  return {
    conversations: (res.conversations ?? []).map(adaptConversation),
    next_cursor: res.next_cursor,
  };
};

export const getConversation = async (id: string) => {
  const res = await api.get<Conversation>(`/messaging/conversations/${id}`);
  return adaptConversation(res);
};

export const startConversation = async (body: StartConversationReq) => {
  const res = await api.post<Conversation>("/messaging/conversations/start", body);
  return adaptConversation(res);
};

export const startGroupConversation = async (body: StartGroupConversationReq) => {
  const res = await api.post<Conversation>("/messaging/conversations/group", body);
  return adaptConversation(res);
};

export const getMessages = async (conversationId: string, cursor?: string) => {
  const res = await api.get<{ messages: Message[]; next_cursor?: string }>(
    `/messaging/conversations/${conversationId}/messages`,
    cursor ? { cursor } : undefined,
  );
  return {
    messages: (res.messages ?? []).map(adaptMessage),
    next_cursor: res.next_cursor,
  };
};

export const sendTextMessage = async (conversationId: string, body: SendTextMessageReq) => {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/text`,
    body,
  );
  return adaptMessage(res);
};

const uploadToPresignedUrl = async (uploadUrl: string, file: File, contentType: string) => {
  const resp = await fetch(uploadUrl, {
    method: "PUT",
    body: file,
    headers: {
      "Content-Type": contentType,
    },
  });
  if (!resp.ok) {
    throw new Error("Failed to upload image");
  }
};

export const sendImageMessage = async (conversationId: string, formData: FormData) => {
  const file = formData.get("file");
  if (!(file instanceof File)) {
    throw new Error("sendImageMessage requires FormData with a file field");
  }

  const contentType = file.type || "image/jpeg";
  const presign = await api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
    `/messaging/conversations/${conversationId}/messages/image/presign`,
    {
      content_type: contentType,
      filename: file.name || "image.jpg",
    },
  );

  await uploadToPresignedUrl(presign.upload_url, file, presign.content_type || contentType);

  const res = await api.post<Message>(`/messaging/conversations/${conversationId}/messages/image`, {
    bucket: presign.bucket,
    key: presign.key,
    content_type: presign.content_type || contentType,
  });
  return adaptMessage(res);
};

export const editMessage = async (conversationId: string, messageId: string, body: { text: string }) => {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/edit`,
    body,
  );
  return adaptMessage(res);
};

export const reactToMessage = (conversationId: string, messageId: string, emoji: string) =>
  api.post(`/messaging/conversations/${conversationId}/messages/${messageId}/react`, { emoji });

export const deleteMessage = (conversationId: string, messageId: string) =>
  api.del(`/messaging/conversations/${conversationId}/messages/${messageId}`);

export const markRead = (conversationId: string, lastReadAt: number) =>
  api.post(`/messaging/conversations/${conversationId}/read`, { last_read_at: lastReadAt });

export const muteConversation = (conversationId: string, mutedUntil: number) =>
  api.post(`/messaging/conversations/${conversationId}/mute`, { muted_until: mutedUntil });

export const updateConversation = async (conversationId: string, body: { title?: string }) => {
  const res = await api.patch<Conversation>(`/messaging/conversations/${conversationId}`, body);
  return adaptConversation(res);
};

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

// ─── File Messages ─────────────────────────────────────────────

export const sendFileMessage = async (
  conversationId: string,
  body: { path: string; kind?: string; duration_seconds?: number },
) => {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/file`,
    body,
  );
  return adaptMessage(res);
};

// ─── Forward ───────────────────────────────────────────────────

export const forwardMessage = async (
  targetConversationId: string,
  body: ForwardMessageReq,
) => {
  const res = await api.post<Message>(
    `/messaging/conversations/${targetConversationId}/messages/forward`,
    body,
  );
  return adaptMessage(res);
};

// ─── Views / Read Receipts ─────────────────────────────────────

export const markViewed = (conversationId: string, messageId: string) =>
  api.post<{ ok: boolean; conversation_id: string; message_id: string; viewer_id: string; viewed_at: number }>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/view`,
    {},
  );

export const getViewers = (conversationId: string, messageId: string) =>
  api.get<MessageViewer[]>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/views`,
  );

// ─── Participants ──────────────────────────────────────────────

export const addParticipants = (conversationId: string, body: AddParticipantsReq) =>
  api.post<{ ok: boolean; added_count: number }>(
    `/messaging/conversations/${conversationId}/participants`,
    body,
  );

export const updateParticipantRole = (
  conversationId: string,
  participantId: string,
  body: UpdateRoleReq,
) =>
  api.patch<{ ok: boolean; role: string }>(
    `/messaging/conversations/${conversationId}/participants/${participantId}`,
    body,
  );
