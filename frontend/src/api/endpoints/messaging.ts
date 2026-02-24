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
  SendImageMessageReq,
  SendFileMessageReq,
  AddParticipantsReq,
  UpdateRoleReq,
  MessagingConfig,
  ConversationGalleryResp,
  ConversationGalleryQuery,
  ConsumeAttachmentReq,
  ConsumeAttachmentResp,
  CreateAttachmentGrantResp,
} from "@/api/types";
import { adaptConversation, adaptMessage } from "./messagingAdapter";
import { isMessagingEncryptionEnabled } from "@/lib/featureFlags";

export const getConversations = async (cursor?: string) => {
  const res = await api.get<{ conversations: Conversation[]; next_cursor?: string } | Conversation[]>(
    "/messaging/conversations",
    cursor ? { cursor } : undefined,
  );
  // Backend returns a plain array; handle both array and object shapes
  const rawConversations = Array.isArray(res) ? res : (res.conversations ?? []);
  const next_cursor = Array.isArray(res) ? undefined : res.next_cursor;
  return {
    conversations: rawConversations.map(adaptConversation),
    next_cursor,
  };
};

export const getConversation = async (id: string) => {
  const res = await api.get<Conversation>(`/messaging/conversations/${id}`);
  return adaptConversation(res);
};

export const startConversation = async (body: StartConversationReq) => {
  const res = await api.post<Conversation>("/messaging/conversations", body);
  return adaptConversation(res);
};

export const startGroupConversation = async (body: StartGroupConversationReq) => {
  const res = await api.post<Conversation>("/messaging/conversations/group", body);
  return adaptConversation(res);
};

export const getMessages = async (conversationId: string, cursor?: string) => {
  const res = await api.get<{ messages: Message[]; next_cursor?: string } | Message[]>(
    `/messaging/conversations/${conversationId}/messages`,
    cursor ? { before: cursor } : undefined,
  );
  // Backend returns a plain array; handle both array and object shapes
  const rawMessages = Array.isArray(res) ? res : (res.messages ?? []);
  const next_cursor = Array.isArray(res) ? undefined : res.next_cursor;
  return {
    messages: rawMessages.map(adaptMessage),
    next_cursor,
  };
};


export const getConversationGallery = async (
  conversationId: string,
  query: ConversationGalleryQuery,
) => {
  const { type, cursor, limit = 50 } = query;
  return api.get<ConversationGalleryResp>(
    `/messaging/conversations/${conversationId}/gallery`,
    { type, limit: String(limit), ...(cursor ? { cursor } : {}) },
  );
};

export const sendTextMessage = async (conversationId: string, body: SendTextMessageReq) => {
  if (body.encryption && !isMessagingEncryptionEnabled()) {
    throw new Error("Encrypted messaging is disabled");
  }
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages`,
    body,
  );
  return adaptMessage(res);
};

export const getMessagingConfig = () =>
  api.get<MessagingConfig>("/messaging/config");

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

export const sendImageMessage = async (
  conversationId: string,
  formData: FormData,
  options?: { consumption_policy?: "none" | "view_once" },
) => {
  const file = formData.get("file");
  if (!(file instanceof File)) {
    throw new Error("sendImageMessage requires FormData with a file field");
  }

  const contentType = file.type || "image/jpeg";
  const presign = await api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
    `/messaging/conversations/${conversationId}/images/presign`,
    {
      content_type: contentType,
      filename: file.name || "image.jpg",
    },
  );

  await uploadToPresignedUrl(presign.upload_url, file, presign.content_type || contentType);

  const payload: SendImageMessageReq = {
    bucket: presign.bucket,
    key: presign.key,
    content_type: presign.content_type || contentType,
  };
  if (options?.consumption_policy) payload.consumption_policy = options.consumption_policy;

  const res = await api.post<Message>(`/messaging/conversations/${conversationId}/messages/image`, payload);
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
  body: SendFileMessageReq,
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


export const createOnceMediaAttachmentGrant = (conversationId: string, messageId: string) =>
  api.post<CreateAttachmentGrantResp>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/attachment/grant`,
    {},
  );

export const consumeOnceMediaAttachment = (
  conversationId: string,
  messageId: string,
  grantToken: string,
  body: ConsumeAttachmentReq,
) =>
  api.post<ConsumeAttachmentResp>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/attachment/consume`,
    body,
    { grant_token: grantToken },
  );

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


export const buildAttachmentDownloadUrl = (
  conversationId: string,
  messageId: string,
  grantToken?: string,
) => {
  const params = new URLSearchParams();
  if (grantToken) {
    params.set("grant_token", grantToken);
  }
  const qs = params.toString();
  return `/messaging/conversations/${conversationId}/messages/${messageId}/attachment${qs ? `?${qs}` : ""}`;
};
