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
  SendTipReq,
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

/** Read natural width/height from an image File. Returns undefined for non-images (e.g. PDFs). */
const readImageDimensions = (file: File): Promise<{ width: number; height: number } | undefined> => {
  if (!file.type.startsWith("image/")) return Promise.resolve(undefined);
  return new Promise((resolve) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      resolve({ width: img.naturalWidth, height: img.naturalHeight });
      URL.revokeObjectURL(url);
    };
    img.onerror = () => {
      resolve(undefined);
      URL.revokeObjectURL(url);
    };
    img.src = url;
  });
};

export const sendImageMessage = async (
  conversationId: string,
  formData: FormData,
  options?: {
    consumption_policy?: "none" | "view_once";
    caption?: string;
    expires_in_seconds?: number;
    lock_price_cents?: number;
    lock_description?: string;
    tip_amount_cents?: number;
  },
) => {
  const file = formData.get("file");
  if (!(file instanceof File)) {
    throw new Error("sendImageMessage requires FormData with a file field");
  }

  const isPdf = file.type === "application/pdf";
  const contentType = file.type || "image/jpeg";

  // Read image dimensions before upload (non-blocking, resolves quickly from local file)
  const dims = await readImageDimensions(file);

  const presign = await api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
    `/messaging/conversations/${conversationId}/images/presign`,
    {
      content_type: contentType,
      filename: file.name || (isPdf ? "document.pdf" : "image.jpg"),
    },
  );

  await uploadToPresignedUrl(presign.upload_url, file, presign.content_type || contentType);

  const payload: SendImageMessageReq = {
    bucket: presign.bucket,
    key: presign.key,
    content_type: presign.content_type || contentType,
    filename: file.name,
    filesize: file.size,
    // file.lastModified is ms since epoch; convert to Unix seconds
    file_created_at: file.lastModified > 0 ? Math.floor(file.lastModified / 1000) : undefined,
    kind: isPdf ? "file" : "image",
    width: dims?.width,
    height: dims?.height,
  };
  if (options?.consumption_policy) payload.consumption_policy = options.consumption_policy;
  if (options?.caption) payload.caption = options.caption;
  if (options?.expires_in_seconds) payload.expires_in_seconds = options.expires_in_seconds;
  if (options?.lock_price_cents) payload.lock_price_cents = options.lock_price_cents;
  if (options?.lock_description) payload.lock_description = options.lock_description;
  if (options?.tip_amount_cents) payload.tip_amount_cents = options.tip_amount_cents;

  const res = await api.post<Message>(`/messaging/conversations/${conversationId}/messages/image`, payload);
  return adaptMessage(res);
};

export const editMessage = async (conversationId: string, messageId: string, body: { text: string }) => {
  const res = await api.patch<Message>(
    `/messaging/conversations/${conversationId}/messages/${messageId}`,
    body,
  );
  return adaptMessage(res);
};

export const reactToMessage = (conversationId: string, messageId: string, emoji: string, action: "add" | "remove" = "add") =>
  api.post(`/messaging/conversations/${conversationId}/messages/${messageId}/reactions`, { emoji, action });

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


export const unlockMessage = (conversationId: string, messageId: string) =>
  api.post<{ ok: boolean }>(`/messaging/conversations/${conversationId}/messages/${messageId}/unlock`, {});

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

// ─── Scheduled Messages ────────────────────────────────────────

export const getScheduledMessages = async (conversationId: string) => {
  const res = await api.get<Message[]>(
    `/messaging/conversations/${conversationId}/messages/scheduled`,
  );
  return Array.isArray(res) ? res.map(adaptMessage) : [];
};

export const cancelScheduledMessage = (conversationId: string, messageId: string) =>
  api.del(`/messaging/conversations/${conversationId}/messages/${messageId}/schedule`);

// ─── Tips ──────────────────────────────────────────────────────

export const sendMessageTip = (conversationId: string, messageId: string, body: SendTipReq) =>
  api.post<{ ok: boolean; tip_payment_id: string; amount_cents: number; currency: string }>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/tip`,
    body,
  );
