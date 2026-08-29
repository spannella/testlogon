import { api, ApiError } from "@/api/client";
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
  CreateLotteryMessageReq,
  LotteryMessage,
  LotteryUnlockResp,
  ConversationGalleryResp,
  ConversationGalleryQuery,
  ConsumeAttachmentReq,
  ConsumeAttachmentResp,
  CreateAttachmentGrantResp,
  SendTipReq,
  SendGalleryMessageReq,
  SendFileShareReq,
  SendCalendarShareReq,
  SendCalendarEventReq,
  SendMeetingPollReq,
  MeetingPollState,
  SendFindDateTimeReq,
  FindDateTimeFull,
  HelpdeskClaimOut,
  HelpdeskTransferOut,
  RoutingEventOut,
  MessageControlActionResp,
  HiddenMessagesResp,
  ConversationPinsResp,
  ReportMessageReq,
  ReportMessageResp,
  ThreadMessagesPage,
  ConversationDraft,
  ConversationDraftListResp,
  CreateConversationDraftReq,
  UpdateConversationDraftReq,
  ReactionDetails,
  GalleryImageItem,
} from "@/api/types";
import { adaptConversation, adaptMessage } from "./messagingAdapter";
import type { MarketCardPayload, PositionCardPayload } from "@/lib/tradingCards";
import type { CryptoTransferPayload } from "@/lib/cryptoTransfer";
import type { ProductCardPayload, OrderCardPayload } from "@/lib/ecomCards";
import { isMessagingDmLotteryEnabled, isMessagingEncryptionEnabled } from "@/lib/featureFlags";
import { encryptBytes } from "@/lib/messageEncryption";

export const getConversations = async (cursor?: string) => {
  const networkFn = async () => {
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

  // Wrap with offline cache (PWA-003)
  const { useAuthStore } = await import("@/stores/authStore");
  const userId = useAuthStore.getState().userId ?? "";
  const { withOfflineCache } = await import("@/lib/withOfflineCache");
  return withOfflineCache(
    networkFn,
    { endpoint: "conversations", cacheKey: `/messaging/conversations${cursor ? `?cursor=${cursor}` : ""}` },
    userId,
  )();
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

export const findOrCreateDm = async (userId: string): Promise<Conversation> => {
  const res = await api.post<Conversation>("/messaging/conversations/dm/find-or-create", {
    user_id: userId,
  });
  return adaptConversation(res);
};

export const getMessages = async (conversationId: string, cursor?: string) => {
  const networkFn = async () => {
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

  // Wrap with offline cache (PWA-003)
  const { useAuthStore } = await import("@/stores/authStore");
  const userId = useAuthStore.getState().userId ?? "";
  const { withOfflineCache } = await import("@/lib/withOfflineCache");
  return withOfflineCache(
    networkFn,
    {
      endpoint: "messages",
      cacheKey: `/messaging/conversations/${conversationId}/messages${cursor ? `?cursor=${cursor}` : ""}`,
    },
    userId,
  )();
};

export const getThreadMessages = async (threadId: string, cursor?: string, limit = 50): Promise<ThreadMessagesPage> => {
  const res = await api.get<{ items: Message[]; next_cursor?: string | null; unread_count?: number }>(
    `/messaging/threads/${threadId}/messages`,
    { ...(cursor ? { cursor } : {}), limit: String(limit) },
  );
  return {
    items: (res.items ?? []).map(adaptMessage),
    next_cursor: res.next_cursor ?? null,
    unread_count: typeof res.unread_count === "number" ? res.unread_count : undefined,
  };
};

const adaptConversationDraft = (draft: ConversationDraft): ConversationDraft => ({
  ...draft,
  version: Number(draft.version ?? 1),
  created_at: Number(draft.created_at ?? 0),
  updated_at: Number(draft.updated_at ?? 0),
  client_updated_at: draft.client_updated_at != null ? Number(draft.client_updated_at) : undefined,
});

export const listConversationDrafts = async (conversationId: string, cursor?: string, limit = 20): Promise<ConversationDraftListResp> => {
  const res = await api.get<ConversationDraftListResp>(
    `/messaging/conversations/${conversationId}/drafts`,
    {
      limit: String(limit),
      ...(cursor ? { cursor } : {}),
    },
  );

  return {
    items: (res.items ?? []).map(adaptConversationDraft),
    next_cursor: res.next_cursor,
  };
};

export const createConversationDraft = async (
  conversationId: string,
  body: CreateConversationDraftReq,
  idempotencyKey: string,
): Promise<ConversationDraft> => {
  const res = await api<{ draft: ConversationDraft }>(
    `/messaging/conversations/${conversationId}/drafts`,
    {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Idempotency-Key": idempotencyKey },
    },
  );
  return adaptConversationDraft(res.draft);
};

export const getConversationDraft = async (conversationId: string, draftId: string): Promise<ConversationDraft> => {
  const res = await api.get<{ draft: ConversationDraft }>(
    `/messaging/conversations/${conversationId}/drafts/${draftId}`,
  );
  return adaptConversationDraft(res.draft);
};

export const updateConversationDraft = async (
  conversationId: string,
  draftId: string,
  body: UpdateConversationDraftReq,
): Promise<ConversationDraft> => {
  const res = await api.patch<{ draft: ConversationDraft }>(
    `/messaging/conversations/${conversationId}/drafts/${draftId}`,
    body,
  );
  return adaptConversationDraft(res.draft);
};

export const deleteConversationDraft = async (conversationId: string, draftId: string): Promise<void> => {
  await api.del(`/messaging/conversations/${conversationId}/drafts/${draftId}`);
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

const lotteryConversationToken = (conversationId: string): string => {
  const sanitized = conversationId.replace(/[^A-Za-z0-9._:-]/g, "");
  const prefix = (sanitized.slice(0, 16) || "conv");
  let hash = 2166136261;
  for (let i = 0; i < conversationId.length; i += 1) {
    hash ^= conversationId.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return `${prefix}_${hash.toString(16).padStart(8, "0")}`;
};

export const createLotteryMessage = async (body: CreateLotteryMessageReq) => {
  if (!isMessagingDmLotteryEnabled()) {
    throw new Error("Lottery messages are disabled");
  }
  const conversationToken = lotteryConversationToken(body.conversation_id);
  const randomPart = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const idempotencyKey = `lottery_create:${conversationToken}:${randomPart}`;
  return api<LotteryMessage>("/messaging/messages/lottery", {
    method: "POST",
    headers: {
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify(body),
  });
};

export const unlockLotteryMessage = async (messageId: string) => {
  if (!isMessagingDmLotteryEnabled()) {
    throw new Error("Lottery messages are disabled");
  }
  return api.post<LotteryUnlockResp>(`/messaging/messages/${messageId}/lottery/unlock`, {});
};

export const getLotteryMessage = async (messageId: string) => {
  if (!isMessagingDmLotteryEnabled()) {
    throw new Error("Lottery messages are disabled");
  }
  return api.get<LotteryMessage>(`/messaging/messages/${messageId}/lottery`);
};

export type DirectCallMode = "audio" | "video";

export interface CallInviteResp {
  call_id: string;
  conversation_id: string;
  state: string;
  mode: DirectCallMode;
  caller_user_id?: string;
  callee_user_id?: string;
}

const _genCallId = (): string => {
  const cryptoObj = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  const uuid = cryptoObj?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return `call_${uuid.replace(/-/g, "")}`;
};

export const createCallInvite = (
  conversationId: string,
  body: {
    callee_user_id: string;
    mode: DirectCallMode;
    idempotency_key?: string;
    paid?: boolean;
  },
) =>
  // Backend route is mounted under the /messaging router prefix and expects a
  // client-supplied call_id + `initial_mode` (not `mode`).
  api.post<CallInviteResp>("/messaging/messages/calls/invite", {
    call_id: _genCallId(),
    conversation_id: conversationId,
    callee_user_id: body.callee_user_id,
    initial_mode: body.mode,
    ...(body.idempotency_key ? { idempotency_key: body.idempotency_key } : {}),
    ...(body.paid !== undefined ? { paid: body.paid } : {}),
  });

export const acceptCallInvite = (callId: string, idempotency_key?: string) =>
  api.post<CallInviteResp>(`/messaging/messages/calls/${callId}/accept`, {
    ...(idempotency_key ? { idempotency_key } : {}),
  });

export const declineCallInvite = (
  callId: string,
  body?: { reason?: "declined" | "busy"; idempotency_key?: string },
) =>
  api.post<CallInviteResp>(`/messaging/messages/calls/${callId}/decline`, {
    ...(body?.reason ? { reason: body.reason } : {}),
    ...(body?.idempotency_key ? { idempotency_key: body.idempotency_key } : {}),
  });

export const endCall = (callId: string, body?: { reason?: string; idempotency_key?: string }) =>
  api.post<CallInviteResp>(`/messaging/messages/calls/${callId}/end`, {
    ...(body?.reason ? { reason: body.reason } : {}),
    ...(body?.idempotency_key ? { idempotency_key: body.idempotency_key } : {}),
  });

export const timeoutCall = (callId: string, body?: { reason?: string; idempotency_key?: string }) =>
  api.post<CallInviteResp>(`/messaging/messages/calls/${callId}/timeout`, {
    ...(body?.reason ? { reason: body.reason } : {}),
    ...(body?.idempotency_key ? { idempotency_key: body.idempotency_key } : {}),
  });

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
  if (file.type.startsWith("video/")) {
    return new Promise((resolve) => {
      const video = document.createElement("video");
      const url = URL.createObjectURL(file);
      video.onloadedmetadata = () => {
        resolve({ width: video.videoWidth, height: video.videoHeight });
        URL.revokeObjectURL(url);
      };
      video.onerror = () => { resolve(undefined); URL.revokeObjectURL(url); };
      video.src = url;
    });
  }
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
    tip_payment_method_id?: string;
    send_at?: number;
    encryption_password?: string;
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

  // Encrypt before upload if password provided
  let encryptionEnvelope: SendImageMessageReq["encryption"] | undefined;
  if (options?.encryption_password) {
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const { envelope, encryptedBytes } = await encryptBytes(fileBytes, options.encryption_password);
    encryptionEnvelope = { ...envelope };
    const encryptedBlob = new Blob([encryptedBytes], { type: "application/octet-stream" });
    const resp = await fetch(presign.upload_url, {
      method: "PUT",
      body: encryptedBlob,
      headers: { "Content-Type": "application/octet-stream" },
    });
    if (!resp.ok) throw new Error("Failed to upload encrypted media");
  } else {
    await uploadToPresignedUrl(presign.upload_url, file, presign.content_type || contentType);
  }

  const payload: SendImageMessageReq = {
    bucket: presign.bucket,
    key: presign.key,
    content_type: presign.content_type || contentType,
    filename: file.name,
    filesize: file.size,
    // file.lastModified is ms since epoch; convert to Unix seconds
    file_created_at: file.lastModified > 0 ? Math.floor(file.lastModified / 1000) : undefined,
    kind: isPdf ? "file" : file.type.startsWith("video/") ? "video" : "image",
    width: dims?.width,
    height: dims?.height,
  };
  if (options?.consumption_policy) payload.consumption_policy = options.consumption_policy;
  if (options?.caption) payload.caption = options.caption;
  if (options?.expires_in_seconds) payload.expires_in_seconds = options.expires_in_seconds;
  if (options?.lock_price_cents) payload.lock_price_cents = options.lock_price_cents;
  if (options?.lock_description) payload.lock_description = options.lock_description;
  if (options?.tip_amount_cents) payload.tip_amount_cents = options.tip_amount_cents;
  if (options?.tip_payment_method_id) payload.tip_payment_method_id = options.tip_payment_method_id;
  if (options?.send_at) payload.send_at = options.send_at;
  if (encryptionEnvelope) payload.encryption = encryptionEnvelope;

  const res = await api.post<Message>(`/messaging/conversations/${conversationId}/messages/image`, payload);
  return adaptMessage(res);
};

/**
 * Upload an image/video into a conversation's media bucket WITHOUT creating a
 * message, and return the S3 key. Used for lottery outcome media: the key is in
 * the `{conversation_id}/{sender}/…` form the lottery endpoint accepts as a
 * `media_asset_id`. (Same presign + PUT steps as sendImageMessage, minus the
 * message-create step.)
 */
export const uploadConversationMedia = async (
  conversationId: string,
  file: File,
): Promise<{ key: string; bucket: string; content_type: string }> => {
  const contentType = file.type || "application/octet-stream";
  const presign = await api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
    `/messaging/conversations/${conversationId}/images/presign`,
    { content_type: contentType, filename: file.name || "upload" },
  );
  await uploadToPresignedUrl(presign.upload_url, file, presign.content_type || contentType);
  return { key: presign.key, bucket: presign.bucket, content_type: presign.content_type || contentType };
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

// MSG-011: fetch who reacted with what (avatars + display names per emoji).
export const getReactionDetails = (conversationId: string, messageId: string) =>
  api.get<ReactionDetails>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/reactions/details`,
  );

export const deleteMessage = (conversationId: string, messageId: string) =>
  api.del(`/messaging/conversations/${conversationId}/messages/${messageId}`);

export const hideMessage = (conversationId: string, messageId: string) =>
  api.post<MessageControlActionResp>(`/messaging/conversations/${conversationId}/messages/${messageId}/hide`);

export const unhideMessage = (conversationId: string, messageId: string) =>
  api.del<MessageControlActionResp>(`/messaging/conversations/${conversationId}/messages/${messageId}/hide`);

export const getHiddenMessages = (conversationId: string, cursor?: string, limit = 50) =>
  api.get<HiddenMessagesResp>(
    `/messaging/conversations/${conversationId}/hidden-messages`,
    { ...(cursor ? { cursor } : {}), limit: String(limit) },
  );

export const pinMessage = (conversationId: string, messageId: string) =>
  api.post<MessageControlActionResp>(`/messaging/conversations/${conversationId}/messages/${messageId}/pin`);

export const unpinMessage = (conversationId: string, messageId: string) =>
  api.del<MessageControlActionResp>(`/messaging/conversations/${conversationId}/messages/${messageId}/pin`);

export const getPinnedMessages = (conversationId: string, cursor?: string, limit = 50) =>
  api.get<ConversationPinsResp>(
    `/messaging/conversations/${conversationId}/pins`,
    { ...(cursor ? { cursor } : {}), limit: String(limit) },
  );

export const reportMessage = (conversationId: string, messageId: string, body: ReportMessageReq) =>
  api.post<ReportMessageResp>(`/messaging/conversations/${conversationId}/messages/${messageId}/report`, body);

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


export const unlockMessage = (conversationId: string, messageId: string, paymentMethodId?: string) =>
  api.post<{ ok: boolean }>(`/messaging/conversations/${conversationId}/messages/${messageId}/unlock`, {
    payment_method_id: paymentMethodId ?? null,
  });

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

// B-SCHED2/#21/#22 + B-SCHED3/#7: edit a still-pending scheduled message — change
// the text, reschedule (send_at OR wall-clock send_at_local+tz), and/or add/replace
// media (image / file_path / video_id / gallery). At least one field required.
export interface RescheduleMessageReq {
  text?: string;
  send_at?: number;
  send_at_local?: string;
  send_at_tz?: string;
  image?: GalleryImageItem;
  file_path?: string;
  video_id?: string;
  free_images?: GalleryImageItem[];
  locked_images?: GalleryImageItem[];
}

export const editScheduledMessage = async (
  conversationId: string,
  messageId: string,
  body: RescheduleMessageReq,
) => {
  const res = await api.patch<Message>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/schedule`,
    body,
  );
  return adaptMessage(res);
};

// ─── Tips ──────────────────────────────────────────────────────

export const sendMessageTip = (conversationId: string, messageId: string, body: SendTipReq) =>
  api.post<{ ok: boolean; tip_payment_id: string; amount_cents: number; currency: string }>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/tip`,
    body,
  );

// ─── File Share Messages ───────────────────────────────────────

export async function sendFileShareMessage(
  conversationId: string,
  params: SendFileShareReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/file-share`,
    params,
  );
  return adaptMessage(res);
}

// ─── Video Share Messages ──────────────────────────────────────

export interface SendVideoShareReq {
  video_id: string;
  text?: string;
  send_at?: number;
}

export async function sendVideoShareMessage(
  conversationId: string,
  body: SendVideoShareReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/video-share`,
    body,
  );
  return adaptMessage(res);
}

// ─── Gallery Messages ──────────────────────────────────────────

/**
 * Generate a blurred 32×32 pixel preview of an image file.
 * The tiny canvas image, when rendered at full size, appears heavily pixelated —
 * giving recipients a hint of the image content without revealing details.
 */
export async function generateBlurredPreview(file: File): Promise<Blob> {
  const drawToCanvas = (source: CanvasImageSource): Promise<Blob> =>
    new Promise((resolve, reject) => {
      const canvas = document.createElement("canvas");
      canvas.width = 32;
      canvas.height = 32;
      const ctx = canvas.getContext("2d");
      if (!ctx) { reject(new Error("No 2d context")); return; }
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(source, 0, 0, 32, 32);
      canvas.toBlob(
        (blob) => { if (blob) resolve(blob); else reject(new Error("Canvas toBlob failed")); },
        "image/jpeg",
        0.8,
      );
    });

  if (file.type.startsWith("video/")) {
    return new Promise((resolve, reject) => {
      const video = document.createElement("video");
      const url = URL.createObjectURL(file);
      video.muted = true;
      video.playsInline = true;
      video.onloadedmetadata = () => { video.currentTime = 0; };
      video.onseeked = () => {
        drawToCanvas(video)
          .then(resolve)
          .catch(reject)
          .finally(() => URL.revokeObjectURL(url));
      };
      video.onerror = () => { URL.revokeObjectURL(url); reject(new Error("Video load failed")); };
      video.src = url;
    });
  }

  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      drawToCanvas(img)
        .then(resolve)
        .catch(reject)
        .finally(() => URL.revokeObjectURL(img.src));
    };
    img.onerror = () => { URL.revokeObjectURL(img.src); reject(new Error("Image load failed")); };
    img.src = URL.createObjectURL(file);
  });
}

// ─── Calendar Share Messages ───────────────────────────────────

export async function sendCalendarShareMessage(
  conversationId: string,
  params: SendCalendarShareReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/calendar-share`,
    params,
  );
  return adaptMessage(res);
}

export async function sendCalendarEventMessage(
  conversationId: string,
  params: SendCalendarEventReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/calendar-event`,
    params,
  );
  return adaptMessage(res);
}

export async function sendMeetingPollMessage(
  conversationId: string,
  params: SendMeetingPollReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/meeting-poll`,
    params,
  );
  return adaptMessage(res);
}

// ---- Find-a-DateTime (MSG-009) ----

export async function sendFindDateTimeMessage(
  conversationId: string,
  params: SendFindDateTimeReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/find-datetime`,
    params,
  );
  return adaptMessage(res);
}

export async function getFindDateTime(pollId: string): Promise<FindDateTimeFull> {
  return api.get<FindDateTimeFull>(`/messaging/messages/find-datetime/${pollId}`);
}

export async function submitFindDateTimeAvailability(
  pollId: string,
  slots: string[],
): Promise<{
  ok: boolean;
  poll_id: string;
  user_sub: string;
  slots_count: number;
  participant_count: number;
  submitted_at: number;
}> {
  return api.post(`/messaging/messages/find-datetime/${pollId}/availability`, { slots });
}

export async function closeFindDateTime(
  pollId: string,
): Promise<{ ok: boolean; poll_id: string; status: string; result: FindDateTimeFull["result"] }> {
  return api.post(`/messaging/messages/find-datetime/${pollId}/close`, {});
}

export async function sendCountdownMessage(
  conversationId: string,
  params: {
    title: string;
    target_datetime: number;
    associated_event_type?: "broadcast" | "call" | "calendar" | "custom";
    associated_event_id?: string;
    reply_to_message_id?: string;
  },
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/countdown`,
    params,
  );
  return adaptMessage(res);
}

// ---- Trading-in-chat cards (EPIC A: FE-101 market, FE-102 position) ----
//
// Preferred path is a dedicated /messaging/cards/* endpoint (BE-101/BE-102).
// If the backend has not shipped it yet (404), we degrade to a normal message
// carrying a new `kind` + structured payload -- the works-now path that renders
// identically because MessageBubble dispatches purely on `kind` + payload.

async function sendCardMessage(
  conversationId: string,
  cardEndpoint: string,
  kind: "market_card" | "position_card" | "crypto_transfer" | "product_card" | "order_card",
  payload: Record<string, unknown>,
  replyToMessageId?: string,
): Promise<Message> {
  try {
    const res = await api.post<Message>(
      `/messaging/conversations/${conversationId}/cards/${cardEndpoint}`,
      { ...payload, reply_to_message_id: replyToMessageId },
    );
    return adaptMessage(res);
  } catch (err) {
    // Degrade-on-404 (endpoint not deployed) to the normal kind+payload send.
    if (err instanceof ApiError && err.status === 404) {
      const res = await api.post<Message>(
        `/messaging/conversations/${conversationId}/messages`,
        { kind, ...payload, reply_to_message_id: replyToMessageId },
      );
      return adaptMessage(res);
    }
    throw err;
  }
}

export async function sendMarketCardMessage(
  conversationId: string,
  payload: MarketCardPayload,
  replyToMessageId?: string,
): Promise<Message> {
  return sendCardMessage(
    conversationId,
    "market",
    "market_card",
    { ...payload },
    replyToMessageId,
  );
}

export async function sendPositionCardMessage(
  conversationId: string,
  payload: PositionCardPayload,
  replyToMessageId?: string,
): Promise<Message> {
  return sendCardMessage(
    conversationId,
    "position",
    "position_card",
    { ...payload },
    replyToMessageId,
  );
}

// ---- Send crypto in chat (EPIC B: FE-110 composer, FE-111 transfer card) ----
//
// Preferred path is a dedicated /messaging/cards/crypto endpoint (BE-111). If the
// backend has not shipped it yet (404), we degrade to a normal message carrying
// kind "crypto_transfer" + the structured payload -- MessageBubble dispatches on
// `kind` + payload so it renders identically either way.
export async function sendCryptoTransferMessage(
  conversationId: string,
  payload: CryptoTransferPayload,
  replyToMessageId?: string,
): Promise<Message> {
  return sendCardMessage(
    conversationId,
    "crypto",
    "crypto_transfer",
    { ...payload },
    replyToMessageId,
  );
}

// ---- Ecommerce-in-chat cards (EPIC F: FE-150 product, FE-151 order-share) ----
//
// Preferred path is a dedicated /messaging/cards/{product,order} endpoint. If the
// backend has not shipped it yet (404), we degrade to a normal message carrying
// kind "product_card"/"order_card" + the structured payload -- MessageBubble
// dispatches on `kind` + payload so it renders identically either way.
export async function sendProductCardMessage(
  conversationId: string,
  payload: ProductCardPayload,
  replyToMessageId?: string,
): Promise<Message> {
  // Map payload.image onto the message field product_image (the plain image
  // field on Message is the MessageImage attachment shape) so the
  // degrade-on-404 message renders identically.
  const { image, ...rest } = payload;
  return sendCardMessage(
    conversationId,
    "product",
    "product_card",
    { ...rest, product_image: image },
    replyToMessageId,
  );
}

export async function sendOrderCardMessage(
  conversationId: string,
  payload: OrderCardPayload,
  replyToMessageId?: string,
): Promise<Message> {
  return sendCardMessage(
    conversationId,
    "order",
    "order_card",
    { ...payload },
    replyToMessageId,
  );
}

export async function sendGifMessage(
  conversationId: string,
  params: {
    gif_url: string;
    gif_alt_text?: string;
    gif_width?: number;
    gif_height?: number;
    reply_to_message_id?: string;
  },
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/gif`,
    params,
  );
  return adaptMessage(res);
}

export async function sendStickerMessage(
  conversationId: string,
  params: {
    sticker_id: string;
    sticker_collection_id: string;
    reply_to_message_id?: string;
  },
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/sticker`,
    params,
  );
  return adaptMessage(res);
}

export async function getMeetingPoll(
  conversationId: string,
  pollId: string,
): Promise<MeetingPollState> {
  return api.get<MeetingPollState>(
    `/messaging/conversations/${conversationId}/polls/${pollId}`,
  );
}

export async function voteMeetingPoll(
  conversationId: string,
  pollId: string,
  votes: Record<string, "yes" | "no" | "maybe">,
): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(
    `/messaging/conversations/${conversationId}/polls/${pollId}/vote`,
    { votes },
  );
}

export async function confirmMeetingPoll(
  conversationId: string,
  pollId: string,
  slotId: string,
  calendarId?: string,
): Promise<{ ok: boolean; event_id?: string }> {
  return api.post<{ ok: boolean; event_id?: string }>(
    `/messaging/conversations/${conversationId}/polls/${pollId}/confirm`,
    { slot_id: slotId, calendar_id: calendarId },
  );
}

export async function sendGalleryMessage(
  conversationId: string,
  params: {
    freeFiles: File[];
    lockedFiles: File[];
    text?: string;
    lock_price_cents?: number;
    lock_description?: string;
    expires_in_seconds?: number;
    send_at?: number;
    tip_amount_cents?: number;
    tip_payment_method_id?: string;
  },
): Promise<Message> {
  const fallbackFilename = (file: File) =>
    file.name || (file.type.startsWith("video/") ? "video.mp4" : "image.jpg");

  // Presign + upload all free items (images or videos) in parallel
  const freeUploads = await Promise.all(
    params.freeFiles.map(async (file) => {
      const dims = await readImageDimensions(file);
      const presign = await api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
        `/messaging/conversations/${conversationId}/images/presign`,
        { content_type: file.type || "image/jpeg", filename: fallbackFilename(file) },
      );
      await uploadToPresignedUrl(presign.upload_url, file, presign.content_type || file.type);
      return {
        bucket: presign.bucket,
        key: presign.key,
        content_type: presign.content_type || file.type,
        width: dims?.width,
        height: dims?.height,
        filename: file.name,
        filesize: file.size,
      };
    }),
  );

  // For each locked item: presign main + presign preview + generate preview blob + upload both
  const lockedUploads = await Promise.all(
    params.lockedFiles.map(async (file) => {
      const dims = await readImageDimensions(file);

      // Presign main item and preview in parallel
      const [mainPresign, previewPresign] = await Promise.all([
        api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
          `/messaging/conversations/${conversationId}/images/presign`,
          { content_type: file.type || "image/jpeg", filename: fallbackFilename(file) },
        ),
        api.post<{ upload_url: string; bucket: string; key: string; content_type: string }>(
          `/messaging/conversations/${conversationId}/images/presign`,
          { content_type: "image/jpeg", filename: `preview_${fallbackFilename(file)}` },
        ),
      ]);

      // Generate blurred preview blob and upload both in parallel
      const previewBlob = await generateBlurredPreview(file);
      await Promise.all([
        uploadToPresignedUrl(mainPresign.upload_url, file, mainPresign.content_type || file.type),
        fetch(previewPresign.upload_url, {
          method: "PUT",
          body: previewBlob,
          headers: { "Content-Type": "image/jpeg" },
        }).then((r) => { if (!r.ok) throw new Error("Failed to upload preview"); }),
      ]);

      return {
        bucket: mainPresign.bucket,
        key: mainPresign.key,
        content_type: mainPresign.content_type || file.type,
        width: dims?.width,
        height: dims?.height,
        filename: file.name,
        filesize: file.size,
        preview_bucket: previewPresign.bucket,
        preview_key: previewPresign.key,
      };
    }),
  );

  const body: SendGalleryMessageReq = {
    free_images: freeUploads,
    locked_images: lockedUploads,
    text: params.text,
    lock_price_cents: params.lock_price_cents,
    lock_description: params.lock_description,
    expires_in_seconds: params.expires_in_seconds,
    send_at: params.send_at,
    tip_amount_cents: params.tip_amount_cents,
    tip_payment_method_id: params.tip_payment_method_id,
  };

  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/messages/gallery`,
    body,
  );
  return adaptMessage(res);
}

// ─── Helpdesk API ─────────────────────────────────────────────────

export async function startHelpdeskConversation(groupId: string): Promise<Conversation> {
  const res = await api.post<Conversation>("/messaging/conversations", {
    routing_mode: "helpdesk_bridge",
    helpdesk_group_id: groupId,
    type: "dm",
  });
  return adaptConversation(res);
}

export async function claimHelpdeskConversation(conversationId: string): Promise<HelpdeskClaimOut> {
  return api.post<HelpdeskClaimOut>(`/messaging/helpdesk/conversations/${conversationId}/claim`, {});
}

export async function transferHelpdeskConversation(
  conversationId: string,
  targetAgentUserId: string,
): Promise<HelpdeskTransferOut> {
  return api.post<HelpdeskTransferOut>(`/messaging/helpdesk/conversations/${conversationId}/transfer`, {
    target_agent_user_id: targetAgentUserId,
  });
}

export interface HelpdeskGroupAgent {
  user_id: string;
  display_name: string;
  online: boolean;
  is_self: boolean;
}

/** HMH-007: list a helpdesk group's agents (membership-gated) for the transfer picker. */
export async function listHelpdeskGroupAgents(groupId: string): Promise<HelpdeskGroupAgent[]> {
  const res = await api.get<{ agents: HelpdeskGroupAgent[] }>(
    `/messaging/helpdesk/groups/${encodeURIComponent(groupId)}/agents`,
  );
  return res.agents ?? [];
}

export async function getHelpdeskQueue(groupId: string, state?: string): Promise<Conversation[]> {
  const params: Record<string, string> = { group_id: groupId };
  if (state) params.state = state;
  // silent403: non-agents get 403 which is expected — don't show an error toast
  const res = await api<Conversation[]>("/messaging/helpdesk/queue", {
    method: "GET",
    params,
    silent403: true,
  });
  return (Array.isArray(res) ? res : []).map(adaptConversation);
}

export async function getRoutingEvents(conversationId: string, limit = 50): Promise<RoutingEventOut[]> {
  const res = await api.get<RoutingEventOut[]>(
    `/messaging/conversations/${conversationId}/routing-events`,
    { limit: String(limit) },
  );
  return Array.isArray(res) ? res : [];
}

// ─── WebRTC Signaling ─────────────────────────────────────────────────

export interface SignalingPayload {
  type: "webrtc.offer" | "webrtc.answer" | "webrtc.ice_candidate";
  event_id: string;
  conversation_id: string;
  recipient_user_id: string;
  nonce: string;
  sent_at: number;
  payload: Record<string, unknown>;
}

export interface SignalingAck {
  event_id: string;
  call_id: string;
  conversation_id: string;
  event_type: string;
  delivered_to: string;
  status: "delivered" | "duplicate";
}

export async function sendSignalingEvent(
  callId: string,
  data: SignalingPayload,
): Promise<SignalingAck> {
  const resp = await api.post<SignalingAck>(`/messaging/messages/calls/${callId}/signal`, data);
  return resp;
}

// ─── TURN Credentials ────────────────────────────────────────────────

export interface TurnIceServer {
  urls: string[];
  username: string;
  credential: string;
}

export interface TurnCredentialsResp {
  ttl_seconds: number;
  expires_at: number;
  ice_servers: TurnIceServer[];
}

export async function fetchTurnCredentials(callId: string): Promise<TurnCredentialsResp> {
  return api.post<TurnCredentialsResp>(`/messaging/messages/calls/${callId}/turn-credentials`, {});
}

// ─── Call Recording ───────────────────────────────────────────────────

export interface RecordingMetadataOut {
  recording_id: string;
  call_id: string;
  conversation_id: string;
  status: string;
  duration_seconds: number | null;
  file_size_bytes: number | null;
  created_at: number;
  download_url: string | null;
  download_expires_at?: number | null;
}

export async function getConversationRecordings(
  conversationId: string,
): Promise<{ items: RecordingMetadataOut[] }> {
  return api.get<{ items: RecordingMetadataOut[] }>(`/messages/recordings`, {
    conversation_id: conversationId,
  });
}

export async function getRecordingDownloadUrl(recordingId: string): Promise<{ download_url: string; expires_at: number }> {
  return api.get<{ download_url: string; expires_at: number }>(
    `/messages/recordings/${recordingId}/download`,
  );
}

// ─── Voice Messages (MSG-002) ───────────────────────────────────────────────

export interface PresignVoiceReq {
  content_type: string;
  size_bytes: number;
  duration_seconds: number;
}

export interface CreateVoiceReq {
  message_id: string;
  s3_key: string;
  content_type: string;
  size_bytes: number;
  duration_seconds: number;
  waveform_data: number[];
  consumption_policy?: "none" | "listen_once";
  reply_to_message_id?: string | null;
  send_at?: number | null;
}

export async function presignVoiceMessage(
  conversationId: string,
  body: PresignVoiceReq,
): Promise<{ message_id: string; upload_url: string; s3_key: string }> {
  return api.post<{ message_id: string; upload_url: string; s3_key: string }>(
    `/messaging/conversations/${conversationId}/voice-message/presign`,
    body,
  );
}

export async function createVoiceMessage(
  conversationId: string,
  body: CreateVoiceReq,
): Promise<Message> {
  return api.post<Message>(
    `/messaging/conversations/${conversationId}/voice-message`,
    body,
  );
}

export async function sendVoiceMessage(
  conversationId: string,
  audioBlob: Blob,
  meta: {
    durationSeconds: number;
    waveform: number[];
    contentType: string;
    consumption_policy?: "none" | "listen_once";
    reply_to_message_id?: string | null;
    send_at?: number | null;
  },
): Promise<Message> {
  // 1. Get presigned URL
  const presign = await presignVoiceMessage(conversationId, {
    content_type: meta.contentType,
    size_bytes: audioBlob.size,
    duration_seconds: meta.durationSeconds,
  });

  // 2. Upload blob to S3
  const uploadResp = await fetch(presign.upload_url, {
    method: "PUT",
    body: audioBlob,
    headers: { "Content-Type": meta.contentType },
  });
  if (!uploadResp.ok) throw new Error("Failed to upload voice recording");

  // 3. Create message record
  return createVoiceMessage(conversationId, {
    message_id: presign.message_id,
    s3_key: presign.s3_key,
    content_type: meta.contentType,
    size_bytes: audioBlob.size,
    duration_seconds: meta.durationSeconds,
    waveform_data: meta.waveform,
    consumption_policy: meta.consumption_policy ?? "none",
    reply_to_message_id: meta.reply_to_message_id ?? null,
    send_at: meta.send_at ?? null,
  });
}


// ─── Voicemail API (CALL-014) ──────────────────────────────────────────────

export interface PresignVoicemailReq {
  call_id: string;
  content_type: string;
  size_bytes: number;
  mode: "audio" | "video";
}

export interface CreateVoicemailReq {
  message_id: string;
  call_id: string;
  s3_key: string;
  content_type: string;
  size_bytes: number;
  duration_seconds: number;
  waveform_data: number[];
  mode: "audio" | "video";
}

export async function presignVoicemail(
  conversationId: string,
  body: PresignVoicemailReq,
): Promise<{ message_id: string; upload_url: string; s3_key: string }> {
  return api.post<{ message_id: string; upload_url: string; s3_key: string }>(
    `/messaging/conversations/${conversationId}/voicemail/presign`,
    body,
  );
}

export async function createVoicemail(
  conversationId: string,
  body: CreateVoicemailReq,
): Promise<Message> {
  return api.post<Message>(
    `/messaging/conversations/${conversationId}/voicemail`,
    body,
  );
}

export async function sendVoicemail(
  conversationId: string,
  blob: Blob,
  meta: {
    callId: string;
    durationSeconds: number;
    waveform: number[];
    contentType: string;
    mode: "audio" | "video";
  },
): Promise<Message> {
  // 1. Get presigned URL
  const presign = await presignVoicemail(conversationId, {
    call_id: meta.callId,
    content_type: meta.contentType,
    size_bytes: blob.size,
    mode: meta.mode,
  });

  // 2. Upload blob to S3
  const uploadResp = await fetch(presign.upload_url, {
    method: "PUT",
    body: blob,
    headers: { "Content-Type": meta.contentType },
  });
  if (!uploadResp.ok) throw new Error("Failed to upload voicemail recording");

  // 3. Create voicemail message record
  return createVoicemail(conversationId, {
    message_id: presign.message_id,
    call_id: meta.callId,
    s3_key: presign.s3_key,
    content_type: meta.contentType,
    size_bytes: blob.size,
    duration_seconds: meta.durationSeconds,
    waveform_data: meta.waveform,
    mode: meta.mode,
  });
}
