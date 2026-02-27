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
  SendGalleryMessageReq,
  SendFileShareReq,
  SendCalendarShareReq,
  SendCalendarEventReq,
  SendMeetingPollReq,
  MeetingPollState,
  HelpdeskClaimOut,
  RoutingEventOut,
} from "@/api/types";
import { adaptConversation, adaptMessage } from "./messagingAdapter";
import { isMessagingEncryptionEnabled } from "@/lib/featureFlags";
import { encryptBytes } from "@/lib/messageEncryption";

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

export const findOrCreateDm = async (userId: string): Promise<Conversation> => {
  const res = await api.post<Conversation>("/messaging/conversations/dm/find-or-create", {
    user_id: userId,
  });
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

export async function getHelpdeskQueue(groupId: string, state?: string): Promise<Conversation[]> {
  const params: Record<string, string> = { group_id: groupId };
  if (state) params.state = state;
  const res = await api.get<Conversation[]>("/messaging/helpdesk/queue", params);
  return (Array.isArray(res) ? res : []).map(adaptConversation);
}

export async function getRoutingEvents(conversationId: string, limit = 50): Promise<RoutingEventOut[]> {
  const res = await api.get<RoutingEventOut[]>(
    `/messaging/conversations/${conversationId}/routing-events`,
    { limit: String(limit) },
  );
  return Array.isArray(res) ? res : [];
}
