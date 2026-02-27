import type { Conversation, Message } from "@/api/types";

type RawConversation = Partial<Conversation> & {
  created_at?: number | string;
  participant_count?: number | string;
  muted_until?: number | string;
  last_read_at?: number | string;
  unread_count?: number | string;
  last_message_at?: number | string;
  active_agent_claimed_at?: number | string;
  assignment_version?: number | string;
};

type RawMessage = Partial<Message> & {
  created_at?: number | string;
  edited_at?: number | string;
  revoked_at?: number | string;
  consumed_at?: number | string;
};

const buildS3ObjectUrl = (bucket?: string, key?: string): string | undefined => {
  if (!bucket || !key) return undefined;
  return `https://${bucket}.s3.amazonaws.com/${encodeURIComponent(key).replace(/%2F/g, "/")}`;
};

const buildFileManagerUrl = (path?: string): string | undefined => {
  if (!path) return undefined;
  return `/filemanager/download?path=${encodeURIComponent(path)}`;
};

const toNum = (value: unknown, fallback = 0): number => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }
  return fallback;
};

export function adaptMessage(raw: RawMessage): Message {
  return {
    message_id: String(raw.message_id ?? ""),
    conversation_id: String(raw.conversation_id ?? ""),
    sender_id: String(raw.sender_id ?? ""),
    kind: (raw.kind as Message["kind"]) ?? "text",
    created_at: toNum(raw.created_at),
    text: raw.text,
    image: raw.image
      ? {
          ...(raw.image as Record<string, unknown>),
          url:
            typeof (raw.image as { url?: unknown }).url === "string"
              ? ((raw.image as { url: string }).url)
              : buildS3ObjectUrl(
                  typeof (raw.image as { bucket?: unknown }).bucket === "string"
                    ? (raw.image as { bucket: string }).bucket
                    : undefined,
                  typeof (raw.image as { key?: unknown }).key === "string"
                    ? (raw.image as { key: string }).key
                    : undefined,
                ),
        }
      : undefined,
    file: raw.file
      ? {
          ...(raw.file as Record<string, unknown>),
          url:
            typeof (raw.file as { url?: unknown }).url === "string"
              ? ((raw.file as { url: string }).url)
              : buildFileManagerUrl(
                  typeof (raw.file as { path?: unknown }).path === "string"
                    ? (raw.file as { path: string }).path
                    : undefined,
                ),
        }
      : undefined,
    preview: raw.preview,
    reply_to_message_id: raw.reply_to_message_id,
    forwarded_from: raw.forwarded_from,
    forward_note: raw.forward_note,
    edited_at: raw.edited_at != null ? toNum(raw.edited_at) : undefined,
    edited_by: raw.edited_by,
    revoked_at: raw.revoked_at != null ? toNum(raw.revoked_at) : undefined,
    revoked_by: raw.revoked_by,
    delivered_to_count: raw.delivered_to_count,
    delivered_to_user_ids: raw.delivered_to_user_ids,
    read_by_count: raw.read_by_count,
    read_by_user_ids: raw.read_by_user_ids,
    reactions_counts: raw.reactions_counts,
    my_reactions: raw.my_reactions,
    is_encrypted: raw.is_encrypted,
    encryption: raw.encryption,
    consumption_policy: raw.consumption_policy,
    media_kind: raw.media_kind,
    consumption_state: raw.consumption_state,
    consumed_at: raw.consumed_at != null ? toNum(raw.consumed_at) : undefined,
    lock_price_cents: raw.lock_price_cents,
    lock_description: raw.lock_description,
    is_unlocked: raw.is_unlocked,
    locked: raw.locked,
    tip_amount_cents: raw.tip_amount_cents,
    tip_currency: raw.tip_currency,
    view_once: raw.view_once,
    expires_at: raw.expires_at,
    expired: raw.expired,
    scheduled: raw.scheduled,
    deliver_at: raw.deliver_at,
    edited: Boolean(raw.edited_at),
    revoked: Boolean(raw.revoked_at),
    file_share: raw.file_share,
    calendar_share: raw.calendar_share,
    calendar_event: raw.calendar_event,
    meeting_poll: raw.meeting_poll,
    free_images: raw.free_images,
    locked_images: raw.locked_images,
    locked_image_count: raw.locked_image_count,
  };
}

export function adaptConversation(raw: RawConversation): Conversation {
  return {
    conversation_id: String(raw.conversation_id ?? ""),
    type: (raw.type as Conversation["type"]) ?? "dm",
    title: raw.title,
    description: raw.description,
    icon: raw.icon,
    topic: raw.topic,
    retention_days: raw.retention_days,
    created_at: toNum(raw.created_at),
    created_by: String(raw.created_by ?? ""),
    participant_count: toNum(raw.participant_count),
    last_message_at: raw.last_message_at != null ? toNum(raw.last_message_at) : undefined,
    last_message_preview: raw.last_message_preview,
    status: String(raw.status ?? "active"),
    muted_until: toNum(raw.muted_until),
    last_read_at: toNum(raw.last_read_at),
    unread_count: toNum(raw.unread_count),
    participants: Array.isArray(raw.participants) ? raw.participants : [],
    last_message: raw.last_message ? adaptMessage(raw.last_message) : undefined,
    routing_mode: raw.routing_mode,
    routing_group_id: raw.routing_group_id,
    routing_state: raw.routing_state,
    active_agent_user_id: raw.active_agent_user_id,
    active_agent_claimed_at: raw.active_agent_claimed_at != null ? toNum(raw.active_agent_claimed_at) : undefined,
    assignment_version: raw.assignment_version != null ? toNum(raw.assignment_version) : undefined,
  };
}
