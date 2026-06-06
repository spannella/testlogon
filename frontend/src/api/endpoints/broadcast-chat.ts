import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

// Product link card payload (LCOM-002 / GAP-0289).
// The HTTP `POST .../chat/product` response only carries the base fields
// (item_id, category_id, name, description, price_cents, currency, image_url),
// while the SSE `chat:product_link` event also carries the broadcast-pricing
// snapshot. All pricing fields are therefore optional.
export interface ChatProductLink {
  item_id: string;
  category_id?: string;
  name: string;
  description?: string | null;
  price_cents: number;
  currency: string;
  image_url?: string | null;
  // Broadcast-pricing snapshot (SSE path only)
  broadcast_price_cents?: number | null;
  broadcast_price_expires_at?: number | null;
  effective_price_cents?: number | null;
  is_broadcast_price?: boolean | null;
  discount_pct?: number | null;
}

export interface ChatMessage {
  message_id: string;
  session_id: string;
  sender_id: string;
  sender_display_name: string;
  text: string | null;
  kind?: string;
  lottery_id?: string | null;
  // Product link card (LCOM-002 / GAP-0289)
  product_link?: ChatProductLink | null;
  created_at: number;
  deleted: boolean;
  // Tip fields (BCAST-013)
  tip_amount_cents?: number;
  tip_currency?: string;
  tip_payment_id?: string;
  // Phase A — Reactions (BCAST-015)
  reactions_counts?: Record<string, number> | null;
  my_reactions?: string[] | null;
  // Phase B — Replies (BCAST-015)
  reply_to_message_id?: string | null;
  reply_to_preview?: { sender_display_name: string; text: string } | null;
  // Phase C — Expiry (BCAST-015)
  expires_at?: number | null;
  expired?: boolean;
  // Phase D — Locked (BCAST-015)
  lock_price_cents?: number | null;
  lock_description?: string | null;
  is_unlocked?: boolean | null;
  tip_total_cents?: number | null;
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

export const sendChatMessage = (
  sessionId: string,
  text: string,
  options?: {
    reply_to_message_id?: string;
    expires_in_seconds?: number;
    lock_price_cents?: number;
    lock_description?: string;
  },
) =>
  api.post<ChatMessage>(`/broadcast/sessions/${sessionId}/chat`, {
    text,
    ...options,
  });

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

// Phase A — Reactions (BCAST-015)
export const reactToChatMessage = (
  sessionId: string,
  messageId: string,
  emoji: string,
  action: "add" | "remove" = "add",
) =>
  api.post<{ ok: boolean; reactions_counts: Record<string, number> }>(
    `/broadcast/sessions/${sessionId}/chat/${messageId}/react`,
    { emoji, action },
  );

// Phase D — Unlock (BCAST-015)
export const unlockChatMessage = (
  sessionId: string,
  messageId: string,
  paymentMethodId: string,
) =>
  api.post<{
    ok: boolean;
    message_id: string;
    text: string;
    unlock_payment_id: string;
    amount_cents: number;
  }>(`/broadcast/sessions/${sessionId}/chat/${messageId}/unlock`, {
    payment_method_id: paymentMethodId,
  });

// Product link share (LCOM-002 / GAP-0289 + GAP-0290)
export const sendChatProductLink = (sessionId: string, itemId: string) =>
  api.post<ChatMessage>(`/broadcast/sessions/${sessionId}/chat/product`, {
    item_id: itemId,
  });

// --- Lottery endpoints (BCAST-014) -----------------------------------------

import type {
  BroadcastLotteryCreateIn,
  BroadcastLotteryEntryIn,
  BroadcastLotteryConfigOut,
  BroadcastLotteryDrawOut,
  BroadcastLotteryEntryOut,
  BroadcastLotteryViewerStatus,
} from "@/api/types";

export const createLottery = (
  sessionId: string,
  data: BroadcastLotteryCreateIn,
) =>
  api.post<BroadcastLotteryConfigOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery`,
    data,
  );

export const enterLottery = (
  sessionId: string,
  lotteryId: string,
  data?: BroadcastLotteryEntryIn,
) =>
  api.post<BroadcastLotteryEntryOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/enter`,
    data ?? {},
  );

export const closeLotteryEntries = (sessionId: string, lotteryId: string) =>
  api.post<BroadcastLotteryConfigOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/close`,
    {},
  );

export const drawLottery = (sessionId: string, lotteryId: string) =>
  api.post<BroadcastLotteryDrawOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/draw`,
    {},
  );

export const getLotteryStatus = (sessionId: string, lotteryId: string) =>
  api.get<BroadcastLotteryViewerStatus>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}`,
  );

export const getLotteryResults = (sessionId: string, lotteryId: string) =>
  api.get<BroadcastLotteryDrawOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/results`,
  );
