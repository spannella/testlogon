import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export interface PrivateChatPurchaseRequest {
  tier: 1 | 2;
  duration_minutes: number;
  payment_method_id: string;
  chat_id?: string; // required for tier 2
}

export interface PrivateChatPurchaseResponse {
  chat_id: string;
  session_id: string;
  tier: number;
  duration_minutes: number;
  total_paid_cents: number;
  rate_per_minute_cents: number;
  expires_at: number;
  status: string;
}

export interface PrivateChatMessage {
  message_id: string;
  session_id: string;
  sender_id: string;
  sender_display_name: string;
  text: string;
  kind: string;
  private_chat_id: string | null;
  created_at: number;
  deleted: boolean;
  filtered: boolean;
}

export interface PrivateChatHistoryResponse {
  messages: PrivateChatMessage[];
  has_more: boolean;
  oldest_sort_key: string | null;
}

export interface PrivateChatExtendRequest {
  duration_minutes: number;
  payment_method_id: string;
}

export interface PrivateChatExtendResponse {
  chat_id: string;
  session_id: string;
  expires_at: number;
  purchased_minutes: number;
  total_paid_cents: number;
  status: string;
}

export interface PrivateChatStatus {
  chat_id: string;
  session_id: string;
  viewer_id: string;
  viewer_display_name: string;
  status: string;
  tier: number;
  rate_per_minute_cents: number;
  purchased_minutes: number;
  remaining_seconds: number;
  started_at: number;
  expires_at: number;
  voyeur_count: number;
}

export interface PrivateChatSummary {
  chat_id: string;
  viewer_id: string;
  viewer_display_name: string;
  tier: number;
  rate_per_minute_cents: number;
  purchased_minutes: number;
  remaining_seconds: number;
  status: string;
  started_at: number;
  expires_at: number;
  voyeur_count: number;
  total_revenue_cents: number;
}

export interface PrivateChatListResponse {
  chats: PrivateChatSummary[];
}

export interface PrivateChatTiers {
  private_chat_enabled: boolean;
  private_chat_rate_per_minute_cents: number;
  voyeur_rate_per_minute_cents: number;
  private_chat_time_blocks: number[];
  private_chat_max_concurrent: number;
  private_chat_voyeur_enabled: boolean;
}

export interface PrivateChatSettingsRequest {
  private_chat_enabled?: boolean;
  private_chat_rate_per_minute_cents?: number;
  voyeur_rate_per_minute_cents?: number;
  private_chat_time_blocks?: number[];
  private_chat_max_concurrent?: number;
}

// ─── API Functions ──────────────────────────────────────────────

export const configureChatTiers = (
  sessionId: string,
  data: PrivateChatSettingsRequest,
) =>
  api.put<PrivateChatTiers>(
    `/broadcast/sessions/${sessionId}/chat-tiers`,
    data,
  );

export const getChatTiers = (sessionId: string) =>
  api.get<PrivateChatTiers>(
    `/broadcast/sessions/${sessionId}/chat-tiers`,
  );

export const purchasePrivateChat = (
  sessionId: string,
  data: PrivateChatPurchaseRequest,
) =>
  api.post<PrivateChatPurchaseResponse>(
    `/broadcast/sessions/${sessionId}/private-chat/purchase`,
    data,
  );

export const sendPrivateChatMessage = (
  sessionId: string,
  chatId: string,
  data: { text: string },
) =>
  api.post<PrivateChatMessage>(
    `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`,
    data,
  );

export const getPrivateChatMessages = (
  sessionId: string,
  chatId: string,
  params?: { limit?: number; before?: string },
) => {
  const qs: Record<string, string> = {};
  if (params?.limit != null) qs.limit = String(params.limit);
  if (params?.before) qs.before = params.before;
  return api.get<PrivateChatHistoryResponse>(
    `/broadcast/sessions/${sessionId}/private-chat/${chatId}/messages`,
    Object.keys(qs).length ? qs : undefined,
  );
};

export const endPrivateChat = (sessionId: string, chatId: string) =>
  api.post<{ ok: boolean; chat_id: string; ended_reason: string }>(
    `/broadcast/sessions/${sessionId}/private-chat/${chatId}/end`,
  );

export const joinVoyeur = (
  sessionId: string,
  chatId: string,
  data: PrivateChatExtendRequest,
) =>
  api.post<PrivateChatPurchaseResponse>(
    `/broadcast/sessions/${sessionId}/private-chat/${chatId}/voyeur`,
    data,
  );

export const getPrivateChatStatus = (
  sessionId: string,
  chatId: string,
) =>
  api.get<PrivateChatStatus>(
    `/broadcast/sessions/${sessionId}/private-chat/${chatId}/status`,
  );

export const listPrivateChats = (sessionId: string) =>
  api.get<PrivateChatListResponse>(
    `/broadcast/sessions/${sessionId}/private-chats`,
  );

export const extendPrivateChat = (
  sessionId: string,
  chatId: string,
  data: PrivateChatExtendRequest,
) =>
  api.post<PrivateChatExtendResponse>(
    `/broadcast/sessions/${sessionId}/private-chat/${chatId}/extend`,
    data,
  );
