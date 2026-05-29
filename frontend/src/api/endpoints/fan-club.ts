import { api } from "../client";
import type {
  TierCreateIn,
  TierOut,
  ChannelOut,
  ChannelMessageOut,
  MemberBadgeData,
} from "../types";

export async function createTier(data: TierCreateIn): Promise<TierOut> {
  return api.post<TierOut>("/ui/fan-club/tiers", data);
}

export async function listTiers(): Promise<TierOut[]> {
  return api.get<TierOut[]>("/ui/fan-club/tiers");
}

export async function getTier(tierId: string): Promise<TierOut> {
  return api.get<TierOut>(`/ui/fan-club/tiers/${tierId}`);
}

export async function updateTier(
  tierId: string,
  data: Partial<TierCreateIn>,
): Promise<TierOut> {
  return api.patch<TierOut>(`/ui/fan-club/tiers/${tierId}`, data);
}

export async function deleteTier(tierId: string): Promise<void> {
  await api.del(`/ui/fan-club/tiers/${tierId}`);
}

export async function reorderTiers(tierIds: string[]): Promise<TierOut[]> {
  return api.patch<TierOut[]>("/ui/fan-club/tiers/reorder", {
    tier_ids: tierIds,
  });
}

export async function listChannels(
  creatorId?: string,
): Promise<ChannelOut[]> {
  const params = creatorId ? { creator_id: creatorId } : undefined;
  return api.get<ChannelOut[]>("/ui/fan-club/channels", params);
}

export async function createChannel(data: {
  name: string;
  description?: string;
  min_tier_level: number;
  slowmode_seconds?: number;
  max_message_length?: number;
}): Promise<ChannelOut> {
  return api.post<ChannelOut>("/ui/fan-club/channels", data);
}

export async function sendChannelMessage(
  channelId: string,
  text: string,
  replyToMessageId?: string,
): Promise<ChannelMessageOut> {
  return api.post<ChannelMessageOut>(
    `/ui/fan-club/channels/${channelId}/messages`,
    { text, reply_to_message_id: replyToMessageId },
  );
}

export async function getChannelMessages(
  channelId: string,
  params?: { before?: string; limit?: number },
): Promise<ChannelMessageOut[]> {
  const p = params
    ? Object.fromEntries(
        Object.entries(params)
          .filter(([, v]) => v != null)
          .map(([k, v]) => [k, String(v)]),
      )
    : undefined;
  return api.get<ChannelMessageOut[]>(
    `/ui/fan-club/channels/${channelId}/messages`,
    p,
  );
}

export async function getMyBadge(
  creatorId: string,
): Promise<MemberBadgeData | null> {
  return api.get<MemberBadgeData | null>(`/ui/fan-club/badge/${creatorId}`);
}

export async function getPublicTiers(
  creatorId: string,
): Promise<TierOut[]> {
  return api.get<TierOut[]>(`/api/creators/${creatorId}/tiers`);
}
