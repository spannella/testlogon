import { api } from "../client";
import type { BlockActionResponse, BlockedUsersResponse, BlockStatusResponse } from "../types";

// ── API calls ────────────────────────────────────────────────────

export const blockUser = (body: { target_user_id: string; reason?: string }) =>
  api.post<BlockActionResponse>("/ui/social/block", body);

export const unblockUser = (body: { target_user_id: string }) =>
  api.post<BlockActionResponse>("/ui/social/unblock", body);

export const getBlockedUsers = (params?: { limit?: string; cursor?: string }) =>
  api.get<BlockedUsersResponse>("/ui/social/blocked", params);

export const getBlockStatus = (targetUserId: string) =>
  api.get<BlockStatusResponse>(`/ui/social/block-status/${targetUserId}`);
