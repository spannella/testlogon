import { api } from "@/api/client";
import type {
  AchievementDefinition,
  UserAchievement,
  AchievementProgress,
  LeaderboardEntry,
  BadgeSummary,
} from "@/api/types";

// ─── User achievement endpoints ─────────────────────────────────

export const getMyAchievements = (params?: {
  displayed?: boolean;
  category?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.displayed !== undefined) q.displayed = String(params.displayed);
  if (params?.category) q.category = params.category;
  return api.get<{
    achievements: UserAchievement[];
    total_points: number;
    achievement_count: number;
  }>("/ui/achievements", Object.keys(q).length ? q : undefined);
};

export const getAchievementProgress = () =>
  api.get<{ progress: AchievementProgress[] }>("/ui/achievements/progress");

export const getProgressForMetric = (metricKey: string) =>
  api.get<AchievementProgress>(`/ui/achievements/progress/${metricKey}`);

export const getEarnedAchievements = () =>
  api.get<{
    achievements: UserAchievement[];
    total_points: number;
    achievement_count: number;
  }>("/ui/achievements/earned");

// ─── Display badges ─────────────────────────────────────────────

export const setDisplayBadges = (achievementIds: string[]) =>
  api.post<{ ok: boolean; display_badges: BadgeSummary[] }>(
    "/ui/achievements/display-badges",
    { achievement_ids: achievementIds },
  );

export const getUserDisplayBadges = (userSub: string) =>
  api.get<{
    user_sub: string;
    display_badges: BadgeSummary[];
    total_points: number;
    achievement_count: number;
  }>(`/ui/achievements/display-badges/${userSub}`);

// ─── Leaderboard ────────────────────────────────────────────────

export const getLeaderboard = (params: {
  period: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = { period: params.period };
  if (params.limit !== undefined) q.limit = String(params.limit);
  if (params.cursor) q.cursor = params.cursor;
  return api.get<{
    entries: LeaderboardEntry[];
    next_cursor?: string;
    period: string;
  }>("/ui/achievements/leaderboard", q);
};

export const getMyRank = (period: string) =>
  api.get<LeaderboardEntry & { period: string }>(
    "/ui/achievements/leaderboard/me",
    { period },
  );

// ─── Admin definitions ──────────────────────────────────────────

export const listDefinitions = (activeOnly = true) =>
  api.get<{ definitions: AchievementDefinition[] }>(
    "/ui/achievements/definitions",
    { active_only: String(activeOnly) },
  );

export const createDefinition = (
  data: Omit<AchievementDefinition, "active" | "created_at" | "updated_at">,
) => api.post<AchievementDefinition>("/ui/achievements/admin/definitions", data);

export const updateDefinition = (
  achievementId: string,
  data: Partial<AchievementDefinition>,
) => api.put<AchievementDefinition>(`/ui/achievements/admin/definitions/${achievementId}`, data);

export const deleteDefinition = (achievementId: string) =>
  api.del(`/ui/achievements/admin/definitions/${achievementId}`);

export const seedDefaultAchievements = () =>
  api.post<{ ok: boolean; created: string[]; count: number }>(
    "/ui/achievements/admin/seed",
  );
