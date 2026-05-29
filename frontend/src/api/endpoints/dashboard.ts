import { api } from "@/api/client";
import type {
  DashboardSummary,
  DashboardMilestone,
  MilestoneSettings,
} from "@/api/types";

export const getDashboardSummary = () =>
  api.get<DashboardSummary>("/ui/dashboard/summary");

export const refreshDashboard = () =>
  api.post<{ ok: boolean; message: string; refreshed_at: number }>("/ui/dashboard/refresh");

export const listMilestones = () =>
  api.get<DashboardMilestone[]>("/ui/milestones");

export const acknowledgeMilestone = (milestoneId: string) =>
  api.post<{ ok: boolean }>(`/ui/milestones/${milestoneId}/acknowledge`);

export const getMilestoneSettings = () =>
  api.get<MilestoneSettings>("/ui/milestones/settings");

export const updateMilestoneSettings = (data: Partial<MilestoneSettings>) =>
  api.patch<MilestoneSettings>("/ui/milestones/settings", data);
