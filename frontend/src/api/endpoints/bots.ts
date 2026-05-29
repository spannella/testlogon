import { api } from "@/api/client";
import type { ChatBot, BotAssignment, BotStats } from "@/api/types";

export const createBot = (data: {
  name: string;
  avatar_url?: string;
  description?: string;
  personality?: string;
  custom_personality?: string;
}) => api.post<ChatBot>("/ui/bots", data);

export const listBots = () =>
  api.get<{ bots: ChatBot[] }>("/ui/bots");

export const getBot = (botId: string) =>
  api.get<ChatBot>(`/ui/bots/${botId}`);

export const updateBot = (botId: string, data: Partial<ChatBot>) =>
  api.put<ChatBot>(`/ui/bots/${botId}`, data);

export const updateBotStatus = (botId: string, status: string) =>
  api.patch<ChatBot>(`/ui/bots/${botId}/status`, { status });

export const deleteBot = (botId: string) =>
  api.del<{ ok: boolean }>(`/ui/bots/${botId}`);

export const assignBot = (
  botId: string,
  data: { target_type: string; target_id?: string },
) => api.post<BotAssignment>(`/ui/bots/${botId}/assignments`, data);

export const unassignBot = (botId: string, assignmentSk: string) =>
  api.del<{ ok: boolean }>(`/ui/bots/${botId}/assignments/${encodeURIComponent(assignmentSk)}`);

export const listAssignments = (botId: string) =>
  api.get<{ assignments: BotAssignment[] }>(`/ui/bots/${botId}/assignments`);

export const getBotStats = (botId: string) =>
  api.get<BotStats>(`/ui/bots/${botId}/stats`);
