import { api } from "@/api/client";
import type {
  ChatBot,
  BotAssignment,
  BotStats,
  BotTemplate,
  BotScheduledSend,
  TemplatePreviewOut,
} from "@/api/types";

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

// -- Bot Templates (BOT-002) --

export const createTemplate = (
  botId: string,
  data: {
    name: string;
    text: string;
    category?: string;
    body_format?: string;
    quick_replies?: Array<{ label: string; value: string }>;
    ab_group?: string;
    ab_weight?: number;
  },
) => api.post<BotTemplate>(`/ui/bots/${botId}/templates`, data);

export const listTemplates = (botId: string, category?: string) => {
  const params = category ? `?category=${encodeURIComponent(category)}` : "";
  return api.get<BotTemplate[]>(`/ui/bots/${botId}/templates${params}`);
};

export const getTemplate = (botId: string, templateId: string) =>
  api.get<BotTemplate>(`/ui/bots/${botId}/templates/${templateId}`);

export const updateTemplate = (
  botId: string,
  templateId: string,
  data: Partial<BotTemplate>,
) => api.put<BotTemplate>(`/ui/bots/${botId}/templates/${templateId}`, data);

export const deleteTemplate = (botId: string, templateId: string) =>
  api.del<{ ok: boolean }>(`/ui/bots/${botId}/templates/${templateId}`);

export const previewTemplate = (
  botId: string,
  templateId: string,
  data: {
    sample_user_name?: string;
    sample_subscriber_status?: string;
    conversation_id?: string;
  },
) =>
  api.post<TemplatePreviewOut>(
    `/ui/bots/${botId}/templates/${templateId}/preview`,
    data,
  );

export const sendTestTemplate = (
  botId: string,
  templateId: string,
  data: { conversation_id: string },
) =>
  api.post<{ ok: boolean; rendered_text: string }>(
    `/ui/bots/${botId}/templates/${templateId}/send-test`,
    data,
  );

// -- Bot Scheduled Sends (BOT-002) --

export const createScheduledSend = (
  botId: string,
  data: {
    template_id: string;
    target_type: string;
    target_id?: string;
    cron_expression: string;
    timezone?: string;
  },
) => api.post<BotScheduledSend>(`/ui/bots/${botId}/schedules`, data);

export const listScheduledSends = (botId: string) =>
  api.get<BotScheduledSend[]>(`/ui/bots/${botId}/schedules`);

export const updateScheduledSend = (
  botId: string,
  scheduleId: string,
  data: Partial<BotScheduledSend>,
) =>
  api.put<BotScheduledSend>(
    `/ui/bots/${botId}/schedules/${scheduleId}`,
    data,
  );

export const deleteScheduledSend = (botId: string, scheduleId: string) =>
  api.del<{ ok: boolean }>(`/ui/bots/${botId}/schedules/${scheduleId}`);
