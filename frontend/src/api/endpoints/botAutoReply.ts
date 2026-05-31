import { api } from "@/api/client";
import type { AutoReplyRule, AutoReplyTestResult } from "@/api/types";

export const createAutoReplyRule = (
  botId: string,
  data: {
    trigger_pattern: string;
    response_template: string;
    match_type?: "keyword" | "regex" | "contains" | "exact";
    priority?: number;
    enabled?: boolean;
  },
) => api.post<AutoReplyRule>(`/ui/bots/${botId}/auto-replies`, data);

export const listAutoReplyRules = (botId: string) =>
  api.get<{ rules: AutoReplyRule[] }>(`/ui/bots/${botId}/auto-replies`);

export const getAutoReplyRule = (botId: string, ruleId: string) =>
  api.get<AutoReplyRule>(`/ui/bots/${botId}/auto-replies/${ruleId}`);

export const updateAutoReplyRule = (
  botId: string,
  ruleId: string,
  data: Partial<{
    trigger_pattern: string;
    response_template: string;
    match_type: "keyword" | "regex" | "contains" | "exact";
    priority: number;
    enabled: boolean;
  }>,
) => api.put<AutoReplyRule>(`/ui/bots/${botId}/auto-replies/${ruleId}`, data);

export const deleteAutoReplyRule = (botId: string, ruleId: string) =>
  api.del<{ ok: boolean }>(`/ui/bots/${botId}/auto-replies/${ruleId}`);

export const testAutoReply = (botId: string, messageText: string) =>
  api.post<AutoReplyTestResult>(`/ui/bots/${botId}/auto-replies/test`, {
    message_text: messageText,
  });
