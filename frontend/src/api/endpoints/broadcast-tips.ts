import { api } from "@/api/client";
import type {
  BroadcastTipGoal,
  BroadcastTipSummary,
  BroadcastTipConfigIn,
  BroadcastSession,
} from "./broadcast";
import type { ChatMessage } from "./broadcast-chat";

// --- Tip Actions ---

export interface SendTipIn {
  amount_cents: number;
  text?: string;
  payment_method_id: string;
  currency?: string;
}

export const sendBroadcastTip = (sessionId: string, body: SendTipIn) =>
  api.post<ChatMessage>(
    `/broadcast/sessions/${sessionId}/chat/tip`,
    body,
  );

export const getTipSummary = (
  sessionId: string,
  params?: { top_limit?: number; recent_limit?: number },
) =>
  api.get<BroadcastTipSummary>(
    `/broadcast/sessions/${sessionId}/tips/summary`,
    params as Record<string, string>,
  );

export const updateTipConfig = (sessionId: string, body: BroadcastTipConfigIn) =>
  api.patch<BroadcastSession>(
    `/broadcast/sessions/${sessionId}/tips/config`,
    body,
  );

// --- Tip Goals ---

export interface CreateGoalIn {
  label: string;
  target_cents: number;
  sort_order?: number;
}

export const createTipGoal = (sessionId: string, body: CreateGoalIn) =>
  api.post<BroadcastTipGoal>(
    `/broadcast/sessions/${sessionId}/goals`,
    body,
  );

export const listTipGoals = (sessionId: string) =>
  api.get<{ goals: BroadcastTipGoal[]; session_id: string }>(
    `/broadcast/sessions/${sessionId}/goals`,
  );

export const deleteTipGoal = (sessionId: string, goalId: string) =>
  api.del<{ ok: boolean; goal_id: string }>(
    `/broadcast/sessions/${sessionId}/goals/${goalId}`,
  );
