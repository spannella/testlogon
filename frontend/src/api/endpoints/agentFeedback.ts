import { api } from "@/api/client";
import type {
  FeedbackListOut,
  FeedbackRequest,
  FeedbackRespondIn,
  CreateFeedbackRequestIn,
  TerminalOutputOut,
  TerminalSearchOut,
  PatternConfigOut,
  PatternUpdateIn,
  PatternTestIn,
  PatternTestOut,
} from "@/api/types";

const BASE = "/ui/agent/feedback";

// ─── Feedback requests ─────────────────────────────────────────────

export const listAllFeedback = (status?: string) => {
  const params: Record<string, string> = {};
  if (status) params.status = status;
  return api.get<FeedbackListOut>(BASE, params);
};

export const listWorkerFeedback = (
  workerId: string,
  status?: string,
) => {
  const params: Record<string, string> = {};
  if (status) params.status = status;
  return api.get<FeedbackListOut>(`${BASE}/${workerId}`, params);
};

export const getFeedbackRequest = (workerId: string, requestId: string) =>
  api.get<FeedbackRequest>(`${BASE}/${workerId}/${requestId}`);

export const createFeedbackRequest = (
  workerId: string,
  body: CreateFeedbackRequestIn,
) => api.post<FeedbackRequest>(`${BASE}/${workerId}`, body);

export const respondToFeedback = (
  workerId: string,
  requestId: string,
  body: FeedbackRespondIn,
) => api.post<FeedbackRequest>(`${BASE}/${workerId}/${requestId}/respond`, body);

export const skipFeedback = (workerId: string, requestId: string) =>
  api.post<FeedbackRequest>(`${BASE}/${workerId}/${requestId}/skip`, {});

// ─── Terminal output ────────────────────────────────────────────────

export const getTerminalLog = (workerId: string, chars?: number) => {
  const params: Record<string, string> = {};
  if (chars) params.chars = String(chars);
  return api.get<TerminalOutputOut>(`${BASE}/${workerId}/terminal-log`, params);
};

export const searchTerminal = (workerId: string, keyword: string) =>
  api.get<TerminalSearchOut>(`${BASE}/${workerId}/terminal-search`, {
    keyword,
  });

// ─── Pattern config ─────────────────────────────────────────────────

export const getPatterns = (workerId: string) =>
  api.get<PatternConfigOut>(`${BASE}/${workerId}/patterns`);

export const updatePatterns = (workerId: string, body: PatternUpdateIn) =>
  api.put<PatternConfigOut>(`${BASE}/${workerId}/patterns`, body);

export const testPatterns = (body: PatternTestIn) =>
  api.post<PatternTestOut>(`${BASE}/test-patterns`, body);
