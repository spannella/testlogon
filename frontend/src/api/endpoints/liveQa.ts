import { api } from "@/api/client";
import type {
  LiveQaModeResponse,
  LiveQaQuestion,
  LiveQaQueueResponse,
  LiveQaStats,
  LiveQaStatus,
} from "@/api/types";

const base = (sessionId: string) => `/ui/live-qa/sessions/${sessionId}`;

export const getLiveQaMode = (sessionId: string) =>
  api.get<LiveQaModeResponse>(`${base(sessionId)}/mode`);

export const setLiveQaMode = (sessionId: string, enabled: boolean) =>
  api.post<LiveQaModeResponse>(`${base(sessionId)}/mode`, { enabled });

export const submitLiveQaQuestion = (sessionId: string, text: string) =>
  api.post<LiveQaQuestion>(`${base(sessionId)}/questions`, { text });

export const listLiveQaQuestions = (
  sessionId: string,
  status: LiveQaStatus = "pending",
  limit = 50,
) =>
  api.get<LiveQaQueueResponse>(`${base(sessionId)}/questions`, {
    status,
    limit: String(limit),
  });

export const getLiveQaFeatured = (sessionId: string) =>
  api.get<LiveQaQuestion | null>(`${base(sessionId)}/featured`);

export const getLiveQaStats = (sessionId: string) =>
  api.get<LiveQaStats>(`${base(sessionId)}/stats`);

export const upvoteLiveQaQuestion = (sessionId: string, questionId: string) =>
  api.post<LiveQaQuestion>(`${base(sessionId)}/questions/${questionId}/vote`);

export const removeLiveQaVote = (sessionId: string, questionId: string) =>
  api.del<LiveQaQuestion>(`${base(sessionId)}/questions/${questionId}/vote`);

export const featureLiveQaQuestion = (sessionId: string, questionId: string) =>
  api.post<LiveQaQuestion>(`${base(sessionId)}/questions/${questionId}/feature`);

export const answerLiveQaQuestion = (sessionId: string, questionId: string) =>
  api.post<LiveQaQuestion>(`${base(sessionId)}/questions/${questionId}/answer`);

export const dismissLiveQaQuestion = (sessionId: string, questionId: string) =>
  api.post<LiveQaQuestion>(`${base(sessionId)}/questions/${questionId}/dismiss`);

export const pinLiveQaQuestion = (
  sessionId: string,
  questionId: string,
  pinned = true,
) =>
  api.post<LiveQaQuestion>(`${base(sessionId)}/questions/${questionId}/pin`, {
    pinned,
  });

export const removeLiveQaQuestion = (sessionId: string, questionId: string) =>
  api.post<{ ok: boolean; question_id: string }>(
    `${base(sessionId)}/questions/${questionId}/remove`,
  );
