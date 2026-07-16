import { api } from "../client";
import type { QAQuestion, QAQueueResponse, QAStats } from "../types";

export const toggleQAMode = (sessionId: string, enabled: boolean) =>
  api.post(`/broadcast/sessions/${sessionId}/qa-mode`, { enabled });

export const submitQuestion = (sessionId: string, text: string) =>
  api.post<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/questions`, { text });

export const listQuestions = (
  sessionId: string,
  status = "pending",
  limit = 50,
) =>
  api.get<QAQueueResponse>(`/broadcast/sessions/${sessionId}/qa/questions`, {
    status,
    limit: String(limit),
  });

export const featureQuestion = (sessionId: string, questionId: string) =>
  api.post<QAQuestion>(
    `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/feature`,
  );

export const answerQuestion = (sessionId: string, questionId: string) =>
  api.post<QAQuestion>(
    `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/answer`,
  );

export const dismissQuestion = (sessionId: string, questionId: string) =>
  api.post<QAQuestion>(
    `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/dismiss`,
  );

export const removeQuestion = (sessionId: string, questionId: string) =>
  api.post(
    `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/remove`,
  );

export const upvoteQuestion = (sessionId: string, questionId: string) =>
  api.post<QAQuestion>(
    `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/upvote`,
  );

export const removeUpvote = (sessionId: string, questionId: string) =>
  api.del<QAQuestion>(
    `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/upvote`,
  );

export const getFeaturedQuestion = (sessionId: string) =>
  api.get<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/featured`);

export const getQAStats = (sessionId: string) =>
  api.get<QAStats>(`/broadcast/sessions/${sessionId}/qa/stats`);
