import client from "../client";
import type { QAQuestion, QAQueueResponse, QAStats } from "../types";

export const toggleQAMode = async (sessionId: string, enabled: boolean) =>
  client
    .post(`/broadcast/sessions/${sessionId}/qa-mode`, { enabled })
    .then((r) => r.data);

export const submitQuestion = async (sessionId: string, text: string) =>
  client
    .post<QAQuestion>(
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text },
    )
    .then((r) => r.data);

export const listQuestions = async (
  sessionId: string,
  status = "pending",
  limit = 50,
) =>
  client
    .get<QAQueueResponse>(
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { params: { status, limit } },
    )
    .then((r) => r.data);

export const featureQuestion = async (
  sessionId: string,
  questionId: string,
) =>
  client
    .post<QAQuestion>(
      `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/feature`,
    )
    .then((r) => r.data);

export const answerQuestion = async (
  sessionId: string,
  questionId: string,
) =>
  client
    .post<QAQuestion>(
      `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/answer`,
    )
    .then((r) => r.data);

export const dismissQuestion = async (
  sessionId: string,
  questionId: string,
) =>
  client
    .post<QAQuestion>(
      `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/dismiss`,
    )
    .then((r) => r.data);

export const removeQuestion = async (
  sessionId: string,
  questionId: string,
) =>
  client
    .post(
      `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/remove`,
    )
    .then((r) => r.data);

export const upvoteQuestion = async (
  sessionId: string,
  questionId: string,
) =>
  client
    .post<QAQuestion>(
      `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/upvote`,
    )
    .then((r) => r.data);

export const removeUpvote = async (
  sessionId: string,
  questionId: string,
) =>
  client
    .delete<QAQuestion>(
      `/broadcast/sessions/${sessionId}/qa/questions/${questionId}/upvote`,
    )
    .then((r) => r.data);

export const getFeaturedQuestion = async (sessionId: string) =>
  client
    .get<QAQuestion>(`/broadcast/sessions/${sessionId}/qa/featured`)
    .then((r) => r.data);

export const getQAStats = async (sessionId: string) =>
  client
    .get<QAStats>(`/broadcast/sessions/${sessionId}/qa/stats`)
    .then((r) => r.data);
