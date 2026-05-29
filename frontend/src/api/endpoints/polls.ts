import { api } from "@/api/client";
import type { VoteResponse, PollResultsResponse } from "@/api/types";

export const castVote = async (postId: string, questionId: string, optionId: string) =>
  api.post<VoteResponse>(`/posts/${postId}/vote`, { question_id: questionId, option_id: optionId });

export const removeVote = async (postId: string, questionId: string) =>
  api.del<VoteResponse>(`/posts/${postId}/vote`, { question_id: questionId });

export const closePoll = async (postId: string) =>
  api.post<{ ok: boolean; post_id: string; closed: boolean; closes_at: number }>(`/posts/${postId}/close-poll`);

export const getPollResults = async (postId: string, questionId: string) =>
  api.get<PollResultsResponse>(`/posts/${postId}/poll-results`, { question_id: questionId });
