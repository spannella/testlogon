import { api } from "@/api/client";
import type {
  SplitConfig,
  SplitConfigInput,
  SplitExecution,
  ExecuteSplitInput,
  MemberEarnings,
} from "@/api/types";

const base = (syndicateId: string) =>
  `/ui/syndicates/revenue-split/${syndicateId}`;

export const getSplitConfig = (syndicateId: string) =>
  api.get<SplitConfig>(`${base(syndicateId)}/config`);

export const setSplitConfig = (syndicateId: string, body: SplitConfigInput) =>
  api.post<SplitConfig>(`${base(syndicateId)}/config`, body);

export const setPerformanceScores = (
  syndicateId: string,
  metric: string,
  scores: Record<string, number>,
) =>
  api.post<unknown>(`${base(syndicateId)}/performance-scores`, { metric, scores });

export const listSplits = (syndicateId: string) =>
  api.get<SplitExecution[]>(`${base(syndicateId)}/splits`);

export const getSplit = (syndicateId: string, splitId: string) =>
  api.get<SplitExecution>(`${base(syndicateId)}/splits/${splitId}`);

export const getMyEarnings = (syndicateId: string) =>
  api.get<MemberEarnings>(`${base(syndicateId)}/my-earnings`);

export const executeSplit = (syndicateId: string, body: ExecuteSplitInput) =>
  api.post<SplitExecution>(`${base(syndicateId)}/execute`, body);
