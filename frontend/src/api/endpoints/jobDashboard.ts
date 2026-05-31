import { api } from "@/api/client";
import type {
  JobRegistryOut,
  JobHealthOut,
  JobRunsOut,
  JobRunOut,
  JobRunNowOut,
} from "@/api/types";

const BASE = "/ui/admin/jobs";

export const getJobRegistry = () => api.get<JobRegistryOut>(`${BASE}/registry`);

export const getJobHealth = () => api.get<JobHealthOut>(`${BASE}/health`);

export const getRecentJobRuns = (limit = 100) =>
  api.get<JobRunsOut>(`${BASE}/runs?limit=${limit}`);

export const getJobRuns = (jobName: string, limit = 50) =>
  api.get<JobRunsOut>(`${BASE}/runs/${encodeURIComponent(jobName)}?limit=${limit}`);

export const getJobLatestRun = (jobName: string) =>
  api.get<JobRunOut>(`${BASE}/runs/${encodeURIComponent(jobName)}/latest`);

export const runJobNow = (jobName: string) =>
  api.post<JobRunNowOut>(`${BASE}/run-now/${encodeURIComponent(jobName)}`);
