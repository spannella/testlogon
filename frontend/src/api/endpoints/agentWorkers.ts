import { api } from "@/api/client";
import type {
  CreateWorkerIn,
  Worker,
  WorkerList,
  ToolListOut,
  ComputeOptionListOut,
} from "@/api/types";

const BASE = "/ui/agent/workers";

// ─── Static metadata ────────────────────────────────────────────

export const getTools = () => api.get<ToolListOut>(`${BASE}/tools`);

export const getComputeOptions = () =>
  api.get<ComputeOptionListOut>(`${BASE}/compute-options`);

// ─── Worker CRUD ────────────────────────────────────────────────

export const createWorker = (body: CreateWorkerIn) =>
  api.post<Worker>(BASE, body);

export const listWorkers = (params?: {
  status?: string;
  agent_type?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.status) q["status"] = params.status;
  if (params?.agent_type) q["agent_type"] = params.agent_type;
  return api.get<WorkerList>(BASE, q);
};

export const getWorker = (workerId: string) =>
  api.get<Worker>(`${BASE}/${workerId}`);

// ─── Worker lifecycle ───────────────────────────────────────────

export const stopWorker = (workerId: string) =>
  api.post<Worker>(`${BASE}/${workerId}/stop`, {});

export const startWorker = (workerId: string) =>
  api.post<Worker>(`${BASE}/${workerId}/start`, {});

export const terminateWorker = (workerId: string) =>
  api.del<Worker>(`${BASE}/${workerId}`);

// ─── Provision log ──────────────────────────────────────────────

export const getProvisionLog = (workerId: string) =>
  api.get<Array<{ step: string; status: string; ts: number; detail: string }>>(
    `${BASE}/${workerId}/provision-log`,
  );
