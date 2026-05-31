import { api } from "@/api/client";
import type {
  AgentPr,
  AgentPrCreateIn,
  AgentPrListOut,
  AgentCompletion,
  StatusFlowConfig,
  StatusFlowUpdateIn,
} from "@/api/types";

const BASE = "/ui/agent/pr";

// ─── PR creation & listing ─────────────────────────────────────

export const createPr = (workerId: string, body: AgentPrCreateIn) =>
  api.post<AgentPr>(`${BASE}/${workerId}/create`, body);

export const listPrs = (params?: {
  worker_id?: string;
  ticket_id?: string;
  limit?: number;
}) => {
  const q: Record<string, string> = {};
  if (params?.worker_id) q.worker_id = params.worker_id;
  if (params?.ticket_id) q.ticket_id = params.ticket_id;
  if (params?.limit != null) q.limit = String(params.limit);
  return api.get<AgentPrListOut>(BASE, q);
};

export const getPr = (prId: string) => api.get<AgentPr>(`${BASE}/${prId}`);

export const getPrsForTicket = (ticketId: string) =>
  api.get<AgentPrListOut>(`${BASE}/ticket/${ticketId}`);

// ─── Work completion ───────────────────────────────────────────

export const completeWork = (workerId: string, ticketId: string) =>
  api.post<AgentCompletion>(`${BASE}/${workerId}/complete`, {
    ticket_id: ticketId,
  });

// ─── Status flow config ────────────────────────────────────────

export const getStatusFlow = (agentType: string) =>
  api.get<StatusFlowConfig>(`${BASE}/status-flow/${agentType}`);

export const setStatusFlow = (agentType: string, body: StatusFlowUpdateIn) =>
  api.put<StatusFlowConfig>(`${BASE}/status-flow/${agentType}`, body);

// ─── Admin ─────────────────────────────────────────────────────

export const listAllPrs = (limit = 200) =>
  api.get<AgentPrListOut>(`/ui/admin/agent/prs`, { limit: String(limit) });
