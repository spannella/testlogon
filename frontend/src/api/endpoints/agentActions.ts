import { api } from "@/api/client";
import type {
  AgentActionListOut,
  AgentActionOut,
  RunAgentActionIn,
} from "@/api/types";

// Agent SSH QA actions (ADR-003 / AQA-006). The whole router is gated behind
// the backend AGENT_SSH_QA_ENABLED flag; with it off these endpoints 404.
const base = (workerId: string) => `/ui/agents/${workerId}/actions`;

export const submitAgentAction = (workerId: string, body: RunAgentActionIn) =>
  api.post<AgentActionOut>(base(workerId), body);

export const listAgentActions = (workerId: string) =>
  api.get<AgentActionListOut>(base(workerId));

export const getAgentAction = (workerId: string, actionId: string) =>
  api.get<AgentActionOut>(`${base(workerId)}/${actionId}`);

export const cancelAgentAction = (workerId: string, actionId: string) =>
  api.post<AgentActionOut>(`${base(workerId)}/${actionId}/cancel`, {});
