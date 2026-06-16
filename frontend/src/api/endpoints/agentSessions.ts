import { api } from "@/api/client";
import type {
  AgentSession,
  AgentSessionList,
  CreateAgentSessionIn,
} from "@/api/types";

// Interactive Claude Code session REST wrappers (ACS-009). Nested under the
// agent-workers router; all flag-gated server-side (404 when the feature is
// off). The actual live terminal traffic flows over the WS at
// AgentSession.ws_path (/api/agent-session/ws), NOT these REST routes.
const BASE = "/ui/agent/workers";

export const createAgentSession = (
  workerId: string,
  body: CreateAgentSessionIn = {},
) =>
  api.post<AgentSession>(`${BASE}/${workerId}/sessions`, {
    cols: body.cols ?? 80,
    rows: body.rows ?? 24,
  });

export const listAgentSessions = (workerId: string) =>
  api.get<AgentSessionList>(`${BASE}/${workerId}/sessions`);

export const getAgentSession = (workerId: string, sessionId: string) =>
  api.get<AgentSession>(`${BASE}/${workerId}/sessions/${sessionId}`);

export const stopAgentSession = (workerId: string, sessionId: string) =>
  api.post<AgentSession>(`${BASE}/${workerId}/sessions/${sessionId}/stop`, {});
