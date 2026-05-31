import { api } from "@/api/client";
import type {
  AgentStatus,
  CheckpointData,
  EligibleTicketsResponse,
  TicketFilterConfig,
} from "@/api/types";

const prefix = "/ui/agent/orchestrator";

// -- Status --

export const getAgentStatus = (workerId: string) =>
  api.get<AgentStatus>(`${prefix}/${workerId}/status`);

// -- Loop Control --

export const startAgent = (workerId: string) =>
  api.post<{ ok: boolean; worker_id: string; agent_state: string; message: string }>(
    `${prefix}/${workerId}/start`,
    {},
  );

export const pauseAgent = (workerId: string) =>
  api.post<{ ok: boolean; worker_id: string; agent_state: string; message: string }>(
    `${prefix}/${workerId}/pause`,
    {},
  );

export const resumeAgent = (workerId: string) =>
  api.post<{ ok: boolean; worker_id: string; agent_state: string; message: string }>(
    `${prefix}/${workerId}/resume`,
    {},
  );

export const stopAgent = (workerId: string) =>
  api.post<{ ok: boolean; worker_id: string; agent_state: string; message: string }>(
    `${prefix}/${workerId}/stop`,
    {},
  );

// -- Ticket Operations --

export const releaseTicket = (workerId: string) =>
  api.post<{ ok: boolean; worker_id: string; released_ticket_id: string; agent_state: string }>(
    `${prefix}/${workerId}/release-ticket`,
    {},
  );

export const claimTicket = (workerId: string, ticketId: string) =>
  api.post<Record<string, unknown>>(
    `${prefix}/${workerId}/claim-ticket`,
    { ticket_id: ticketId },
  );

export const completeTicket = (workerId: string, opts?: { summary?: string; pr_url?: string }) =>
  api.post<{ ok: boolean; worker_id: string; completed_ticket_id: string; agent_state: string }>(
    `${prefix}/${workerId}/complete-ticket`,
    opts ?? {},
  );

// -- Checkpoint --

export const getCheckpoint = (workerId: string) =>
  api.get<CheckpointData>(`${prefix}/${workerId}/checkpoint`);

export const saveCheckpoint = (workerId: string, checkpoint: Record<string, unknown>) =>
  api.post<{ ok: boolean; ticket_id: string }>(
    `${prefix}/${workerId}/checkpoint`,
    { checkpoint },
  );

// -- Heartbeat --

export const sendHeartbeat = (workerId: string) =>
  api.post<{ ok: boolean; heartbeat_at: number }>(
    `${prefix}/${workerId}/heartbeat`,
    {},
  );

// -- Eligible Tickets --

export const getEligibleTickets = (workerId: string) =>
  api.get<EligibleTicketsResponse>(`${prefix}/${workerId}/eligible-tickets`);

// -- Ticket Filter --

export const updateTicketFilter = (workerId: string, filter: TicketFilterConfig) =>
  api.put<{ ok: boolean; ticket_filter: TicketFilterConfig }>(
    `${prefix}/${workerId}/ticket-filter`,
    filter,
  );

// -- Worker creation stub --

export const createWorkerStub = (opts: { worker_id?: string; label?: string; agent_type?: string }) =>
  api.post<Record<string, unknown>>(`${prefix}/create-worker`, opts);
