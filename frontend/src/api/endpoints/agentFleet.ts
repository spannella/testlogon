import { api } from "@/api/client";
import type {
  FleetStatus,
  BulkActionResult,
  Capacity,
  WorkerTemplate,
  WorkerTemplateIn,
  WorkerTemplateList,
  Worker,
} from "@/api/types";

const BASE = "/ui/agent/fleet";

// ─── Fleet status & capacity ───────────────────────────────────

export const getFleetStatus = () => api.get<FleetStatus>(`${BASE}/status`);

export const getCapacity = () => api.get<Capacity>(`${BASE}/capacity`);

// ─── Bulk actions ──────────────────────────────────────────────

export const bulkStart = () => api.post<BulkActionResult>(`${BASE}/start-all`, {});

export const bulkStop = () => api.post<BulkActionResult>(`${BASE}/stop-all`, {});

// ─── Templates ─────────────────────────────────────────────────

export const listTemplates = () =>
  api.get<WorkerTemplateList>(`${BASE}/templates`);

export const createTemplate = (body: WorkerTemplateIn) =>
  api.post<WorkerTemplate>(`${BASE}/templates`, body);

export const deleteTemplate = (templateId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/templates/${templateId}`);

export const createFromTemplate = (
  templateId: string,
  label?: string,
) =>
  api.post<Worker>(`${BASE}/templates/${templateId}/create`, label ? { label } : {});
