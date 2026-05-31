import { api } from "@/api/client";
import type {
  AgentIdentity,
  AgentIdentityUpdate,
  ProjectContext,
  ProjectContextUpdate,
  MemoryEntry,
  MemoryEntryCreate,
  MemoryEntryUpdate,
  MemoryListOut,
  FullContextOut,
  MemoryExport,
  MemoryImportIn,
  MemoryImportOut,
  MemoryTemplate,
} from "@/api/types";

const BASE = "/ui/agent/memory";

// ─── Identity ──────────────────────────────────────────────────

export const getIdentity = (workerId: string) =>
  api.get<AgentIdentity>(`${BASE}/${workerId}/identity`);

export const updateIdentity = (workerId: string, body: AgentIdentityUpdate) =>
  api.put<AgentIdentity>(`${BASE}/${workerId}/identity`, body);

// ─── Project Context ───────────────────────────────────────────

export const getProjectContext = (workerId: string) =>
  api.get<ProjectContext>(`${BASE}/${workerId}/project`);

export const updateProjectContext = (
  workerId: string,
  body: ProjectContextUpdate,
) => api.put<ProjectContext>(`${BASE}/${workerId}/project`, body);

// ─── Memory Entries ────────────────────────────────────────────

export const listEntries = (workerId: string, category?: string) => {
  const params: Record<string, string> = {};
  if (category) params["category"] = category;
  return api.get<MemoryListOut>(`${BASE}/${workerId}/entries`, params);
};

export const addEntry = (workerId: string, body: MemoryEntryCreate) =>
  api.post<MemoryEntry>(`${BASE}/${workerId}/entries`, body);

export const updateEntry = (
  workerId: string,
  memoryId: string,
  body: MemoryEntryUpdate,
) => api.put<MemoryEntry>(`${BASE}/${workerId}/entries/${memoryId}`, body);

export const deleteEntry = (workerId: string, memoryId: string) =>
  api.del(`${BASE}/${workerId}/entries/${memoryId}`);

// ─── Full Context ──────────────────────────────────────────────

export const getFullContext = (workerId: string) =>
  api.get<FullContextOut>(`${BASE}/${workerId}/full-context`);

// ─── Export / Import ───────────────────────────────────────────

export const exportMemory = (workerId: string) =>
  api.get<MemoryExport>(`${BASE}/${workerId}/export`);

export const importMemory = (workerId: string, body: MemoryImportIn) =>
  api.post<MemoryImportOut>(`${BASE}/${workerId}/import`, body);

// ─── Templates ─────────────────────────────────────────────────

export const listTemplates = () =>
  api.get<MemoryTemplate[]>(`${BASE}/templates`);
