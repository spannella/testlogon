import { api } from "@/api/client";
import type {
  CreateHostInput,
  HostGroupListOut,
  HostHistoryOut,
  HostListOut,
  HostOut,
  HostQuickConnectOut,
  ImportHostsResult,
  ListHostsParams,
  UpdateHostInput,
} from "@/api/types";

const BASE = "/ui/hosts";

function toParams(p?: ListHostsParams): Record<string, string> | undefined {
  if (!p) return undefined;
  const out: Record<string, string> = {};
  if (p.protocol) out.protocol = p.protocol;
  if (p.group) out.group = p.group;
  if (p.sort_by) out.sort_by = p.sort_by;
  if (p.limit != null) out.limit = String(p.limit);
  if (p.cursor) out.cursor = p.cursor;
  return out;
}

export const hostInventoryApi = {
  list: (params?: ListHostsParams) =>
    api.get<HostListOut>(BASE, toParams(params)),
  get: (id: string) => api.get<HostOut>(`${BASE}/${id}`),
  create: (body: CreateHostInput) => api.post<HostOut>(BASE, body),
  update: (id: string, body: UpdateHostInput) =>
    api.patch<HostOut>(`${BASE}/${id}`, body),
  delete: (id: string) => api.del<{ ok: boolean }>(`${BASE}/${id}`),
  importCsv: (csv_content: string) =>
    api.post<ImportHostsResult>(`${BASE}/import`, { csv_content }),
  groups: () => api.get<HostGroupListOut>(`${BASE}/groups`),
  history: (id: string) => api.get<HostHistoryOut>(`${BASE}/${id}/history`),
  recordConnection: (id: string) =>
    api.post<HostOut>(`${BASE}/${id}/record-connection`),
  quickConnect: (id: string) =>
    api.post<HostQuickConnectOut>(`${BASE}/${id}/quick-connect`),
};
