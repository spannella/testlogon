import { api } from "@/api/client";
import type {
  ConnectionProfile,
  ConnectionProfileList,
  CreateConnectionProfileInput,
  UpdateConnectionProfileInput,
  QuickConnectResult,
} from "@/api/types";

const BASE = "/ui/compute/connection-profiles";

export const connectionProfilesApi = {
  list: () => api.get<ConnectionProfileList>(BASE),
  get: (id: string) => api.get<ConnectionProfile>(`${BASE}/${id}`),
  create: (body: CreateConnectionProfileInput) =>
    api.post<ConnectionProfile>(BASE, body),
  update: (id: string, body: UpdateConnectionProfileInput) =>
    api.patch<ConnectionProfile>(`${BASE}/${id}`, body),
  delete: (id: string) => api.del(`${BASE}/${id}`),
  quickConnect: (id: string) =>
    api.post<QuickConnectResult>(`${BASE}/${id}/quick-connect`),
};
