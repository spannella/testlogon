import { api } from "@/api/client";
import type {
  CreateSshBastionPathIn,
  SshBastionPathListOut,
  SshBastionPathOut,
  SshBastionResolvedOut,
  UpdateSshBastionPathIn,
} from "@/api/types";

const BASE = "/ui/compute/bastion";

export const listBastionPaths = () =>
  api.get<SshBastionPathListOut>(`${BASE}/paths`);

export const getBastionPath = (pathId: string) =>
  api.get<SshBastionPathOut>(`${BASE}/paths/${pathId}`);

export const resolveBastionPath = (pathId: string) =>
  api.get<SshBastionResolvedOut>(`${BASE}/paths/${pathId}/resolve`);

export const createBastionPath = (body: CreateSshBastionPathIn) =>
  api.post<SshBastionPathOut>(`${BASE}/paths`, body);

export const updateBastionPath = (pathId: string, body: UpdateSshBastionPathIn) =>
  api.patch<SshBastionPathOut>(`${BASE}/paths/${pathId}`, body);

export const deleteBastionPath = (pathId: string) =>
  api.del<void>(`${BASE}/paths/${pathId}`);
