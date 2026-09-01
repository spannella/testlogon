import { api } from "@/api/client";
import type {
  DeleteProviderCredentialResp,
  DeleteTrackedFileResp,
  ProjectEventListResp,
  ProjectDetailResp,
  Project,
  ProjectCreateReq,
  ProviderCredential,
  ProviderCredentialUpsertReq,
  ProviderOAuthStartResp,
  ProviderOAuthCallbackReq,
  ProjectListResp,
  TrackedFile,
  TrackedFileCreateReq,
  TrackedFileListResp,
  ProjectUpdateReq,
} from "@/api/types";

export const listProjects = (opts?: {
  limit?: number;
  cursor?: string;
  tag?: string;
  nameQuery?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.tag) params.tag = opts.tag;
  if (opts?.nameQuery) params.name_query = opts.nameQuery;
  return api.get<ProjectListResp>("/v1/projects", params);
};

export const createProject = (body: ProjectCreateReq) =>
  api.post<Project>("/v1/projects", body);

export const getProject = (projectId: string) =>
  api.get<Project>(`/v1/projects/${projectId}`);

export const updateProject = (projectId: string, body: ProjectUpdateReq) =>
  api.patch<Project>(`/v1/projects/${projectId}`, body);

export const deleteProject = (projectId: string) =>
  api.del<{ ok: boolean }>(`/v1/projects/${projectId}`);

export const getProjectDetail = (projectId: string, opts?: {
  limit?: number;
  cursor?: string;
  status?: string;
  provider?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.status) params.status = opts.status;
  if (opts?.provider) params.provider = opts.provider;
  return api.get<ProjectDetailResp>(`/v1/projects/${projectId}/detail`, params);
};

export const listTrackedFiles = (projectId: string, opts?: {
  limit?: number;
  cursor?: string;
  status?: string;
  provider?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.status) params.status = opts.status;
  if (opts?.provider) params.provider = opts.provider;
  return api.get<TrackedFileListResp>(`/v1/projects/${projectId}/files`, params);
};

export const addTrackedFile = (projectId: string, body: TrackedFileCreateReq) =>
  api.post<TrackedFile>(`/v1/projects/${projectId}/files`, body);

export const removeTrackedFile = (projectId: string, trackedFileId: string) =>
  api.del<DeleteTrackedFileResp>(`/v1/projects/${projectId}/files/${trackedFileId}`);

export const listProjectEvents = (projectId: string, opts?: {
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  return api.get<ProjectEventListResp>(`/v1/projects/${projectId}/events`, params);
};

export const upsertProviderCredential = (
  provider: string,
  body: ProviderCredentialUpsertReq,
) => api.put<ProviderCredential>(`/v1/projects/providers/${provider}/credentials`, body);

export const getProviderCredential = (provider: string, org?: string) => {
  const params: Record<string, string> = {};
  if (org) params.org = org;
  return api.get<ProviderCredential>(`/v1/projects/providers/${provider}/credentials`, params);
};

export const deleteProviderCredential = (provider: string, org?: string) => {
  const params: Record<string, string> = {};
  if (org) params.org = org;
  return api.del<DeleteProviderCredentialResp>(`/v1/projects/providers/${provider}/credentials`, params);
};

export const startGoogleDriveOauth = () =>
  api.post<ProviderOAuthStartResp>(
    "/v1/projects/providers/google_drive/oauth/start",
  );

export const completeGoogleDriveOauth = (body: ProviderOAuthCallbackReq) =>
  api.post<ProviderCredential>(
    "/v1/projects/providers/google_drive/oauth/callback",
    body,
  );
