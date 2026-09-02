import { api } from "@/api/client";
import type { FileListResp, FileEntry, ShareFileReq, SharedItem, OkResp, FileEncryptionMetadata, UsageSummaryResp, UsageDailyResp, UsageStorageResp, SftpMountSummary, MountMockFilesResp } from "@/api/types";

export const listFiles = (
  path = "/",
  opts?: { limit?: number; cursor?: string; sort_by?: string; sort_dir?: string },
) => {
  const params: Record<string, string> = { path };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.sort_by) params["sort_by"] = opts.sort_by;
  if (opts?.sort_dir) params["sort_dir"] = opts.sort_dir;
  return api.get<FileListResp>("/v1/fs/list", params);
};

export const getFileInfo = (path: string) =>
  api.get<FileEntry>("/v1/fs/info", { path });

export const searchFiles = (prefix: string, limit = 50) =>
  api.get<{ prefix: string; results: FileEntry[] }>("/v1/fs/search", {
    prefix,
    limit: String(limit),
  });

export const searchText = (q: string, limit = 50) =>
  api.get<{ query: string; results: FileEntry[] }>("/v1/fs/search-text", {
    q,
    limit: String(limit),
  });

export const createFolder = (path: string) =>
  api.post<OkResp>("/v1/fs/folder", { path });


type ICloudInitiateReq = {
  mount_path: string;
  apple_id: string;
  auth_mode: "session_token" | "app_password";
  auth_value: string;
  device_label?: string | null;
};

type ICloudInitiateResp = {
  onboarding_session_id: string;
  mount_id: string;
  status: string;
  next_action: string;
  expires_at: string;
};

type ICloudVerifyReq = {
  onboarding_session_id: string;
  mfa_code?: string;
};

type ICloudVerifyResp = {
  onboarding_session_id: string;
  mount_id: string;
  status: string;
  next_action: string;
  outcome: "mfa_required" | "auth_failed" | "active";
};

export const initiateICloudMount = (body: ICloudInitiateReq) =>
  api.post<ICloudInitiateResp>("/v1/fs/mounts/icloud/initiate", body);

export const verifyICloudMount = (body: ICloudVerifyReq) =>
  api.post<ICloudVerifyResp>("/v1/fs/mounts/icloud/verify", body);


export type FileMount = {
  mount_id: string;
  provider: string;
  mount_path: string;
  status: string;
  updated_at?: string | null;
  can_rotate: boolean;
  can_reconnect: boolean;
  can_disconnect: boolean;
};

export type ICloudRotateReq = {
  mount_id: string;
  auth_mode: "session_token" | "app_password";
  auth_value: string;
  device_label?: string | null;
};

export type ICloudRotateResp = {
  mount_id: string;
  secret_ref: string;
  status: string;
};

export type ICloudRevokeReq = {
  mount_id: string;
};

export type ICloudRevokeResp = {
  mount_id: string;
  status: string;
  sessions_cleared: number;
};

export const listMounts = () => api.get<FileMount[]>("/v1/fs/mounts");

export const rotateICloudMount = (body: ICloudRotateReq) =>
  api.post<ICloudRotateResp>("/v1/fs/mounts/icloud/rotate", body);

export const revokeICloudMount = (body: ICloudRevokeReq) =>
  api.post<ICloudRevokeResp>("/v1/fs/mounts/icloud/revoke", body);

// ── Generic mount management (SFTP / Drive / OneDrive / S3) ──────────
// Mirrors app/routers/filemanager.py:
//   • S3-style FileMount CRUD  (POST/PATCH/DELETE /v1/fs/mounts, /validate)
//   • host-based provider mounts (POST /v1/fs/mounts/{id}/test,
//                                 POST /v1/fs/mounts/{id}/rotate-credential,
//                                 POST /v1/fs/mounts/sftp)
// All calls degrade gracefully on 404 (feature not enabled) at the call site.

export type FileMountRecord = {
  id: string;
  owner: string;
  provider?: string;
  mount_path?: string;
  bucket?: string;
  prefix?: string | null;
  mode?: string;
  auth_ref?: string;
  status: string;
  created_at?: string;
  updated_at?: string;
  last_check_at?: string | null;
  last_error?: string | null;
};

export type FileMountCreateBody = {
  mount_path: string;
  bucket: string;
  prefix?: string | null;
  mode?: "read_only" | "read_write";
  auth_ref: string;
  status?: "active" | "degraded" | "error" | "disabled";
};

export type FileMountUpdateBody = Partial<FileMountCreateBody>;

// S3-style object-store mount CRUD ------------------------------------
export const createFileMount = (body: FileMountCreateBody) =>
  api.post<FileMountRecord>("/v1/fs/mounts", body);

export const updateFileMount = (mountId: string, body: FileMountUpdateBody) =>
  api.patch<FileMountRecord>(`/v1/fs/mounts/${encodeURIComponent(mountId)}`, body);

export const deleteFileMount = (mountId: string) =>
  api.del<{ ok: boolean; deleted: boolean }>(`/v1/fs/mounts/${encodeURIComponent(mountId)}`);

export const validateFileMount = (mountId: string) =>
  api.post<{ ok: boolean; mount_id: string; status: string }>(
    `/v1/fs/mounts/${encodeURIComponent(mountId)}/validate`,
  );

// Host-based (SFTP/SCP/FTP) provider mount management -----------------
export type SftpMountApi = {
  id: string;
  owner: string;
  protocol: string;
  host: string;
  port: number;
  auth_credential_ref: string;
  remote_root: string;
  read_only: boolean;
  status: string;
  created_at?: string;
  updated_at?: string;
  last_tested_at?: string | null;
  last_status_change_at?: string | null;
  last_error_code?: string | null;
  last_error_message?: string | null;
};

export type SftpMountCreateBody = {
  protocol?: "sftp" | "scp" | "ftp";
  host: string;
  port?: number;
  auth_credential_ref: string;
  remote_root: string;
  read_only?: boolean;
};

export type SftpMountUpdateBody = {
  protocol?: "sftp" | "scp" | "ftp";
  host?: string;
  port?: number;
  auth_credential_ref?: string;
  remote_root?: string;
  read_only?: boolean;
  status?: "healthy" | "degraded" | "auth_failed" | "unreachable" | "disabled";
};

export type SftpRotateCredentialBody = {
  auth_mode: "password" | "private_key";
  username: string;
  password?: string | null;
  private_key?: string | null;
  private_key_passphrase?: string | null;
  auth_credential_ref?: string | null;
};

export const createSftpMount = (body: SftpMountCreateBody) =>
  api.post<{ ok: boolean; mount: SftpMountApi }>("/v1/fs/mounts/sftp", body);

export const updateSftpMount = (mountId: string, body: SftpMountUpdateBody) =>
  api.patch<{ ok: boolean; mount: SftpMountApi }>(
    `/v1/fs/mounts/${encodeURIComponent(mountId)}`,
    body,
  );

export const deleteSftpMount = (mountId: string) =>
  api.del<{ ok: boolean; mount_id: string }>(`/v1/fs/mounts/${encodeURIComponent(mountId)}`);

export const testMount = (mountId: string) =>
  api.post<{ ok: boolean; mount: SftpMountApi }>(
    `/v1/fs/mounts/${encodeURIComponent(mountId)}/test`,
  );

export const rotateMountCredential = (mountId: string, body: SftpRotateCredentialBody) =>
  api.post<{ ok: boolean; mount: SftpMountApi; auth_credential_ref: string }>(
    `/v1/fs/mounts/${encodeURIComponent(mountId)}/rotate-credential`,
    body,
  );

export const uploadFile = (
  file: File,
  path: string,
  opts?: { encrypted?: boolean; encMeta?: FileEncryptionMetadata | null },
) => {
  const formData = new FormData();
  formData.append("file", file);
  const params: Record<string, string> = { path };
  if (opts?.encrypted) {
    params.encrypted = "true";
    params.enc_meta = JSON.stringify(opts.encMeta ?? {});
  }
  return api.upload<{ ok: boolean; path: string; size: number }>("/v1/fs/upload", formData, params);
};

export interface BatchUploadResult {
  uploaded: Array<{ path: string; name: string; size: number }>;
  failed: Array<{ name: string; error: string }>;
}

export const batchUpload = (files: File[], targetPath: string) => {
  const formData = new FormData();
  for (const file of files) {
    formData.append("files", file);
  }
  return api.upload<BatchUploadResult>(`/v1/fs/batch-upload?target_path=${encodeURIComponent(targetPath)}`, formData);
};

export const deleteFile = (path: string) =>
  api.del<OkResp>("/v1/fs/file", { path });

export const deleteFolder = (path: string) =>
  api.del<{ ok: boolean; deleted_count: number }>("/v1/fs/folder", { path });

export const moveFile = (src: string, dst: string) =>
  api.post<{ ok: boolean; src: string; dst: string }>("/v1/fs/move", { src, dst });

export const renameFile = (path: string, newName: string) =>
  api.post<{ ok: boolean; src: string; dst: string }>("/v1/fs/rename-file", { path, new_name: newName });

export const renameFolder = (path: string, newName: string) =>
  api.post<{ ok: boolean; src: string; dst: string }>("/v1/fs/rename-folder", { path, new_name: newName });

export const shareFile = (body: ShareFileReq) =>
  api.post<OkResp>("/v1/fs/share", body);

export const unshareFile = (path: string, toUser: string) =>
  api.post<OkResp>("/v1/fs/unshare", { path, to_user: toUser });

export const getSharedWith = (path: string) =>
  api.get<{ path: string; shared_with: { user_id: string; permission: string }[] }>(
    "/v1/fs/shared-with",
    { path },
  );

export const downloadUrl = (path: string) =>
  `/v1/fs/download?path=${encodeURIComponent(path)}`;


export const getUsageSummary = (period?: string) =>
  api.get<UsageSummaryResp>("/v1/fs/usage/summary", period ? { period } : undefined);

export const getUsageDaily = (opts?: { from?: string; to?: string }) =>
  api.get<UsageDailyResp>("/v1/fs/usage/daily", {
    ...(opts?.from ? { from: opts.from } : {}),
    ...(opts?.to ? { to: opts.to } : {}),
  });

export const getUsageStorage = (topN?: number) =>
  api.get<UsageStorageResp>("/v1/fs/usage/storage", topN ? { top_n: String(topN) } : undefined);

// ── Preview & Thumbnail URLs ────────────────────────────────────

export const previewUrl = (path: string) =>
  `/v1/fs/preview?path=${encodeURIComponent(path)}`;

export const sharedPreviewUrl = (owner: string, path: string) =>
  `/v1/fs/shared-preview?owner=${encodeURIComponent(owner)}&path=${encodeURIComponent(path)}`;

export const thumbnailUrl = (path: string) =>
  `/v1/fs/thumbnail?path=${encodeURIComponent(path)}`;

// ── Shared With Me ──────────────────────────────────────────────

export const getSharedWithMe = () =>
  api.get<{ items: SharedItem[] }>("/v1/fs/shared-with-me");

export const listSharedFolder = (
  owner: string,
  path = "/",
  opts?: { limit?: number; cursor?: string; sort_by?: string; sort_dir?: string },
) => {
  const params: Record<string, string> = { owner, path };
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.sort_by) params["sort_by"] = opts.sort_by;
  if (opts?.sort_dir) params["sort_dir"] = opts.sort_dir;
  return api.get<{ path: string; items: FileEntry[]; cursor?: string }>("/v1/fs/shared-list", params);
};

export const sharedDownloadUrl = (owner: string, path: string) =>
  `/v1/fs/shared-download?owner=${encodeURIComponent(owner)}&path=${encodeURIComponent(path)}`;

export const getSharedFileInfo = (owner: string, path: string) =>
  api.get<FileEntry>("/v1/fs/shared-info", { owner, path });

// ── Bulk & Advanced ─────────────────────────────────────────────

export const downloadZip = async (paths: string[]) => {
  const resp = await fetch("/v1/fs/download-zip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paths }),
    credentials: "include",
  });
  if (!resp.ok) throw new Error("Failed to download ZIP");
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "files.zip";
  a.click();
  URL.revokeObjectURL(url);
};

export const uploadZip = (file: File, destFolder = "/") => {
  const formData = new FormData();
  formData.append("zip_file", file);
  return api.upload<{ ok: boolean; created: string[]; count: number }>(
    "/v1/fs/upload-zip",
    formData,
    { dest_folder: destFolder },
  );
};

export const fsPresignUpload = (path: string, contentType?: string) =>
  api.post<{
    upload_url: string;
    bucket: string;
    key: string;
    ticket_id: string;
    path: string;
    content_type: string;
  }>("/v1/fs/presign-upload", {
    path,
    content_type: contentType ?? null,
  });

export const completeUpload = (
  path: string,
  key: string,
  ticketId: string,
  contentType?: string,
  opts?: { encrypted?: boolean; encMeta?: FileEncryptionMetadata | null },
) =>
  api.post<{ ok: boolean; path: string; size: number | null; content_type: string }>(
    "/v1/fs/complete-upload",
    {
      path,
      key,
      ticket_id: ticketId,
      content_type: contentType ?? null,
      encrypted: !!opts?.encrypted,
      enc_meta: opts?.encrypted ? (opts.encMeta ?? {}) : null,
    },
  );

export const purgeDeleted = () =>
  api.post<{ ok: boolean; purged: number; skipped: number; errors: number }>(
    "/v1/fs/purge-deleted",
  );

export const emitFileCryptoTelemetry = (body: {
  event: "decrypt_failure" | "remembered_password_used";
  path?: string;
  reason?: "wrong_password" | "corrupted_metadata" | "crypto_error";
  remembered_password_used?: boolean;
}) => api.post<{ ok: boolean }>("/v1/fs/client-telemetry", body);


export const emitFilePreviewTelemetry = (body: {
  event: "hover_play_start" | "hover_play_failure";
  path?: string;
  reason?: "playback_error" | "autoplay_blocked" | "unsupported_capability" | "unknown";
}) => api.post<{ ok: boolean }>("/v1/fs/client-telemetry", body);


export const listSftpMounts = () =>
  api.get<{ items: SftpMountSummary[] }>("/v1/fs/mounts");

export const listMountMockFiles = (
  mountId: string,
  opts?: { path?: string; limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {
    path: opts?.path ?? "/",
    limit: String(opts?.limit ?? 200),
  };
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<MountMockFilesResp>(`/v1/fs/mounts/${encodeURIComponent(mountId)}/mock-files`, params);
};
