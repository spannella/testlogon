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
