import { api } from "@/api/client";
import type { FileListResp, FileEntry, ShareFileReq, OkResp } from "@/api/types";

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

export const uploadFile = (file: File, path: string) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<{ ok: boolean; path: string; size: number }>("/v1/fs/upload", formData, { path });
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
