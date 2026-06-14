import { api } from "@/api/client";

// ─── EVT-011..013: CRM Document Library (file_manager CRM metadata) ──────────
//
// The backend exposes CRM document metadata + search as additive endpoints on
// the existing file-manager router (`/v1/fs`), gated by the
// `crm_document_library_enabled` flag (default OFF → both new endpoints return
// 404). See docs/suitecrm/specs/EVT-011.md and app/routers/filemanager.py.
//
// All TS types are defined inline here (RULE-3: do NOT touch shared api/types.ts).

/** Valid CRM record types a document may be linked to. Mirrors
 *  `app/services/filemanager.py::_LINKED_RECORD_TYPES`. */
export const LINKED_RECORD_TYPES = ["contact", "ticket", "account", "party"] as const;
export type LinkedRecordType = (typeof LINKED_RECORD_TYPES)[number];

/** CRM metadata projection returned by the two new endpoints
 *  (CrmMetadataOut in app/routers/filemanager.py). */
export interface CrmDocumentMetadata {
  path: string;
  crm_category: string | null;
  crm_description: string | null;
  linked_record_type: string | null;
  linked_record_id: string | null;
  crm_metadata_updated_at: string | null;
}

/** Search response (CrmSearchOut). `cursor` is a base64 LastEvaluatedKey or null. */
export interface CrmDocumentSearchResp {
  items: CrmDocumentMetadata[];
  cursor: string | null;
  count: number;
}

/** PATCH body for /v1/fs/crm-metadata (CrmMetadataIn).
 *  Omitting a field clears it (write-exactly-what-you-send semantics);
 *  linked_record_type + linked_record_id are an atomic pair. */
export interface CrmMetadataIn {
  crm_category?: string | null;
  crm_description?: string | null;
  linked_record_type?: string | null;
  linked_record_id?: string | null;
}

/** Subset of GET /v1/fs/info we display in the document detail view. */
export interface FileInfo {
  path: string;
  type: string;
  name: string;
  parent: string | null;
  created_at: string | null;
  updated_at: string | null;
  upload_at: string | null;
  upload_by: string | null;
  last_download_at: string | null;
  last_download_by: string | null;
  size: number | null;
  content_type: string | null;
  shared: boolean;
  duration_seconds?: number | null;
  thumbnail?: string | null;
}

/** A single entry in a folder listing (GET /v1/fs/list items[]). */
export interface FileListEntry {
  path: string;
  type: string; // "file" | "folder"
  name: string;
  size: number | null;
  updated_at: string | null;
  content_type?: string | null;
}

export interface FileListResp {
  path: string;
  items: FileListEntry[];
  cursor: string | null;
}

export interface UploadResp {
  ok: boolean;
  path: string;
  name?: string;
  size?: number;
  content_type?: string;
  [k: string]: unknown;
}

// ─── CRM metadata (EVT-011) ─────────────────────────────────────────────────

/** Write or clear CRM metadata on a file node (PATCH /v1/fs/crm-metadata). */
export const updateCrmMetadata = (path: string, body: CrmMetadataIn) =>
  api.patch<CrmDocumentMetadata>(
    `/v1/fs/crm-metadata?path=${encodeURIComponent(path)}`,
    body,
  );

/** Search the caller's documents linked to a CRM record. */
export const searchCrmDocuments = (params: {
  linked_record_type: string;
  linked_record_id: string;
  limit?: number;
  cursor?: string;
}) => {
  const p: Record<string, string> = {
    linked_record_type: params.linked_record_type,
    linked_record_id: params.linked_record_id,
  };
  if (params.limit) p["limit"] = String(params.limit);
  if (params.cursor) p["cursor"] = params.cursor;
  return api.get<CrmDocumentSearchResp>("/v1/fs/crm-search", p);
};

// ─── File-manager primitives reused by the CRM document UI ──────────────────

/** List files/folders under a path (GET /v1/fs/list). */
export const listFiles = (params?: {
  path?: string;
  limit?: number;
  cursor?: string;
  sort_by?: "name" | "updated" | "size";
  sort_dir?: "asc" | "desc";
}) => {
  const p: Record<string, string> = {};
  if (params?.path) p["path"] = params.path;
  if (params?.limit) p["limit"] = String(params.limit);
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.sort_by) p["sort_by"] = params.sort_by;
  if (params?.sort_dir) p["sort_dir"] = params.sort_dir;
  return api.get<FileListResp>("/v1/fs/list", p);
};

/** Fetch a single file node's info (GET /v1/fs/info). */
export const getFileInfo = (path: string) =>
  api.get<FileInfo>("/v1/fs/info", { path });

/** Upload a file to the given path (POST /v1/fs/upload, multipart). */
export const uploadFile = (path: string, file: File, overwrite = false) => {
  const fd = new FormData();
  fd.append("file", file);
  return api.upload<UploadResp>(
    `/v1/fs/upload?path=${encodeURIComponent(path)}&overwrite=${overwrite ? "true" : "false"}`,
    fd,
  );
};

/** Download URL for a file node (GET /v1/fs/download). */
export const fileDownloadUrl = (path: string) =>
  `/v1/fs/download?path=${encodeURIComponent(path)}`;
