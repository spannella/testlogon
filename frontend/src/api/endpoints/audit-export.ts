import { api } from "@/api/client";

export interface AuditExportCreateReq {
  categories: string[];
  format: string;
  from_date: number;
  to_date: number;
  actor_user_id?: string;
  target_user_id?: string;
  event_actions?: string[];
}

export interface AuditExportOut {
  export_id: string;
  status: string;
  categories: string[];
  format: string;
  from_date: number;
  to_date: number;
  event_count: number | null;
  file_size_bytes: number | null;
  download_url: string | null;
  download_expires_at: number | null;
  manifest_sha256: string | null;
  created_at: number;
  created_by: string;
  completed_at: number | null;
  error_message: string | null;
  events_scanned: number | null;
  events_written: number | null;
}

export const createAuditExport = (body: AuditExportCreateReq) =>
  api.post<AuditExportOut>("/ui/admin/audit-exports", body);

export const listAuditExports = () =>
  api.get<{ exports: AuditExportOut[] }>("/ui/admin/audit-exports");

export const getAuditExport = (exportId: string) =>
  api.get<AuditExportOut>(`/ui/admin/audit-exports/${exportId}`);

export const downloadAuditExport = (exportId: string) =>
  api.get<string>(`/ui/admin/audit-exports/${exportId}/download`);
