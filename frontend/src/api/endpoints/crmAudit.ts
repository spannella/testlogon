import { api } from "@/api/client";

// ─── EVT-015: CRM Audit Log Browse ───────────────────────────────
// LIVE backend: app/routers/audit_export.py (browse_router)
//   prefix = /ui/admin
//   GET /audit-log   (require_ui_session + ROOT-only)
//     query: category (required), from_ts (required), to_ts (required),
//            user_sub?, event_type?, limit (1..200), cursor?
//   Returns the raw service dict (see browse_audit_log()):
//     { items, cursor, total_scanned, category, from_ts, to_ts }
// Feature flag CRM_AUDIT_LOG_BROWSE_ENABLED defaults OFF -> 404.
// Each item is a UnifiedAuditEvent.to_ndjson_dict() — None fields omitted.

export type AuditCategory =
  | "auth"
  | "moderation"
  | "broadcast"
  | "admin"
  | "billing";

export const AUDIT_CATEGORIES: AuditCategory[] = [
  "auth",
  "moderation",
  "broadcast",
  "admin",
  "billing",
];

export interface AuditEventItem {
  event_id?: string;
  event_type?: string;
  event_action?: string;
  timestamp?: string;
  timestamp_unix?: number;
  actor_user_id?: string;
  actor_role?: string;
  actor_ip?: string;
  actor_user_agent?: string;
  target_user_id?: string;
  target_resource_type?: string;
  target_resource_id?: string;
  outcome?: string;
  metadata?: Record<string, unknown>;
  source_table?: string;
  tenant_id?: string;
  impersonation_context?: Record<string, unknown> | null;
  // tolerate any extra fields surfaced by the adapter
  [key: string]: unknown;
}

export interface AuditLogBrowseOut {
  items: AuditEventItem[];
  cursor: string | null;
  total_scanned: number;
  category: string;
  from_ts: number;
  to_ts: number;
}

export interface BrowseAuditLogParams {
  category: AuditCategory;
  from_ts: number;
  to_ts: number;
  user_sub?: string;
  event_type?: string;
  limit?: number;
  cursor?: string;
}

export const browseAuditLog = (p: BrowseAuditLogParams) => {
  const params: Record<string, string> = {
    category: p.category,
    from_ts: String(p.from_ts),
    to_ts: String(p.to_ts),
  };
  if (p.user_sub?.trim()) params["user_sub"] = p.user_sub.trim();
  if (p.event_type?.trim()) params["event_type"] = p.event_type.trim();
  if (p.limit) params["limit"] = String(p.limit);
  if (p.cursor) params["cursor"] = p.cursor;
  return api.get<AuditLogBrowseOut>("/ui/admin/audit-log", params);
};
