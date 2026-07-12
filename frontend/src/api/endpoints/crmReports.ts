/**
 * CRM Reports & Dashboards (RPT cluster) API wrappers.
 *
 * Mirrors the LIVE backend:
 *   app/routers/crm_reports.py   (prefix /ui/crm)
 *   app/routers/crm_dashboard.py (prefix /ui/crm)
 *   app/services/crm_reports.py + crm_dashboard.py + crm_dashlet_data.py
 *   app/models.py RPT models
 *
 * All endpoints return 404 when the `crm_reports_enabled` flag is OFF.
 * TS interfaces are declared INLINE here (not in shared api/types.ts).
 */
import { api } from "@/api/client";

// ─── Shared enums / literals ─────────────────────────────────────

export type ReportModule =
  | "tickets"
  | "contacts"
  | "billing_ledger"
  | "orders"
  | "subscriptions"
  | "questionnaire_responses";

export type ConditionOperator =
  | "eq"
  | "neq"
  | "contains"
  | "gt"
  | "lt"
  | "gte"
  | "lte"
  | "is_empty"
  | "not_empty";

export type AggregateFunction = "SUM" | "AVG" | "COUNT" | "MIN" | "MAX";

export type ChartType = "bar" | "line" | "pie";

export type ScheduleCadence = "daily" | "weekly" | "monthly";

export type ScheduleFormat = "csv" | "json";

export type DashletType =
  | "recent_tickets"
  | "calendar_today"
  | "my_contacts"
  | "billing_summary"
  | "report"
  | "saved_search";

// ─── Report definition models ────────────────────────────────────

export interface ReportCondition {
  field: string;
  operator: ConditionOperator;
  value?: string | null;
}

export interface AggregateSpec {
  field: string;
  function: AggregateFunction;
}

export interface ChartConfig {
  chart_type: ChartType;
  x_field: string;
  y_field: string;
}

export interface ReportOut {
  report_id: string;
  name: string;
  description?: string | null;
  module: ReportModule;
  fields: string[];
  conditions: ReportCondition[];
  group_by?: string | null;
  aggregates: AggregateSpec[];
  chart?: ChartConfig | null;
  owner_sub: string;
  created_at: number;
  updated_at: number;
}

export interface ReportListOut {
  reports: ReportOut[];
  next_cursor?: string | null;
}

export interface ReportRunOut {
  report_id: string;
  run_id: string;
  run_at: number;
  status: string;
  row_count: number;
  columns: string[];
  rows: Array<Array<unknown>>;
  error_msg?: string | null;
  chart?: ChartConfig | null;
}

export interface ReportCreateIn {
  name: string;
  description?: string | null;
  module: ReportModule;
  fields: string[];
  conditions?: ReportCondition[];
  group_by?: string | null;
  aggregates?: AggregateSpec[];
  chart?: ChartConfig | null;
}

export interface ReportUpdateIn {
  name?: string;
  description?: string | null;
  fields?: string[];
  conditions?: ReportCondition[];
  group_by?: string | null;
  aggregates?: AggregateSpec[];
  chart?: ChartConfig | null;
}

// ─── Schedule models (RPT-004) ───────────────────────────────────

export interface ReportScheduleOut {
  schedule_id: string;
  report_id: string;
  owner_sub: string;
  cadence: ScheduleCadence;
  recipients: string[];
  format: ScheduleFormat;
  enabled: boolean;
  created_at: number;
  next_run_at: number;
  last_run_at?: number | null;
  last_run_id?: string | null;
}

export interface ReportScheduleListOut {
  schedules: ReportScheduleOut[];
  cursor?: string | null;
}

export interface ReportScheduleCreateIn {
  cadence: ScheduleCadence;
  recipients: string[];
  format?: ScheduleFormat;
}

export interface ReportScheduleUpdateIn {
  cadence?: ScheduleCadence;
  recipients?: string[];
  format?: ScheduleFormat;
  enabled?: boolean;
}

// ─── Dashboard models (RPT-006 / RPT-007) ────────────────────────

export interface DashletConfigOut {
  dashlet_id: string;
  dashlet_type: DashletType;
  title: string;
  config: Record<string, unknown>;
}

export interface DashboardOut {
  dashboard_id: string;
  name: string;
  owner_sub: string;
  dashlets: DashletConfigOut[];
  created_at: number;
  updated_at: number;
}

export interface DashletAddIn {
  dashlet_type: DashletType;
  title: string;
  config?: Record<string, unknown>;
}

export interface DashboardUpdateIn {
  name?: string;
  dashlets?: Array<{ dashlet_type: DashletType; title: string; config?: Record<string, unknown> }>;
}

export interface DashletDataOut {
  dashlet_id: string;
  dashlet_type: DashletType;
  fetched_at: number;
  data: Record<string, unknown>;
}

// ─── Reports endpoints ───────────────────────────────────────────

export const listReports = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<ReportListOut>("/ui/crm/reports", params);
};

export const getReport = (reportId: string) =>
  api.get<ReportOut>(`/ui/crm/reports/${encodeURIComponent(reportId)}`);

export const createReport = (body: ReportCreateIn) =>
  api.post<ReportOut>("/ui/crm/reports", body);

export const updateReport = (reportId: string, body: ReportUpdateIn) =>
  api.patch<ReportOut>(`/ui/crm/reports/${encodeURIComponent(reportId)}`, body);

export const deleteReport = (reportId: string) =>
  api.del<{ ok: boolean }>(`/ui/crm/reports/${encodeURIComponent(reportId)}`);

export const runReport = (reportId: string) =>
  api.post<ReportRunOut>(`/ui/crm/reports/${encodeURIComponent(reportId)}/run`, {});

// ─── Schedule endpoints (RPT-004) ────────────────────────────────

export const listSchedules = (reportId: string, cursor?: string) => {
  const params: Record<string, string> = {};
  if (cursor) params["cursor"] = cursor;
  return api.get<ReportScheduleListOut>(
    `/ui/crm/reports/${encodeURIComponent(reportId)}/schedules`,
    params,
  );
};

export const createSchedule = (reportId: string, body: ReportScheduleCreateIn) =>
  api.post<ReportScheduleOut>(
    `/ui/crm/reports/${encodeURIComponent(reportId)}/schedules`,
    body,
  );

export const updateSchedule = (reportId: string, sid: string, body: ReportScheduleUpdateIn) =>
  api.patch<ReportScheduleOut>(
    `/ui/crm/reports/${encodeURIComponent(reportId)}/schedules/${encodeURIComponent(sid)}`,
    body,
  );

export const deleteSchedule = (reportId: string, sid: string) =>
  api.del<{ ok: boolean }>(
    `/ui/crm/reports/${encodeURIComponent(reportId)}/schedules/${encodeURIComponent(sid)}`,
  );

// ─── Dashboard endpoints (RPT-006 / RPT-007) ─────────────────────

export const getDashboard = () => api.get<DashboardOut>("/ui/crm/dashboard");

export const updateDashboard = (body: DashboardUpdateIn) =>
  api.patch<DashboardOut>("/ui/crm/dashboard", body);

export const addDashlet = (body: DashletAddIn) =>
  api.post<DashboardOut>("/ui/crm/dashboard/dashlets", body);

export const reorderDashlets = (dashletIds: string[]) =>
  api.post<DashboardOut>("/ui/crm/dashboard/dashlets/reorder", { dashlet_ids: dashletIds });

export const removeDashlet = (dashletId: string) =>
  api.del<DashboardOut>(`/ui/crm/dashboard/dashlets/${encodeURIComponent(dashletId)}`);

export const getDashletData = (dashletId: string) =>
  api.get<DashletDataOut>(`/ui/crm/dashboard/dashlets/${encodeURIComponent(dashletId)}/data`);

// ─── Helpers ─────────────────────────────────────────────────────

export const REPORT_MODULES: ReportModule[] = [
  "tickets",
  "contacts",
  "billing_ledger",
  "orders",
  "subscriptions",
  "questionnaire_responses",
];

export const DASHLET_TYPES: DashletType[] = [
  "recent_tickets",
  "calendar_today",
  "my_contacts",
  "billing_summary",
  "report",
  "saved_search",
];
