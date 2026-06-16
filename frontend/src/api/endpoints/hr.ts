import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// OFBiz HR / Payroll (HRM) — endpoint wrappers + inline types.
//
// LIVE backend: app/routers/hr.py (prefix /ui/hr). Admin/root only.
// Feature flags (default OFF): hr_enabled, hr_payroll_enabled. When off the
// backend returns 404 {code: "hr_disabled" | "hr_payroll_disabled"}.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Positions ──────────────────────────────────────────────────────────────

export type PositionStatus = "OPEN" | "FILLED" | "CLOSED";

export interface Position {
  position_id: string;
  title: string;
  department: string | null;
  status: PositionStatus;
  created_at: number;
  updated_at: number;
}

export interface CreatePositionIn {
  title: string;
  department?: string | null;
  correlation_id?: string | null;
}

export interface UpdatePositionStatusIn {
  status: PositionStatus;
}

export interface PositionPage {
  items: Position[];
  next_cursor: string | null;
}

// ─── Employments ──────────────────────────────────────────────────────────────

export type EmploymentStatus = "ACTIVE" | "TERMINATED" | "ON_LEAVE";
export type PayPeriod = "MONTHLY" | "BIWEEKLY" | "WEEKLY" | "HOURLY";

export interface Employment {
  employment_id: string;
  party_id: string;
  position_id: string;
  org_party_id: string;
  status: EmploymentStatus;
  start_date: number;
  end_date: number | null;
  pay_rate_cents: number;
  pay_period: PayPeriod;
  currency: string;
  created_at: number;
  updated_at: number;
}

export interface CreateEmploymentIn {
  party_id: string;
  position_id: string;
  org_party_id: string;
  start_date: number;
  end_date?: number | null;
  pay_rate_cents: number;
  pay_period: PayPeriod;
  currency: string;
  correlation_id?: string | null;
}

export interface TerminateEmploymentIn {
  end_date: number;
  note?: string | null;
}

export interface EmploymentPage {
  items: Employment[];
  next_cursor: string | null;
}

// ─── Payroll ──────────────────────────────────────────────────────────────────

export type PayrollRunStatus = "DRAFT" | "APPROVED" | "POSTED";

export interface PayrollLine {
  employment_id: string;
  party_id: string;
  gross_cents: number;
  currency: string;
}

export interface PayrollRun {
  payroll_run_id: string;
  period_start: number;
  period_end: number;
  status: PayrollRunStatus;
  lines: PayrollLine[];
  created_at: number;
  updated_at: number;
  approved_by: string | null;
  posted_at: number | null;
}

export interface CreatePayrollRunIn {
  period_start: number;
  period_end: number;
  currency?: string;
  correlation_id?: string | null;
}

export interface PayrollRunPage {
  items: PayrollRun[];
  next_cursor: string | null;
}

export interface PayrollLinesResp {
  lines: PayrollLine[];
}

// ─── Position calls ─────────────────────────────────────────────────────────

export const createPosition = (body: CreatePositionIn) =>
  api.post<Position>("/ui/hr/positions", body);

export const listPositions = (opts?: { status?: string; cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<PositionPage>("/ui/hr/positions", params);
};

export const getPosition = (positionId: string) =>
  api.get<Position>(`/ui/hr/positions/${encodeURIComponent(positionId)}`);

export const updatePositionStatus = (positionId: string, body: UpdatePositionStatusIn) =>
  api.patch<Position>(`/ui/hr/positions/${encodeURIComponent(positionId)}/status`, body);

// ─── Employment calls ─────────────────────────────────────────────────────────

export const createEmployment = (body: CreateEmploymentIn) =>
  api.post<Employment>("/ui/hr/employments", body);

export const listEmployments = (opts?: {
  party_id?: string;
  status?: string;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.party_id) params["party_id"] = opts.party_id;
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<EmploymentPage>("/ui/hr/employments", params);
};

export const getEmployment = (employmentId: string) =>
  api.get<Employment>(`/ui/hr/employments/${encodeURIComponent(employmentId)}`);

export const terminateEmployment = (employmentId: string, body: TerminateEmploymentIn) =>
  api.post<Employment>(`/ui/hr/employments/${encodeURIComponent(employmentId)}/terminate`, body);

// ─── Payroll calls ─────────────────────────────────────────────────────────────

export const createPayrollRun = (body: CreatePayrollRunIn) =>
  api.post<PayrollRun>("/ui/hr/payroll", body);

export const listPayrollRuns = (opts?: { status?: string; cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.limit) params["limit"] = String(opts.limit);
  return api.get<PayrollRunPage>("/ui/hr/payroll", params);
};

export const getPayrollRun = (payrollRunId: string) =>
  api.get<PayrollRun>(`/ui/hr/payroll/${encodeURIComponent(payrollRunId)}`);

export const getPayrollRunLines = (payrollRunId: string) =>
  api.get<PayrollLinesResp>(`/ui/hr/payroll/${encodeURIComponent(payrollRunId)}/lines`);

export const approvePayrollRun = (payrollRunId: string) =>
  api.post<PayrollRun>(`/ui/hr/payroll/${encodeURIComponent(payrollRunId)}/approve`);

export const postPayrollRun = (payrollRunId: string) =>
  api.post<PayrollRun>(`/ui/hr/payroll/${encodeURIComponent(payrollRunId)}/post`);
