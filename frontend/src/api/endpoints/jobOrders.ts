/**
 * ATS — Job Orders API client (JOB-001..008).
 *
 * Backend prefix: /ui/ats/job-orders
 * Feature gate:   GET /ui/ats/job-orders/feature-status (no auth)
 * All other endpoints require cookie-auth session.
 */
import { api } from "@/api/client";

// ─── Inline TypeScript types mirroring app/models.py ─────────────────────────

export type JobOrderType = "hire" | "contract" | "contract_to_hire" | "referral";
export type JobOrderStatus =
  | "active"
  | "on_hold"
  | "full"
  | "closed"
  | "canceled"
  | "lead"
  | "upcoming";

export const JOB_ORDER_TYPES: JobOrderType[] = [
  "hire",
  "contract",
  "contract_to_hire",
  "referral",
];

export const JOB_ORDER_STATUSES: JobOrderStatus[] = [
  "active",
  "on_hold",
  "full",
  "closed",
  "canceled",
  "lead",
  "upcoming",
];

export const JOB_ORDER_TERMINAL: JobOrderStatus[] = ["closed", "canceled"];

export const JOB_ORDER_OPEN_STATUSES: JobOrderStatus[] = JOB_ORDER_STATUSES.filter(
  (s) => !JOB_ORDER_TERMINAL.includes(s),
);

export interface JobOrder {
  job_id: string;
  title: string;
  type: JobOrderType;
  status: JobOrderStatus;
  openings: number;
  placed_count: number;
  openings_remaining: number;
  client_company_id: string;
  client_contact_id: string | null;
  recruiter_subs: string[];
  hot: boolean;
  public: boolean;
  /** Pay rate in integer cents (e.g. 7500 = $75.00/hr) */
  pay_rate_cents: number | null;
  /** Bill rate in integer cents (e.g. 12000 = $120.00/hr) */
  bill_rate_cents: number | null;
  duration: string | null;
  city: string | null;
  state: string | null;
  description: string | null;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface JobOrderListResponse {
  items: JobOrder[];
  next_cursor: string | null;
}

export interface JobOrderCreateInput {
  title: string;
  type: JobOrderType;
  status?: JobOrderStatus;
  openings?: number;
  client_company_id: string;
  client_contact_id?: string | null;
  recruiter_subs?: string[];
  hot?: boolean;
  public?: boolean;
  pay_rate_cents?: number | null;
  bill_rate_cents?: number | null;
  duration?: string | null;
  city?: string | null;
  state?: string | null;
  description?: string | null;
}

export interface JobOrderUpdateInput {
  title?: string;
  type?: JobOrderType;
  status?: JobOrderStatus;
  openings?: number;
  client_company_id?: string;
  client_contact_id?: string | null;
  recruiter_subs?: string[];
  hot?: boolean;
  public?: boolean;
  pay_rate_cents?: number | null;
  bill_rate_cents?: number | null;
  duration?: string | null;
  city?: string | null;
  state?: string | null;
  description?: string | null;
}

export interface JobOrderOpeningsSummary {
  openings: number;
  placed_count: number;
  openings_remaining: number;
}

export interface JobOrderFeatureStatus {
  ats_enabled: boolean;
  job_orders_enabled: boolean;
}

// ─── API wrappers ─────────────────────────────────────────────────────────────

/** Check feature flag state — no auth required. */
export const getJobOrderFeatureStatus = () =>
  api.get<JobOrderFeatureStatus>("/ui/ats/job-orders/feature-status");

/** List open (non-terminal, non-deleted) job orders, newest-first. */
export const listOpenJobOrders = (opts?: {
  company_id?: string;
  status?: JobOrderStatus;
  cursor?: string;
  limit?: number;
}) => {
  const params: Record<string, string> = {};
  if (opts?.company_id) params.company_id = opts.company_id;
  if (opts?.status) params.status = opts.status;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit != null) params.limit = String(opts.limit);
  return api.get<JobOrderListResponse>("/ui/ats/job-orders/open", params);
};

/** List hot-flagged, non-deleted job orders, newest-first. */
export const listHotJobOrders = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit != null) params.limit = String(opts.limit);
  return api.get<JobOrderListResponse>("/ui/ats/job-orders/hot", params);
};

/** List job orders assigned to the calling recruiter, newest-first. */
export const listMyJobOrders = (opts?: { cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit != null) params.limit = String(opts.limit);
  return api.get<JobOrderListResponse>("/ui/ats/job-orders/mine", params);
};

/** Create a new Job Order. Returns 201 + JobOrder. */
export const createJobOrder = (body: JobOrderCreateInput) =>
  api.post<JobOrder>("/ui/ats/job-orders/", body);

/** Fetch a single Job Order by ID. Returns 404 if not found or deleted. */
export const getJobOrder = (jobId: string) =>
  api.get<JobOrder>(`/ui/ats/job-orders/${encodeURIComponent(jobId)}`);

/** Partial-update a Job Order. */
export const updateJobOrder = (jobId: string, body: JobOrderUpdateInput) =>
  api.patch<JobOrder>(`/ui/ats/job-orders/${encodeURIComponent(jobId)}`, body);

/** Transition a Job Order's status via the 7-state machine. Returns 409 on illegal transitions. */
export const setJobOrderStatus = (jobId: string, status: JobOrderStatus) =>
  api.post<JobOrder>(`/ui/ats/job-orders/${encodeURIComponent(jobId)}/status`, { status });

/** Return the lightweight openings summary for a job order. */
export const getJobOrderOpenings = (jobId: string) =>
  api.get<JobOrderOpeningsSummary>(`/ui/ats/job-orders/${encodeURIComponent(jobId)}/openings`);

/** Soft-delete a Job Order. Returns 204. */
export const deleteJobOrder = (jobId: string) =>
  api.del<void>(`/ui/ats/job-orders/${encodeURIComponent(jobId)}`);
