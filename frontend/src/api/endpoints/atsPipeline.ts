/**
 * ATS Recruiting Pipeline API client — PIP-001..PIP-010.
 *
 * Backend prefix: /ui/ats/pipeline  (admin: /ui/admin/ats/pipeline)
 * Feature gate:   GET /ui/ats/pipeline/feature-status (no auth required)
 * All other endpoints require cookie-auth session.
 *
 * With ATS_PIPELINE_ENABLED=false the server returns 503 {code: "ats_pipeline_disabled"}.
 * Callers should handle ApiError.status === 503 gracefully.
 */
import { api } from "@/api/client";

// ─── Inline TypeScript types mirroring app/models.py ─────────────────────────

/** Pipeline entry — M:N junction between a candidate and a job order. */
export interface PipelineEntry {
  pipeline_id: string;
  job_order_id: string;
  candidate_id: string;
  owner_sub: string;
  /** e.g. "100_no_contact", "400_submitted", "900_placed" */
  status: string;
  /** Numeric rank from status config, used for board ordering */
  status_rank: number;
  /** 0 = unrated; 1–5 stars */
  rating: number;
  created_at: number;
  updated_at: number;
}

export interface PipelineEntryCreateIn {
  job_order_id: string;
  candidate_id: string;
  /** Defaults to "100_no_contact" if omitted */
  status?: string;
}

export interface PipelineStatusChangeIn {
  new_status: string;
  note?: string | null;
}

export interface PipelineRatingIn {
  /** 1–5 star rating; 0 clears the rating (unrated) */
  rating: number;
}

/** A single status stage in the pipeline ladder. */
export interface PipelineStatusItem {
  status_key: string;
  label: string;
  rank: number;
  order: number;
  is_submitted: boolean;
  is_placed: boolean;
  is_terminal: boolean;
  color: string | null;
}

export interface PipelineStatusConfig {
  statuses: PipelineStatusItem[];
  updated_at: number | null;
  updated_by_sub: string | null;
}

/** Admin-write payload — replaces the full status ladder. */
export interface PipelineStatusConfigIn {
  statuses: Array<{
    status_key: string;
    label: string;
    rank: number;
    order?: number;
    is_submitted?: boolean;
    is_placed?: boolean;
    is_terminal?: boolean;
    color?: string | null;
  }>;
}

/** Placement record — created when a candidate is formally placed. */
export interface Placement {
  placement_id: string;
  job_order_id: string;
  candidate_id: string;
  owner_sub: string;
  /** Unix epoch seconds for candidate start date */
  start_date: number;
  /** Integer cents; 0 = pro-bono */
  fee_cents: number;
  /** Status key at time of placement (e.g. "900_placed") */
  status_at_placement: string;
  notes: string | null;
  created_at: number;
}

export interface PlacementIn {
  start_date: number;
  fee_cents: number;
  notes?: string | null;
}

export interface PipelineListResponse {
  entries: PipelineEntry[];
  cursor: string | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Check whether the pipeline feature is enabled.
 * This probe does NOT call _require_flag() so it always returns (no 503).
 * NOTE: when ats_pipeline_enabled=false the router itself is not mounted
 * so this endpoint may 404. Treat 404 the same as enabled=false.
 */
export const getPipelineFeatureStatus = () =>
  api.get<{ enabled: boolean }>("/ui/ats/pipeline/feature-status");

// ─── Status Config (PIP-002) ──────────────────────────────────────────────────

export const getPipelineStatuses = () =>
  api.get<PipelineStatusConfig>("/ui/ats/pipeline/statuses");

/** Admin only — replace deployment-wide status ladder. */
export const setPipelineStatuses = (body: PipelineStatusConfigIn) =>
  api.put<PipelineStatusConfig>("/ui/admin/ats/pipeline/statuses", body);

// ─── Bulk list (PIP-001) ─────────────────────────────────────────────────────

export const listPipelineByJob = (
  jobOrderId: string,
  opts?: { cursor?: string; limit?: number },
) =>
  api.get<PipelineListResponse>(`/ui/ats/pipeline/by-job/${jobOrderId}`, {
    ...(opts?.cursor ? { cursor: opts.cursor } : {}),
    ...(opts?.limit ? { limit: String(opts.limit) } : {}),
  });

export const listPipelineByCandidate = (
  candidateId: string,
  opts?: { cursor?: string; limit?: number },
) =>
  api.get<PipelineListResponse>(`/ui/ats/pipeline/by-candidate/${candidateId}`, {
    ...(opts?.cursor ? { cursor: opts.cursor } : {}),
    ...(opts?.limit ? { limit: String(opts.limit) } : {}),
  });

// ─── Pipeline entry CRUD (PIP-001) ───────────────────────────────────────────

export const addToPipeline = (body: PipelineEntryCreateIn) =>
  api.post<PipelineEntry>("/ui/ats/pipeline/entries", body);

export const removePipelineEntry = (jobOrderId: string, candidateId: string) =>
  api.del<undefined>(`/ui/ats/pipeline/by-job/${jobOrderId}/candidate/${candidateId}`);

// ─── Status change (PIP-003) ─────────────────────────────────────────────────

export const changePipelineStatus = (
  jobOrderId: string,
  candidateId: string,
  body: PipelineStatusChangeIn,
) =>
  api.patch<PipelineEntry>(
    `/ui/ats/pipeline/by-job/${jobOrderId}/candidate/${candidateId}/status`,
    body,
  );

// ─── Rating (PIP-004) ────────────────────────────────────────────────────────

export const setPipelineRating = (
  jobOrderId: string,
  candidateId: string,
  body: PipelineRatingIn,
) =>
  api.patch<PipelineEntry>(
    `/ui/ats/pipeline/by-job/${jobOrderId}/candidate/${candidateId}/rating`,
    body,
  );

// ─── Placement (PIP-006) ─────────────────────────────────────────────────────

export const createPlacement = (
  jobOrderId: string,
  candidateId: string,
  body: PlacementIn,
) =>
  api.post<Placement>(
    `/ui/ats/pipeline/by-job/${jobOrderId}/candidate/${candidateId}/placement`,
    body,
  );

export const getPlacement = (jobOrderId: string, candidateId: string) =>
  api.get<Placement>(
    `/ui/ats/pipeline/by-job/${jobOrderId}/candidate/${candidateId}/placement`,
  );
