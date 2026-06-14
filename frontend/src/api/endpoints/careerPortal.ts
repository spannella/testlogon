/**
 * ATS Career Portal API client (PRT-001..PRT-005).
 *
 * Public endpoints (no auth):
 *   GET  /public/careers/config
 *   GET  /public/careers/jobs
 *   GET  /public/careers/jobs/{slug}
 *   POST /public/careers/jobs/{slug}/resume-presign
 *   POST /public/careers/jobs/{slug}/apply
 *
 * Admin endpoints (cookie session + CSRF, ADMIN/ROOT role):
 *   GET /ui/admin/career-portal/config
 *   PUT /ui/admin/career-portal/config
 *
 * Feature flag: CAREER_PORTAL_ENABLED (default off).
 * When flag is off every endpoint returns HTTP 404.
 * Callers should handle ApiError.status === 404 as "not enabled".
 */

import { api } from "@/api/client";
import { ApiError } from "@/api/client";

// ─── Type helpers ────────────────────────────────────────────────

/** True when the error indicates the feature is disabled (flag off). */
export function isCareerPortalNotEnabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

// ─── Inline TypeScript types (mirrors app/models.py) ─────────────

export type EmploymentType =
  | "full_time"
  | "part_time"
  | "contract"
  | "temp"
  | "referral";

/** GET /public/careers/config and GET/PUT /ui/admin/career-portal/config */
export interface CareerPortalConfigOut {
  portal_name: string;
  intro_copy: string;
  logo_file_path: string | null;
  /** Resolved URL for logo; null when no logo set. */
  logo_url: string | null;
  primary_color: string | null;
  support_email: string | null;
  /** Unix timestamp of last config write; null when never set. */
  updated_at: number | null;
  updated_by: string | null;
}

/** Body for PUT /ui/admin/career-portal/config */
export interface CareerPortalConfigIn {
  portal_name: string;
  intro_copy?: string;
  logo_file_path?: string | null;
  /** Must match ^#[0-9a-fA-F]{6}$ */
  primary_color?: string | null;
  support_email?: string | null;
}

/** A single job in the public listing. */
export interface CareerJobSummaryOut {
  job_order_id: string;
  slug: string;
  title: string;
  location: string | null;
  employment_type: EmploymentType | null;
  /** Unix timestamp */
  posted_at: number;
  openings: number;
}

/** GET /public/careers/jobs */
export interface CareerJobListOut {
  items: CareerJobSummaryOut[];
  /** Opaque cursor; null = no more pages. */
  cursor: string | null;
  total_estimate: number | null;
}

/** GET /public/careers/jobs/{slug} */
export interface CareerJobDetailOut extends CareerJobSummaryOut {
  public_description: string | null;
  /** Non-null when a screening questionnaire is linked (PRT-005). */
  screening_questionnaire_slug: string | null;
  apply_path: string;
}

/** POST /public/careers/jobs/{slug}/apply — request body. */
export interface CareerApplyIn {
  first_name: string;
  last_name: string;
  email: string;
  phone?: string | null;
  cover_note?: string | null;
  /** PRT-005: ticket_id from resume presign. */
  resume_ticket_id?: string | null;
  /** PRT-005: questionnaire session id. */
  screening_response_session_id?: string | null;
  /** Bot-trap: leave empty; any value triggers honeypot. */
  honeypot?: string;
}

/** POST /public/careers/jobs/{slug}/apply — response body. */
export interface CareerApplyOut {
  application_id: string;
  candidate_id: string | null;
  /** Always "received" on success. */
  status: string;
}

/** POST /public/careers/jobs/{slug}/resume-presign — request body. */
export interface CareerResumePresignIn {
  filename: string;
  /** application/pdf | application/msword | application/vnd.openxmlformats-officedocument.wordprocessingml.document */
  content_type: string;
  size_bytes: number;
  honeypot?: string;
}

/** POST /public/careers/jobs/{slug}/resume-presign — response body. */
export interface CareerResumePresignOut {
  /** PUT target URL (presigned S3 or /mock/s3/ in dev). */
  upload_url: string;
  ticket_id: string;
  key: string;
  path: string;
  content_type: string;
}

// ─── Public API wrappers ──────────────────────────────────────────

/** Fetch portal branding/config (no auth required). */
export const getPublicPortalConfig = () =>
  api.get<CareerPortalConfigOut>("/public/careers/config");

/** Paginated public job listings. Passes cursor for subsequent pages. */
export const listPublicJobs = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CareerJobListOut>("/public/careers/jobs", params);
};

/** Fetch a single public job posting by slug. */
export const getPublicJob = (slug: string) =>
  api.get<CareerJobDetailOut>(`/public/careers/jobs/${encodeURIComponent(slug)}`);

/**
 * Mint a presigned S3 PUT URL for resume upload before submitting the
 * application. Validates content-type and file size server-side.
 */
export const presignResumeUpload = (slug: string, body: CareerResumePresignIn) =>
  api.post<CareerResumePresignOut>(
    `/public/careers/jobs/${encodeURIComponent(slug)}/resume-presign`,
    body,
  );

/**
 * Submit a public job application. Optionally includes resume_ticket_id
 * (from presignResumeUpload) and screening_response_session_id.
 */
export const applyToJob = (slug: string, body: CareerApplyIn) =>
  api.post<CareerApplyOut>(
    `/public/careers/jobs/${encodeURIComponent(slug)}/apply`,
    body,
  );

// ─── Admin API wrappers ───────────────────────────────────────────

/** Fetch portal branding config (ADMIN/ROOT session required). */
export const getAdminPortalConfig = () =>
  api.get<CareerPortalConfigOut>("/ui/admin/career-portal/config");

/** Update portal branding config (ADMIN/ROOT session required). */
export const updateAdminPortalConfig = (body: CareerPortalConfigIn) =>
  api.put<CareerPortalConfigOut>("/ui/admin/career-portal/config", body);
