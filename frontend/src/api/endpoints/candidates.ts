import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// ATS Candidates (CND-001..CND-007) — endpoint wrappers + inline types.
// All routes live under /ui/candidates. Backend gates on S.candidates_enabled
// — when off, every endpoint returns 404. Callers should handle
// ApiError.status === 404 || 503 gracefully (see isNotEnabled helper below).
// ─────────────────────────────────────────────────────────────────────────────

// ─── Constants ───────────────────────────────────────────────────────────────

export const CANDIDATE_STATUSES = [
  "active",
  "qualified",
  "submitted",
  "interviewing",
  "placed",
  "on_hold",
  "not_in_search",
  "archived",
] as const;
export type CandidateStatus = (typeof CANDIDATE_STATUSES)[number];

export const CANDIDATE_SOURCES = [
  "direct",
  "referral",
  "job_board",
  "linkedin",
  "agency",
  "career_portal",
  "import",
  "other",
] as const;
export type CandidateSource = (typeof CANDIDATE_SOURCES)[number];

// ─── Interfaces mirroring app/models.py ──────────────────────────────────────

export interface CandidateResumeOut {
  attachment_id: string;
  candidate_id: string;
  filename: string;
  filename_original: string;
  content_type: string;
  size_bytes: number;
  /** Presigned URL (prod) or /mock/s3/… (dev) */
  url: string;
  /** "upload" | "file_manager" */
  source: string;
  is_primary: boolean;
  node_path?: string | null;
  created_at: number;
  uploaded_by: string;
}

export interface Candidate {
  candidate_id: string;
  first_name: string;
  last_name: string;
  email: string;
  email_raw: string;
  phone?: string | null;
  company?: string | null;
  title?: string | null;
  source: string;
  owner_sub: string;
  status: string;
  current_pay?: string | null;
  desired_pay?: string | null;
  key_skills?: string | null;
  date_available?: string | null;
  can_relocate: boolean;
  linkedin_url?: string | null;
  web_url?: string | null;
  address?: string | null;
  city?: string | null;
  state?: string | null;
  postal_code?: string | null;
  country?: string | null;
  primary_resume_id?: string | null;
  created_by: string;
  created_at: number;
  updated_at: number;
  deleted_at?: number | null;
  /** Populated on detail endpoint only; empty array on list. */
  resumes: CandidateResumeOut[];
}

export interface CandidateListResp {
  candidates: Candidate[];
  cursor?: string | null;
  total_hint?: number | null;
}

export interface CandidateCreateIn {
  first_name: string;
  last_name: string;
  email: string;
  phone?: string;
  company?: string;
  title?: string;
  source?: string;
  owner_sub?: string;
  status?: string;
  current_pay?: string;
  desired_pay?: string;
  key_skills?: string;
  date_available?: string;
  can_relocate?: boolean;
  linkedin_url?: string;
  web_url?: string;
  address?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
}

export interface CandidateUpdateIn {
  first_name?: string;
  last_name?: string;
  email?: string;
  phone?: string;
  company?: string;
  title?: string;
  source?: string;
  status?: string;
  current_pay?: string;
  desired_pay?: string;
  key_skills?: string;
  date_available?: string;
  can_relocate?: boolean;
  linkedin_url?: string;
  web_url?: string;
  address?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
}

export interface CandidateHistoryEvent {
  event_id: string;
  candidate_id: string;
  change_type: string;
  summary: string;
  actor_sub: string;
  metadata: Record<string, unknown>;
  created_at: number;
}

export interface CandidateHistoryPage {
  events: CandidateHistoryEvent[];
  cursor?: string | null;
}

export interface SetOwnerIn {
  owner_sub: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildParams(
  p?: Record<string, string | number | boolean | undefined | null>,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!p) return out;
  for (const [k, v] of Object.entries(p)) {
    if (v !== undefined && v !== null && v !== "") out[k] = String(v);
  }
  return out;
}

export function isNotEnabled(err: unknown): boolean {
  const e = err as { status?: number } | undefined;
  return !!e && (e.status === 404 || e.status === 503);
}

// ─── Candidate CRUD ───────────────────────────────────────────────────────────

export interface CandidateListParams {
  owner_sub?: string;
  status?: string;
  source?: string;
  created_after?: number;
  cursor?: string;
  limit?: number;
}

export const listCandidates = (params?: CandidateListParams) =>
  api.get<CandidateListResp>(
    "/ui/candidates",
    buildParams(params as Record<string, string | number | boolean | undefined | null> | undefined),
  );

export const getCandidate = (candidateId: string) =>
  api.get<Candidate>(`/ui/candidates/${encodeURIComponent(candidateId)}`);

export const createCandidate = (body: CandidateCreateIn) =>
  api.post<Candidate>("/ui/candidates", body);

export const updateCandidate = (candidateId: string, body: CandidateUpdateIn) =>
  api.patch<Candidate>(`/ui/candidates/${encodeURIComponent(candidateId)}`, body);

export const deleteCandidate = (candidateId: string) =>
  api.del<void>(`/ui/candidates/${encodeURIComponent(candidateId)}`);

// ─── Owner assignment ─────────────────────────────────────────────────────────

export const setCandidateOwner = (candidateId: string, ownerSub: string) =>
  api.put<Candidate>(`/ui/candidates/${encodeURIComponent(candidateId)}/owner`, {
    owner_sub: ownerSub,
  } satisfies SetOwnerIn);

// ─── Résumé management ───────────────────────────────────────────────────────

export const listResumes = (candidateId: string) =>
  api.get<CandidateResumeOut[]>(
    `/ui/candidates/${encodeURIComponent(candidateId)}/resumes`,
  );

export const getResume = (candidateId: string, attachmentId: string) =>
  api.get<CandidateResumeOut>(
    `/ui/candidates/${encodeURIComponent(candidateId)}/resumes/${encodeURIComponent(attachmentId)}`,
  );

export const uploadResume = (
  candidateId: string,
  file: File,
  makePrimary = false,
): Promise<CandidateResumeOut> => {
  const form = new FormData();
  form.append("file", file);
  form.append("make_primary", String(makePrimary));
  return api.upload<CandidateResumeOut>(
    `/ui/candidates/${encodeURIComponent(candidateId)}/resumes`,
    form,
  );
};

export const setPrimaryResume = (candidateId: string, attachmentId: string) =>
  api.put<CandidateResumeOut>(
    `/ui/candidates/${encodeURIComponent(candidateId)}/resumes/${encodeURIComponent(attachmentId)}/primary`,
  );

export const deleteResume = (candidateId: string, attachmentId: string) =>
  api.del<void>(
    `/ui/candidates/${encodeURIComponent(candidateId)}/resumes/${encodeURIComponent(attachmentId)}`,
  );

// ─── Change history ───────────────────────────────────────────────────────────

export const getCandidateHistory = (
  candidateId: string,
  opts?: { cursor?: string; limit?: number },
) =>
  api.get<CandidateHistoryPage>(
    `/ui/candidates/${encodeURIComponent(candidateId)}/history`,
    buildParams(opts),
  );
