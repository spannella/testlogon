import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// RSK-001..RSK-004 — Skill Registry + Résumé/Skill Search endpoint wrappers.
//
// All routes under:
//   /ui/ats/skills/*                (RSK-001 — skill registry + assignment)
//   /ui/ats/candidates/search/*     (RSK-003 résumé search, RSK-004 skill search)
//   /ui/ats/job-orders/search/*     (RSK-004 job-order skill search)
//   /ui/ats/job-orders/:id/matching-candidates  (RSK-004 matching)
//
// Backend gates every endpoint on S.candidates_enabled (owned by CND-001).
// Flag-off → HTTP 404. Callers should guard with isRskNotEnabled().
// ─────────────────────────────────────────────────────────────────────────────

// ─── Inline TS types (mirrors app/models.py RSK section) ─────────────────────

/** One entry in the canonical skill registry / assignment list. */
export interface SkillOut {
  skill_id: string;
  name: string;
  usage_count: number;
  /** 1–5 candidate proficiency; only meaningful on candidate assignments. */
  weight?: number | null;
  /** True = required for job order; only meaningful on job-order assignments. */
  required?: boolean | null;
  created_at: number;
}

/** Body sent when assigning a skill to an entity. */
export interface SkillAssignmentIn {
  name: string;
  /** 1–5; candidates only. */
  weight?: number | null;
  /** Job-order required flag. */
  required?: boolean | null;
}

/** All skills tagged to a single entity (candidate or job_order). */
export interface EntitySkillsOut {
  entity_type: "candidate" | "job_order";
  entity_id: string;
  skills: SkillOut[];
}

/** One hit in a résumé full-text search result set. */
export interface ResumeSearchResultItem {
  candidate_id: string;
  /** Snippet of the candidate's name (anonymised for non-admins). */
  name_snippet: string;
  owner_sub: string;
  updated_at: number;
}

/** Top-level response from GET /ui/ats/candidates/search/resume. */
export interface ResumeSearchOut {
  items: ResumeSearchResultItem[];
  query: string;
  total_estimate: number;
  has_more: boolean;
}

/** Candidate match returned from skill-based search / matching. */
export interface CandidateMatchOut {
  candidate_id: string;
  name: string;
  /** Present only for admin callers. */
  email?: string | null;
  matched_skill_ids: string[];
  match_score: number;
  /** Present only for admin callers. */
  owner_sub?: string | null;
}

/** Job-order match returned from skill-based job-order search. */
export interface JobOrderMatchOut {
  job_order_id: string;
  title: string;
  status: string;
  matched_skill_ids: string[];
  match_score: number;
}

/** Unified response envelope for skill-based search (candidates OR job orders). */
export interface SkillSearchResultsOut<
  T extends CandidateMatchOut | JobOrderMatchOut = CandidateMatchOut | JobOrderMatchOut,
> {
  items: T[];
  total: number;
  /** The normalised skill IDs that were queried. */
  query_skill_ids: string[];
  /** "all" | "any" */
  match: string;
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

/**
 * Returns true when the error indicates the RSK feature is not enabled
 * (backend returns 404 when S.candidates_enabled is false).
 */
export function isRskNotEnabled(err: unknown): boolean {
  const e = err as { status?: number } | null | undefined;
  return !!e && (e.status === 404 || e.status === 503);
}

// ─── RSK-001: Skill Registry + Assignment ────────────────────────────────────

/**
 * Autocomplete skill names by prefix.
 * GET /ui/ats/skills/search?prefix=&limit=
 */
export const searchSkills = (prefix: string, limit = 20) =>
  api.get<{ skills: SkillOut[] }>(
    "/ui/ats/skills/search",
    buildParams({ prefix, limit }),
  );

/**
 * List all skills assigned to a candidate or job_order.
 * GET /ui/ats/skills/entity/{entity_type}/{entity_id}
 */
export const listEntitySkills = (
  entityType: "candidate" | "job_order",
  entityId: string,
) =>
  api.get<EntitySkillsOut>(
    `/ui/ats/skills/entity/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`,
  );

/**
 * Assign a skill to an entity (candidate or job_order).
 * POST /ui/ats/skills/entity/{entity_type}/{entity_id}
 */
export const assignSkill = (
  entityType: "candidate" | "job_order",
  entityId: string,
  body: SkillAssignmentIn,
) =>
  api.post<SkillOut>(
    `/ui/ats/skills/entity/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`,
    body,
  );

/**
 * Remove a skill assignment from an entity.
 * DELETE /ui/ats/skills/entity/{entity_type}/{entity_id}/{skill_id}
 */
export const unassignSkill = (
  entityType: "candidate" | "job_order",
  entityId: string,
  skillId: string,
) =>
  api.del<{ ok: boolean }>(
    `/ui/ats/skills/entity/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}/${encodeURIComponent(skillId)}`,
  );

// ─── RSK-003: Résumé Full-Text Search ────────────────────────────────────────

export interface ResumeSearchParams {
  q: string;
  limit?: number;
  /** If true and caller is admin, searches across all owners. */
  all?: boolean;
}

/**
 * Full-text search over extracted résumé content.
 * GET /ui/ats/candidates/search/resume
 */
export const searchResumes = (params: ResumeSearchParams) =>
  api.get<ResumeSearchOut>(
    "/ui/ats/candidates/search/resume",
    buildParams(params as unknown as Record<string, string | number | boolean | undefined | null>),
  );

// ─── RSK-004: Skill-Based Candidate Search ───────────────────────────────────

export interface SkillCandidateSearchParams {
  /** Comma-separated skill IDs or names. */
  skill_ids: string;
  /** "all" (AND) | "any" (OR). Default: "all". */
  match?: "all" | "any";
  limit?: number;
  /** Admin-only: search across all owners. */
  all?: boolean;
}

/**
 * Search candidates by skill IDs with AND/OR semantics.
 * GET /ui/ats/candidates/search/skills
 */
export const searchCandidatesBySkills = (params: SkillCandidateSearchParams) =>
  api.get<SkillSearchResultsOut<CandidateMatchOut>>(
    "/ui/ats/candidates/search/skills",
    buildParams(params as unknown as Record<string, string | number | boolean | undefined | null>),
  );

// ─── RSK-004: Skill-Based Job-Order Search ───────────────────────────────────

export interface SkillJobOrderSearchParams {
  skill_ids: string;
  match?: "all" | "any";
  required_only?: boolean;
  limit?: number;
}

/**
 * Search job orders by skill IDs.
 * GET /ui/ats/job-orders/search/skills
 */
export const searchJobOrdersBySkills = (params: SkillJobOrderSearchParams) =>
  api.get<SkillSearchResultsOut<JobOrderMatchOut>>(
    "/ui/ats/job-orders/search/skills",
    buildParams(params as unknown as Record<string, string | number | boolean | undefined | null>),
  );

// ─── RSK-004: Matching Candidates for a Job Order ────────────────────────────

/**
 * Return ranked candidates by how well they match a job order's required skills.
 * GET /ui/ats/job-orders/{job_order_id}/matching-candidates
 */
export const getMatchingCandidates = (jobOrderId: string, limit = 50) =>
  api.get<SkillSearchResultsOut<CandidateMatchOut>>(
    `/ui/ats/job-orders/${encodeURIComponent(jobOrderId)}/matching-candidates`,
    buildParams({ limit }),
  );
