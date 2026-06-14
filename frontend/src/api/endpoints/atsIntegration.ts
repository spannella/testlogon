/**
 * ATI — ATS Integration cross-link bridge API client (ATI-001..ATI-005).
 *
 * Backend prefix: /ui/ats/integration
 * Feature gate:   503 {code: "ats_integration_disabled"} when
 *                 ATS_INTEGRATION_ENABLED=false OR CANDIDATES_ENABLED=false.
 *
 * All endpoints require cookie-auth session (CSRF for non-GET).
 */
import { api } from "@/api/client";

// ─── Inline TypeScript types mirroring app/models.py ─────────────────────────

/** Candidate <-> CRM Contact cross-link. */
export interface CandidateContactLink {
  link_id: string;
  link_type: "candidate_contact";
  candidate_id: string;
  contact_id: string;
  owner_sub: string;
  /** True when the CRM contact was successfully created/fetched from the ATS candidate. */
  synced: boolean;
  /** True when a sibling cluster was unavailable and the link persisted in partial state. */
  degraded: boolean;
  /** Comma-joined reason codes, e.g. "candidates_flag_off,contact_sync_failed" */
  degraded_reason: string | null;
  created_at: number;
  updated_at: number;
}

/** Job Order <-> CRM Opportunity cross-link. */
export interface JobOpportunityLink {
  link_id: string;
  link_type: "job_opportunity";
  job_order_id: string;
  opportunity_id: string;
  owner_sub: string;
  /** True when the CRM opportunity was successfully created/fetched from the job order. */
  synced: boolean;
  /** True when a sibling cluster was unavailable and the link persisted in partial state. */
  degraded: boolean;
  /** Comma-joined reason codes, e.g. "job_orders_flag_off,opportunity_sync_failed" */
  degraded_reason: string | null;
  created_at: number;
  updated_at: number;
}

/** Full links list response from GET /ui/ats/integration/links */
export interface IntegrationLinksOut {
  candidate_contact_links: CandidateContactLink[];
  job_opportunity_links: JobOpportunityLink[];
  count: number;
}

/** Request body for POST /ui/ats/integration/candidate-contact-links */
export interface CandidateContactLinkIn {
  candidate_id: string;
  /** Optional: omit to auto-sync a new contact from the candidate. */
  contact_id?: string;
}

/** Request body for POST /ui/ats/integration/job-opportunity-links */
export interface JobOpportunityLinkIn {
  job_order_id: string;
  /** Optional: omit to auto-sync a new opportunity from the job order. */
  opportunity_id?: string;
}

// ─── API wrappers ─────────────────────────────────────────────────────────────

/** List all ATI cross-links for the current user. */
export const listIntegrationLinks = () =>
  api.get<IntegrationLinksOut>("/ui/ats/integration/links");

/** Create or upsert a Candidate <-> Contact link. */
export const createCandidateContactLink = (body: CandidateContactLinkIn) =>
  api.post<CandidateContactLink>("/ui/ats/integration/candidate-contact-links", body);

/** Create or upsert a Job Order <-> Opportunity link. */
export const createJobOpportunityLink = (body: JobOpportunityLinkIn) =>
  api.post<JobOpportunityLink>("/ui/ats/integration/job-opportunity-links", body);

/**
 * Delete a cross-link by type + id.
 * @param linkType "candidate_contact" | "job_opportunity"
 * @param linkId   The deterministic link_id from the link record.
 */
export const deleteIntegrationLink = (linkType: string, linkId: string) =>
  api.del<{ ok: boolean }>(`/ui/ats/integration/links/${linkType}/${encodeURIComponent(linkId)}`);
