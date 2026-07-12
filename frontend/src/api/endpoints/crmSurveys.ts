// SuiteCRM Surveys (EVT-Surveys, EVT-008..010) — frontend API wrappers.
//
// Backend: app/routers/questionnaires.py (router prefix `/questionnaires`, mounted at root).
// Surveys reuse the questionnaires builder/publish/response pipeline. Survey
// distribution (EVT-008) is gated behind the `crm_survey_distribution_enabled`
// flag (default OFF) → those endpoints return 404 when disabled.
//
// TS types are defined INLINE here (per shared-tree rules) mirroring the LIVE
// Pydantic models in app/routers/questionnaires.py.

import { api } from "@/api/client";

// ─── Survey (questionnaire) draft ────────────────────────────────────────────

export type SurveyVisibility = "private" | "public" | "unlisted";
export type SurveyStatus = "draft" | "published" | "archived";

export interface SurveyDraft {
  questionnaire_id: string;
  owner_id: string;
  title: string;
  description: string;
  status: SurveyStatus;
  visibility: SurveyVisibility;
  published_version_id: string | null;
  created_at: string;
  updated_at: string;
  [k: string]: unknown;
}

export interface SurveyDraftEnvelope {
  draft: SurveyDraft;
}

export interface SurveyDraftListEnvelope {
  items: SurveyDraft[];
}

export interface SurveySection {
  section_id: string;
  questionnaire_id?: string;
  title: string;
  description: string;
  position: number;
  [k: string]: unknown;
}

export interface SurveySectionEnvelope {
  section: SurveySection;
}

export interface SurveySectionListEnvelope {
  items: SurveySection[];
}

export type SurveyQuestionType =
  | "text"
  | "select"
  | "multiselect"
  | "radio"
  | "slider"
  | "number"
  | "date"
  | "boolean";

export interface SurveyQuestion {
  question_id: string;
  section_id: string;
  type: string;
  label: string;
  required: boolean;
  hint: string;
  config_json: Record<string, unknown>;
  position: number;
  [k: string]: unknown;
}

export interface SurveyQuestionEnvelope {
  question: SurveyQuestion;
}

export interface SurveyQuestionListEnvelope {
  items: SurveyQuestion[];
}

export interface SurveyVersion {
  questionnaire_id: string;
  version_id: string;
  version_number: number;
  published_slug: string;
  published_at: string;
  visibility: SurveyVisibility;
  schema_json: SurveySchema;
  [k: string]: unknown;
}

export interface SurveyVersionEnvelope {
  version: SurveyVersion;
}

// ─── Schema snapshot (builder + results) ─────────────────────────────────────

export interface SurveySchemaSection {
  section_id: string;
  title: string;
  description: string;
  position: number;
  questions: SurveyQuestion[];
}

export interface SurveySchema {
  questionnaire_id: string;
  sections: SurveySchemaSection[];
}

// ─── Analytics / results ─────────────────────────────────────────────────────

export interface SurveyFunnel {
  starts: number;
  completions: number;
  completion_rate: number;
}

export interface SurveyDropoffPoint {
  label: string;
  count: number;
}

export interface SurveyValidationHotspot {
  key: string;
  count: number;
}

export interface SurveyVersionAnalytics {
  version_id: string;
  version_number: number | null;
  published_at: string | null;
  funnel: SurveyFunnel;
  average_completion_seconds: number | null;
  dropoff_points: SurveyDropoffPoint[];
  validation_hotspots: SurveyValidationHotspot[];
}

export interface SurveyAnalytics {
  generated_at: string;
  freshness_sla_seconds: number;
  versions: SurveyVersionAnalytics[];
  totals: {
    starts: number;
    completions: number;
    top_dropoffs: SurveyDropoffPoint[];
    top_validation_hotspots: SurveyValidationHotspot[];
  };
}

export interface SurveyAnalyticsEnvelope {
  analytics: SurveyAnalytics;
}

// ─── Distribution (EVT-008, flag-gated) ──────────────────────────────────────

export interface DistributeSurveyReq {
  recipients: string[];
  subject?: string;
  message?: string | null;
  contact_list_id?: string | null;
}

export interface DistributeSurveyResp {
  sent: number;
  skipped: number;
  failed: number;
}

export interface DistributionSummary {
  total_sent: number;
  total_responses: number;
  response_rate: number;
}

// ─── Request bodies ──────────────────────────────────────────────────────────

export interface CreateSurveyReq {
  questionnaire_id: string;
  title: string;
  description?: string;
  visibility?: SurveyVisibility;
}

export interface UpdateSurveyReq {
  title?: string;
  description?: string;
  visibility?: SurveyVisibility;
}

export interface CreateSectionReq {
  section_id: string;
  title: string;
  description?: string;
}

export interface CreateQuestionReq {
  section_id: string;
  question_id: string;
  type: string;
  label: string;
  required?: boolean;
  hint?: string;
  config_json?: Record<string, unknown>;
}

export interface PublishSurveyReq {
  published_slug?: string | null;
}

// ─── API wrappers (EXACT live paths) ─────────────────────────────────────────

const BASE = "/questionnaires";

export const listSurveys = (includeArchived = false) =>
  api.get<SurveyDraftListEnvelope>(`${BASE}/drafts`, {
    include_archived: includeArchived ? "true" : "false",
  });

export const getSurvey = (questionnaireId: string) =>
  api.get<SurveyDraftEnvelope>(`${BASE}/drafts/${encodeURIComponent(questionnaireId)}`);

export const createSurvey = (body: CreateSurveyReq) =>
  api.post<SurveyDraftEnvelope>(`${BASE}/drafts`, body);

export const updateSurvey = (questionnaireId: string, body: UpdateSurveyReq) =>
  api.patch<SurveyDraftEnvelope>(`${BASE}/drafts/${encodeURIComponent(questionnaireId)}`, body);

export const archiveSurvey = (questionnaireId: string) =>
  api.del<SurveyDraftEnvelope>(`${BASE}/drafts/${encodeURIComponent(questionnaireId)}`);

export const publishSurvey = (questionnaireId: string, body: PublishSurveyReq = {}) =>
  api.post<SurveyVersionEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/publish`,
    body,
  );

export const getSurveySchema = (questionnaireId: string) =>
  api.get<SurveySchema>(`${BASE}/drafts/${encodeURIComponent(questionnaireId)}/schema`);

export const getSurveyAnalytics = (questionnaireId: string) =>
  api.get<SurveyAnalyticsEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/analytics`,
  );

// ── Sections ──

export const listSections = (questionnaireId: string) =>
  api.get<SurveySectionListEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/sections`,
  );

export const createSection = (questionnaireId: string, body: CreateSectionReq) =>
  api.post<SurveySectionEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/sections`,
    body,
  );

export const deleteSection = (questionnaireId: string, sectionId: string) =>
  api.del<SurveySectionEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/sections/${encodeURIComponent(sectionId)}`,
  );

// ── Questions ──

export const listQuestions = (questionnaireId: string, sectionId: string) =>
  api.get<SurveyQuestionListEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/sections/${encodeURIComponent(sectionId)}/questions`,
  );

export const createQuestion = (questionnaireId: string, body: CreateQuestionReq) =>
  api.post<SurveyQuestionEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/questions`,
    body,
  );

export const deleteQuestion = (questionnaireId: string, questionId: string, sectionId: string) =>
  api.del<SurveyQuestionEnvelope>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/questions/${encodeURIComponent(questionId)}`,
    { section_id: sectionId },
  );

// ── Distribution (EVT-008) ──

export const distributeSurvey = (questionnaireId: string, body: DistributeSurveyReq) =>
  api.post<DistributeSurveyResp>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/distribute`,
    body,
  );

export const getDistributionSummary = (questionnaireId: string) =>
  api.get<DistributionSummary>(
    `${BASE}/drafts/${encodeURIComponent(questionnaireId)}/distribution-summary`,
  );
