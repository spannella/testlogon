import { api } from "@/api/client";
import type {
  QuestionnaireDraft,
  QuestionnaireDraftListResp,
  QuestionnaireDraftUpdateReq,
  QuestionnaireSection,
  QuestionnaireSectionCreateReq,
  QuestionnaireSectionUpdateReq,
  QuestionnaireQuestion,
  QuestionnaireQuestionCreateReq,
  QuestionnaireQuestionUpdateReq,
  QuestionnaireVersion,
  PublishedQuestionnaireVersion,
  QuestionnaireSessionStateResp,
  QuestionnaireAnalyticsResp,
} from "@/api/types";

export const listQuestionnaireDrafts = (includeArchived = false) =>
  api.get<QuestionnaireDraftListResp>("/questionnaires/drafts", { include_archived: String(includeArchived) });

export const getQuestionnaireDraft = (questionnaireId: string) =>
  api.get<{ draft: QuestionnaireDraft }>(`/questionnaires/drafts/${questionnaireId}`);

export const updateQuestionnaireDraft = (questionnaireId: string, body: QuestionnaireDraftUpdateReq) =>
  api.patch<{ draft: QuestionnaireDraft }>(`/questionnaires/drafts/${questionnaireId}`, body);

export const listQuestionnaireSections = (questionnaireId: string) =>
  api.get<{ items: QuestionnaireSection[] }>(`/questionnaires/drafts/${questionnaireId}/sections`);

export const createQuestionnaireSection = (questionnaireId: string, body: QuestionnaireSectionCreateReq) =>
  api.post<{ section: QuestionnaireSection }>(`/questionnaires/drafts/${questionnaireId}/sections`, body);

export const updateQuestionnaireSection = (questionnaireId: string, sectionId: string, body: QuestionnaireSectionUpdateReq) =>
  api.patch<{ section: QuestionnaireSection }>(`/questionnaires/drafts/${questionnaireId}/sections/${sectionId}`, body);

export const deleteQuestionnaireSection = (questionnaireId: string, sectionId: string) =>
  api.del<{ section: QuestionnaireSection }>(`/questionnaires/drafts/${questionnaireId}/sections/${sectionId}`);

export const reorderQuestionnaireSections = (questionnaireId: string, sectionIds: string[]) =>
  api.post<{ items: QuestionnaireSection[] }>(`/questionnaires/drafts/${questionnaireId}/sections/reorder`, { section_ids: sectionIds });


export const listQuestionnaireQuestions = (questionnaireId: string, sectionId: string) =>
  api.get<{ items: QuestionnaireQuestion[] }>(`/questionnaires/drafts/${questionnaireId}/sections/${sectionId}/questions`);

export const createQuestionnaireQuestion = (questionnaireId: string, body: QuestionnaireQuestionCreateReq) =>
  api.post<{ question: QuestionnaireQuestion }>(`/questionnaires/drafts/${questionnaireId}/questions`, body);

export const updateQuestionnaireQuestion = (
  questionnaireId: string,
  sectionId: string,
  questionId: string,
  body: QuestionnaireQuestionUpdateReq,
) => api.patch<{ question: QuestionnaireQuestion }>(`/questionnaires/drafts/${questionnaireId}/questions/${questionId}?section_id=${encodeURIComponent(sectionId)}`, body);

export const deleteQuestionnaireQuestion = (questionnaireId: string, sectionId: string, questionId: string) =>
  api.del<{ question: QuestionnaireQuestion }>(`/questionnaires/drafts/${questionnaireId}/questions/${questionId}`, { section_id: sectionId });


export const validateQuestionnaireDraft = (
  questionnaireId: string,
  body: Record<string, unknown>,
) => api.post<Record<string, unknown>>(`/questionnaires/drafts/${questionnaireId}/validate`, body);


export const getQuestionnaireDraftSchema = (questionnaireId: string) =>
  api.get<Record<string, unknown>>(`/questionnaires/drafts/${questionnaireId}/schema`);

export const publishQuestionnaireDraft = (questionnaireId: string, published_slug?: string) =>
  api.post<{ version: QuestionnaireVersion }>(`/questionnaires/drafts/${questionnaireId}/publish`, { published_slug });


export const getPublishedQuestionnaireBySlug = (publishedSlug: string) =>
  api.get<{ version: PublishedQuestionnaireVersion }>(`/questionnaires/published/${publishedSlug}`);

export const getPublishedQuestionnaireById = (questionnaireId: string) =>
  api.get<{ version: PublishedQuestionnaireVersion }>(`/questionnaires/published/by-id/${questionnaireId}`);

export const startPublishedResponseSession = (publishedSlug: string) =>
  api.post<{ session: Record<string, unknown> }>(`/questionnaires/published/${publishedSlug}/sessions`, {});

export const getPublishedResponseSessionState = (publishedSlug: string, responseSessionId: string) =>
  api.get<QuestionnaireSessionStateResp>(`/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}`);

export const savePublishedResponseSessionState = (
  publishedSlug: string,
  responseSessionId: string,
  body: { answers_by_question_id: Record<string, unknown>; current_section_index?: number; current_question_id?: string },
) => api.put<QuestionnaireSessionStateResp>(`/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}`, body);


export const validatePublishedResponseSession = (
  publishedSlug: string,
  responseSessionId: string,
  body: Record<string, unknown>,
) => api.post<Record<string, unknown>>(`/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}/validate`, body);

export const submitPublishedResponseSession = (
  publishedSlug: string,
  responseSessionId: string,
  body: Record<string, unknown>,
) => api.post<{ session: Record<string, unknown>; result: Record<string, unknown> }>(`/questionnaires/published/${publishedSlug}/sessions/${responseSessionId}/submit`, body);


export const getQuestionnaireAnalytics = (questionnaireId: string) =>
  api.get<QuestionnaireAnalyticsResp>(`/questionnaires/drafts/${questionnaireId}/analytics`);
