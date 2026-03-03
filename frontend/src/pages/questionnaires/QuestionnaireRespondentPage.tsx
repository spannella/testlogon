import * as React from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2, Pencil } from "lucide-react";
import { useParams, useSearchParams } from "react-router-dom";

import {
  getPublishedQuestionnaireBySlug,
  getPublishedResponseSessionState,
  savePublishedResponseSessionState,
  startPublishedResponseSession,
  submitPublishedResponseSession,
  validatePublishedResponseSession,
} from "@/api/endpoints/questionnaires";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type ViewMode = "form" | "summary";

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function isAnswered(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

function stringifyAnswer(value: unknown): string {
  if (value == null) return "—";
  if (Array.isArray(value)) return value.length ? value.map((v) => String(v)).join(", ") : "—";
  if (typeof value === "object") return JSON.stringify(value);
  const rendered = String(value);
  return rendered.trim().length ? rendered : "—";
}

function trackRespondentCheckpoint(event: string, payload: Record<string, unknown>) {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("questionnaire:checkpoint", { detail: { event, ...payload } }));
  }

  const body = JSON.stringify({ event, ...payload });
  try {
    if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
      navigator.sendBeacon("/telemetry/questionnaire-checkpoint", new Blob([body], { type: "application/json" }));
      return;
    }
  } catch {
    // no-op
  }
}

export default function QuestionnaireRespondentPage() {
  const { publishedSlug = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const sessionId = searchParams.get("session_id") || "";

  const [currentSectionIndex, setCurrentSectionIndex] = React.useState(0);
  const [answers, setAnswers] = React.useState<Record<string, unknown>>({});
  const [validationResult, setValidationResult] = React.useState<Record<string, unknown> | null>(null);
  const [submitError, setSubmitError] = React.useState<string>("");
  const [viewMode, setViewMode] = React.useState<ViewMode>("form");

  const saveTimer = React.useRef<number | null>(null);
  const validateTimer = React.useRef<number | null>(null);
  const sectionHeadingRef = React.useRef<HTMLHeadingElement | null>(null);

  const publishedQuery = useQuery({
    queryKey: ["published-questionnaire", publishedSlug],
    queryFn: () => getPublishedQuestionnaireBySlug(publishedSlug),
    enabled: Boolean(publishedSlug),
  });

  const startSessionMutation = useMutation({
    mutationFn: () => startPublishedResponseSession(publishedSlug),
    onSuccess: (res) => {
      const nextSession = String((res.session as { response_session_id?: string }).response_session_id || "");
      if (nextSession) setSearchParams({ session_id: nextSession, view: "form" });
    },
  });

  const sessionStateQuery = useQuery({
    queryKey: ["published-questionnaire-session", publishedSlug, sessionId],
    queryFn: () => getPublishedResponseSessionState(publishedSlug, sessionId),
    enabled: Boolean(publishedSlug && sessionId),
  });

  const hydratedSessionId = React.useRef<string>("");

  React.useEffect(() => {
    if (!sessionStateQuery.data) return;
    const loadedSessionId = String(sessionStateQuery.data.session.response_session_id || "");
    if (!loadedSessionId || hydratedSessionId.current === loadedSessionId) return;

    hydratedSessionId.current = loadedSessionId;
    setAnswers(sessionStateQuery.data.answers_by_question_id || {});

    const restoredIndex = Number(sessionStateQuery.data.session.current_section_index || 0);
    const sectionParam = searchParams.get("section");
    const sectionFromQuery = sectionParam == null ? NaN : Number(sectionParam);
    setCurrentSectionIndex(Number.isFinite(sectionFromQuery) ? Math.max(0, sectionFromQuery) : restoredIndex);
    setViewMode(searchParams.get("view") === "summary" ? "summary" : "form");

    trackRespondentCheckpoint("session_restored", {
      session_id: loadedSessionId,
      current_section_index: restoredIndex,
    });
  }, [sessionStateQuery.data, searchParams]);

  React.useEffect(() => {
    const sectionParam = searchParams.get("section");
    const sectionFromQuery = sectionParam == null ? NaN : Number(sectionParam);
    if (Number.isFinite(sectionFromQuery)) setCurrentSectionIndex(Math.max(0, sectionFromQuery));
    setViewMode(searchParams.get("view") === "summary" ? "summary" : "form");
  }, [searchParams]);


  React.useEffect(() => {
    if (sectionHeadingRef.current) sectionHeadingRef.current.focus();
  }, [currentSectionIndex, viewMode]);

  const saveMutation = useMutation({
    mutationFn: (payload: { answers: Record<string, unknown>; sectionIndex: number; questionId?: string }) =>
      savePublishedResponseSessionState(publishedSlug, sessionId, {
        answers_by_question_id: payload.answers,
        current_section_index: payload.sectionIndex,
        current_question_id: payload.questionId,
      }),
    onSuccess: () => {
      trackRespondentCheckpoint("autosave", {
        session_id: sessionId,
        current_section_index: currentSectionIndex,
      });
    },
  });

  const validateMutation = useMutation({
    mutationFn: (payload: { answers: Record<string, unknown>; finalSubmit?: boolean }) =>
      validatePublishedResponseSession(publishedSlug, sessionId, {
        answers_by_question_id: payload.answers,
        final_submit: Boolean(payload.finalSubmit),
      }),
    onSuccess: (res) => {
      setValidationResult(res);
      setSubmitError("");
    },
  });

  const submitMutation = useMutation({
    mutationFn: () =>
      submitPublishedResponseSession(publishedSlug, sessionId, {
        answers_by_question_id: answers,
        final_submit: true,
      }),
    onSuccess: () => {
      setSubmitError("");
      trackRespondentCheckpoint("submitted", { session_id: sessionId });
    },
    onError: (err) => {
      const message = err instanceof Error ? err.message : "Cannot submit while blocking errors exist.";
      setSubmitError(message);
    },
  });

  const schemaSections = asArray<Record<string, unknown>>(publishedQuery.data?.version?.schema_json?.sections);
  const currentSection = schemaSections[currentSectionIndex] || schemaSections[0];
  const questions = asArray<Record<string, unknown>>(currentSection?.questions);
  const allQuestions = React.useMemo(
    () => schemaSections.flatMap((section) => asArray<Record<string, unknown>>(section.questions)),
    [schemaSections],
  );
  const requiredIds = React.useMemo(
    () => allQuestions.filter((q) => Boolean(q.required)).map((q) => String(q.question_id || "")),
    [allQuestions],
  );
  const answeredRequiredCount = React.useMemo(
    () => requiredIds.filter((qid) => isAnswered(answers[qid])).length,
    [requiredIds, answers],
  );
  const requiredCount = requiredIds.length;
  const pageProgressLabel = `${Math.min(currentSectionIndex + 1, Math.max(1, schemaSections.length))}/${Math.max(1, schemaSections.length)}`;
  const answeredCount = React.useMemo(() => Object.values(answers).filter((value) => isAnswered(value)).length, [answers]);
  const completionPercent = requiredCount > 0 ? Math.round((answeredRequiredCount / requiredCount) * 100) : 0;

  const errorMap = (validationResult?.errors as Record<string, Array<{ message: string; blocking?: boolean }>>) || {};
  const fieldErrors = (questionId: string) => errorMap[questionId] || [];
  const groupOrFormErrors = Object.entries(errorMap).filter(([key]) => key.startsWith("group:") || key.startsWith("form:"));
  const hasBlocking = Boolean(validationResult && !(validationResult.can_submit as boolean));

  const queueSaveAndValidate = React.useCallback(
    (nextAnswers: Record<string, unknown>, sectionIndex: number, questionId?: string) => {
      if (!sessionId) return;
      if (saveTimer.current) window.clearTimeout(saveTimer.current);
      saveTimer.current = window.setTimeout(() => {
        saveMutation.mutate({ answers: nextAnswers, sectionIndex, questionId });
      }, 500);

      if (validateTimer.current) window.clearTimeout(validateTimer.current);
      validateTimer.current = window.setTimeout(() => {
        validateMutation.mutate({ answers: nextAnswers, finalSubmit: false });
      }, 350);
    },
    [saveMutation, sessionId, validateMutation],
  );

  const goToSummary = () => {
    setViewMode("summary");
    setSearchParams({ session_id: sessionId, view: "summary" });
    trackRespondentCheckpoint("open_summary", { session_id: sessionId });
  };

  const editQuestion = (sectionIndex: number, questionId: string) => {
    setViewMode("form");
    setCurrentSectionIndex(sectionIndex);
    setSearchParams({ session_id: sessionId, view: "form", section: String(sectionIndex), question: questionId });
    trackRespondentCheckpoint("summary_edit_click", { session_id: sessionId, section_index: sectionIndex, question_id: questionId });
  };

  if (publishedQuery.isLoading) {
    return <div className="p-6 text-muted-foreground flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Loading questionnaire…</div>;
  }

  if (!sessionId) {
    return (
      <div className="mx-auto max-w-3xl p-6" data-testid="respondent-start-screen">
        <Card>
          <CardHeader><CardTitle>{String(publishedQuery.data?.version?.schema_json?.questionnaire_id || "Questionnaire")}</CardTitle></CardHeader>
          <CardContent>
            <Button type="button" onClick={() => startSessionMutation.mutate()} disabled={startSessionMutation.isPending}>
              {startSessionMutation.isPending ? "Starting…" : "Start questionnaire"}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (sessionStateQuery.isLoading) {
    return <div className="p-6 text-muted-foreground flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Restoring progress…</div>;
  }

  return (
    <div className="mx-auto max-w-3xl p-6 space-y-4" data-testid="respondent-flow">
      <Card>
        <CardHeader>
          <CardTitle ref={sectionHeadingRef} tabIndex={-1}>{viewMode === "summary" ? "Answer summary" : String(currentSection?.title || "Section")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2" data-testid="respondent-progress">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span data-testid="respondent-page-progress">Page {pageProgressLabel}</span>
              <span data-testid="respondent-required-progress">Required answered {answeredRequiredCount}/{requiredCount}</span>
            </div>
            <div className="h-2 w-full rounded bg-muted">
              <div
                className="h-2 rounded bg-primary transition-all"
                style={{ width: `${completionPercent}%` }}
                data-testid="respondent-progress-bar"
              />
            </div>
            <div className="text-xs text-muted-foreground" data-testid="respondent-answered-counter">
              Answered {answeredCount}/{allQuestions.length} questions
            </div>
          </div>

          {groupOrFormErrors.length > 0 && (
            <div className="rounded border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive" role="alert" aria-live="assertive" data-testid="respondent-error-summary">
              {groupOrFormErrors.flatMap(([key, issues]) => issues.map((i, idx) => <div key={`${key}-${idx}`}>{i.message}</div>))}
            </div>
          )}

          {viewMode === "summary" ? (
            <div className="space-y-3" data-testid="respondent-summary-view">
              {schemaSections.map((section, sectionIndex) => {
                const sectionQuestions = asArray<Record<string, unknown>>(section.questions);
                return (
                  <div key={String(section.section_id || sectionIndex)} className="rounded border p-3 space-y-2">
                    <div className="font-medium">{String(section.title || `Section ${sectionIndex + 1}`)}</div>
                    {sectionQuestions.map((q) => {
                      const qid = String(q.question_id || "");
                      return (
                        <div key={qid} className="flex items-start justify-between gap-3 text-sm" data-testid={`summary-question-${qid}`}>
                          <div>
                            <div className="font-medium">{String(q.label || "Question")}</div>
                            <div className="text-muted-foreground" data-testid={`summary-answer-${qid}`}>{stringifyAnswer(answers[qid])}</div>
                          </div>
                          <Button type="button" size="sm" variant="outline" onClick={() => editQuestion(sectionIndex, qid)}>
                            <Pencil className="mr-1 h-3 w-3" /> Edit
                          </Button>
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          ) : (
            <>
              {questions.map((q) => {
                const questionId = String(q.question_id || "");
                const errors = fieldErrors(questionId);
                return (
                  <div key={questionId} className="space-y-1" data-testid={`respondent-question-${questionId}`}>
                    <Label htmlFor={`answer-input-${questionId}`}>{String(q.label || "Question")}</Label>
                    <Input
                      id={`answer-input-${questionId}`}
                      aria-label={`answer-${questionId}`}
                      aria-invalid={errors.length > 0}
                      aria-describedby={errors.length > 0 ? `field-error-${questionId}` : undefined}
                      value={String(answers[questionId] || "")}
                      onChange={(e) => {
                        const next = { ...answers, [questionId]: e.target.value };
                        setAnswers(next);
                        queueSaveAndValidate(next, currentSectionIndex, questionId);
                      }}
                    />
                    {errors.length > 0 && (
                      <div id={`field-error-${questionId}`} className="text-xs text-destructive" role="status" aria-live="polite" data-testid={`field-error-${questionId}`}>
                        {errors.map((err, idx) => <div key={`${questionId}-${idx}`}>{err.message}</div>)}
                      </div>
                    )}
                  </div>
                );
              })}

              <div className="flex items-center justify-between pt-2" data-testid="respondent-nav">
                <Button
                  type="button"
                  variant="outline"
                  disabled={currentSectionIndex <= 0}
                  onClick={() => {
                    const next = Math.max(0, currentSectionIndex - 1);
                    setCurrentSectionIndex(next);
                    queueSaveAndValidate(answers, next);
                    trackRespondentCheckpoint("navigate_previous", { session_id: sessionId, current_section_index: next });
                  }}
                >
                  Previous
                </Button>
                <div className="text-xs text-muted-foreground" role="status" aria-live="polite" data-testid="respondent-autosave-state">
                  {saveMutation.isPending || validateMutation.isPending ? "Autosaving…" : "Progress saved"}
                </div>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    if (currentSectionIndex >= Math.max(0, schemaSections.length - 1)) {
                      goToSummary();
                      return;
                    }
                    const next = Math.min(schemaSections.length - 1, currentSectionIndex + 1);
                    setCurrentSectionIndex(next);
                    queueSaveAndValidate(answers, next);
                    trackRespondentCheckpoint("navigate_next", { session_id: sessionId, current_section_index: next });
                  }}
                >
                  {currentSectionIndex >= Math.max(0, schemaSections.length - 1) ? "Review summary" : "Next"}
                </Button>
              </div>
            </>
          )}

          <div className="sr-only" role="status" aria-live="polite" data-testid="respondent-live-announcer">
            {`Viewing ${viewMode === "summary" ? "summary" : `section ${currentSectionIndex + 1}`}. Required answered ${answeredRequiredCount} of ${requiredCount}.`}
          </div>

          <div className="flex items-center justify-end gap-2" data-testid="respondent-submit-area">
            {viewMode === "summary" && (
              <Button type="button" variant="outline" onClick={() => setViewMode("form")}>Back to form</Button>
            )}
            {submitError && <p className="text-xs text-destructive">{submitError}</p>}
            <Button
              type="button"
              disabled={hasBlocking || submitMutation.isPending}
              onClick={() => submitMutation.mutate()}
            >
              {submitMutation.isPending ? "Submitting…" : "Submit"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
