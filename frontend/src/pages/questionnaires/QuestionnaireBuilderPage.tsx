import * as React from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { arrayMove } from "@dnd-kit/sortable";
import { GripVertical, Loader2, Plus, Save, Trash2 } from "lucide-react";
import { useParams, useSearchParams } from "react-router-dom";
import { toast } from "sonner";

import {
  createQuestionnaireQuestion,
  createQuestionnaireSection,
  deleteQuestionnaireQuestion,
  deleteQuestionnaireSection,
  getQuestionnaireDraft,
  listQuestionnaireQuestions,
  listQuestionnaireSections,
  reorderQuestionnaireSections,
  updateQuestionnaireDraft,
  updateQuestionnaireQuestion,
  updateQuestionnaireSection,
  validateQuestionnaireDraft,
  getQuestionnaireDraftSchema,
  getQuestionnaireAnalytics,
  publishQuestionnaireDraft,
} from "@/api/endpoints/questionnaires";
import type { QuestionnaireQuestion, QuestionnaireSection } from "@/api/types";
import { EmptyState } from "@/components/shared/EmptyState";
import SortableList from "@/components/shared/SortableList";
import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

import QuestionTypeConfigEditor from "./QuestionTypeConfigEditor";
import QuestionnaireAnalyticsTab from "./QuestionnaireAnalyticsTab";
import ValidationRuleBuilder from "./ValidationRuleBuilder";
import { defaultConfigForType, type BuilderQuestionType, validateQuestionConfig } from "./questionConfig";
import { toBackendRulePayload, type BuilderRule, validateRuleReferences } from "./validationRules";

function newId(prefix: string): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
  }
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

export default function QuestionnaireBuilderPage() {
  const { questionnaireId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [title, setTitle] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [visibility, setVisibility] = React.useState<"private" | "public" | "unlisted">("private");
  const [sections, setSections] = React.useState<QuestionnaireSection[]>([]);
  const [questionsBySection, setQuestionsBySection] = React.useState<Record<string, QuestionnaireQuestion[]>>({});
  const [metadataDirty, setMetadataDirty] = React.useState(false);
  const [savingCount, setSavingCount] = React.useState(0);
  const [dirtySections, setDirtySections] = React.useState<Set<string>>(new Set());
  const [dirtyQuestions, setDirtyQuestions] = React.useState<Set<string>>(new Set());
  const [questionErrors, setQuestionErrors] = React.useState<Record<string, string>>({});
  const [rules, setRules] = React.useState<BuilderRule[]>([]);
  const [previewOutput, setPreviewOutput] = React.useState<Record<string, unknown> | null>(null);
  const sectionSaveTimers = React.useRef<Record<string, number>>({});
  const questionSaveTimers = React.useRef<Record<string, number>>({});
  const metaTimer = React.useRef<number | null>(null);
  const [publishOpen, setPublishOpen] = React.useState(false);
  const [readiness, setReadiness] = React.useState<{ ok: boolean; items: string[] }>({ ok: false, items: [] });
  const [publishResult, setPublishResult] = React.useState<{ versionId: string; publishedAt: string } | null>(null);
  const mode = searchParams.get("mode") === "preview" ? "preview" : "builder";

  const draftQuery = useQuery({
    queryKey: ["questionnaire", questionnaireId, "draft"],
    queryFn: () => getQuestionnaireDraft(questionnaireId),
    enabled: Boolean(questionnaireId),
  });

  const sectionsQuery = useQuery({
    queryKey: ["questionnaire", questionnaireId, "sections"],
    queryFn: () => listQuestionnaireSections(questionnaireId),
    enabled: Boolean(questionnaireId),
  });

  const schemaQuery = useQuery({
    queryKey: ["questionnaire", questionnaireId, "schema"],
    queryFn: () => getQuestionnaireDraftSchema(questionnaireId),
    enabled: Boolean(questionnaireId),
  });

  const analyticsQuery = useQuery({
    queryKey: ["questionnaire", questionnaireId, "analytics"],
    queryFn: () => getQuestionnaireAnalytics(questionnaireId),
    enabled: Boolean(questionnaireId),
    refetchInterval: 60000,
  });

  React.useEffect(() => {
    if (!draftQuery.data?.draft) return;
    setTitle(draftQuery.data.draft.title || "");
    setDescription(draftQuery.data.draft.description || "");
  }, [draftQuery.data?.draft?.title, draftQuery.data?.draft?.description]);

  React.useEffect(() => {
    if (!sectionsQuery.data?.items) return;
    const sorted = [...sectionsQuery.data.items].sort((a, b) => a.position - b.position);
    setSections(sorted);

    void (async () => {
      const entries = await Promise.all(
        sorted.map(async (section) => {
          const res = await listQuestionnaireQuestions(questionnaireId, section.section_id);
          return [section.section_id, (res.items || []).sort((a, b) => a.position - b.position)] as const;
        }),
      );
      setQuestionsBySection(Object.fromEntries(entries));
    })();
  }, [questionnaireId, sectionsQuery.data?.items]);


  React.useEffect(() => {
    if (!questionnaireId) return;
    try {
      const raw = window.localStorage.getItem(`qnr_rules_${questionnaireId}`);
      if (raw) setRules(JSON.parse(raw));
    } catch {
      // ignore
    }
  }, [questionnaireId]);

  React.useEffect(() => {
    if (!questionnaireId) return;
    window.localStorage.setItem(`qnr_rules_${questionnaireId}`, JSON.stringify(rules));
  }, [questionnaireId, rules]);
  const withSaving = async <T,>(fn: () => Promise<T>): Promise<T> => {
    setSavingCount((c) => c + 1);
    try {
      return await fn();
    } finally {
      setSavingCount((c) => Math.max(0, c - 1));
    }
  };

  const saveMetadataMutation = useMutation({
    mutationFn: (payload: { title: string; description: string }) => withSaving(() => updateQuestionnaireDraft(questionnaireId, payload)),
    onSuccess: () => setMetadataDirty(false),
    onError: () => toast.error("Failed to autosave metadata"),
  });

  const saveSectionMutation = useMutation({
    mutationFn: (payload: { sectionId: string; title: string; description: string }) =>
      withSaving(() => updateQuestionnaireSection(questionnaireId, payload.sectionId, { title: payload.title, description: payload.description })),
    onSuccess: (_res, vars) => {
      setDirtySections((prev) => {
        const next = new Set(prev);
        next.delete(vars.sectionId);
        return next;
      });
    },
  });

  const saveQuestionMutation = useMutation({
    mutationFn: (payload: QuestionnaireQuestion) =>
      withSaving(() =>
        updateQuestionnaireQuestion(questionnaireId, payload.section_id, payload.question_id, {
          label: payload.label,
          required: payload.required,
          hint: payload.hint,
          config_json: payload.config_json,
        }),
      ),
    onSuccess: (_res, vars) => {
      setDirtyQuestions((prev) => {
        const next = new Set(prev);
        next.delete(vars.question_id);
        return next;
      });
    },
  });

  const unsaved = metadataDirty || dirtySections.size > 0 || dirtyQuestions.size > 0 || savingCount > 0;

  React.useEffect(() => {
    const handler = (event: BeforeUnloadEvent) => {
      if (!unsaved) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [unsaved]);

  React.useEffect(() => {
    if (!metadataDirty) return;
    if (metaTimer.current) window.clearTimeout(metaTimer.current);
    metaTimer.current = window.setTimeout(() => {
      saveMetadataMutation.mutate({ title: title.trim(), description: description.trim() });
    }, 700);
    return () => {
      if (metaTimer.current) window.clearTimeout(metaTimer.current);
    };
  }, [title, description, metadataDirty]);

  const queueSectionSave = (section: QuestionnaireSection) => {
    setDirtySections((prev) => new Set(prev).add(section.section_id));
    const timer = sectionSaveTimers.current[section.section_id];
    if (timer) window.clearTimeout(timer);
    sectionSaveTimers.current[section.section_id] = window.setTimeout(() => {
      saveSectionMutation.mutate({ sectionId: section.section_id, title: section.title, description: section.description || "" });
    }, 700);
  };

  const queueQuestionSave = (question: QuestionnaireQuestion) => {
    const validationError = validateQuestionConfig({
      question_id: question.question_id,
      section_id: question.section_id,
      type: question.type as BuilderQuestionType,
      label: question.label,
      required: question.required,
      hint: question.hint || "",
      config_json: question.config_json,
    });
    setQuestionErrors((prev) => ({ ...prev, [question.question_id]: validationError || "" }));
    if (validationError) return;

    setDirtyQuestions((prev) => new Set(prev).add(question.question_id));
    const timer = questionSaveTimers.current[question.question_id];
    if (timer) window.clearTimeout(timer);
    questionSaveTimers.current[question.question_id] = window.setTimeout(() => {
      saveQuestionMutation.mutate(question);
    }, 700);
  };

  const handleSectionChange = (sectionId: string, patch: Partial<QuestionnaireSection>) => {
    setSections((prev) => {
      const next = prev.map((s) => (s.section_id === sectionId ? { ...s, ...patch } : s));
      const changed = next.find((s) => s.section_id === sectionId);
      if (changed) queueSectionSave(changed);
      return next;
    });
  };

  const handleQuestionChange = (sectionId: string, questionId: string, patch: Partial<QuestionnaireQuestion>) => {
    setQuestionsBySection((prev) => {
      const list = prev[sectionId] || [];
      const next = list.map((q) => (q.question_id === questionId ? { ...q, ...patch } : q));
      const changed = next.find((q) => q.question_id === questionId);
      if (changed) queueQuestionSave(changed);
      return { ...prev, [sectionId]: next };
    });
  };

  const reorder = async (ordered: QuestionnaireSection[]) => {
    setSections(ordered.map((s, idx) => ({ ...s, position: idx })));
    await withSaving(() => reorderQuestionnaireSections(questionnaireId, ordered.map((s) => s.section_id)));
  };

  const moveSection = async (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= sections.length) return;
    const ordered = [...sections];
    const [item] = ordered.splice(index, 1);
    if (!item) return;
    ordered.splice(target, 0, item);
    await reorder(ordered);
  };

  const createSection = async () => {
    const created = await withSaving(() =>
      createQuestionnaireSection(questionnaireId, { section_id: newId("sec"), title: `Section ${sections.length + 1}`, description: "" }),
    );
    setSections((prev) => [...prev, created.section]);
    setQuestionsBySection((prev) => ({ ...prev, [created.section.section_id]: [] }));
  };

  const removeSection = async (sectionId: string) => {
    await withSaving(() => deleteQuestionnaireSection(questionnaireId, sectionId));
    setSections((prev) => prev.filter((s) => s.section_id !== sectionId));
    setQuestionsBySection((prev) => {
      const next = { ...prev };
      delete next[sectionId];
      return next;
    });
  };

  const addQuestion = async (sectionId: string) => {
    const type: BuilderQuestionType = "text";
    const created = await withSaving(() =>
      createQuestionnaireQuestion(questionnaireId, {
        section_id: sectionId,
        question_id: newId("q"),
        type,
        label: "Untitled question",
        required: false,
        hint: "",
        config_json: defaultConfigForType(type),
      }),
    );
    setQuestionsBySection((prev) => ({ ...prev, [sectionId]: [...(prev[sectionId] || []), created.question] }));
  };

  const removeQuestion = async (sectionId: string, questionId: string) => {
    await withSaving(() => deleteQuestionnaireQuestion(questionnaireId, sectionId, questionId));
    setQuestionsBySection((prev) => ({ ...prev, [sectionId]: (prev[sectionId] || []).filter((q) => q.question_id !== questionId) }));
  };


  const allQuestionIds = React.useMemo(() => Object.values(questionsBySection).flat().map((q) => q.question_id), [questionsBySection]);
  const ruleReferenceErrors = React.useMemo(() => validateRuleReferences(rules, allQuestionIds), [rules, allQuestionIds]);

  const runRulePreview = async (answers: Record<string, unknown>) => {
    if (ruleReferenceErrors.length > 0) {
      setPreviewOutput({ error: "Fix invalid rule references before preview." });
      return;
    }
    const payload = toBackendRulePayload(rules);
    const res = await withSaving(() =>
      validateQuestionnaireDraft(questionnaireId, {
        answers_by_question_id: answers,
        group_rules: payload.group_rules,
        form_rules: payload.form_rules,
        final_submit: false,
      }),
    );
    setPreviewOutput(res);
  };


  const runReadinessChecks = async () => {
    const items: string[] = [];
    if (!title.trim()) items.push("Title is required.");
    if (sections.length === 0) items.push("At least one section is required.");
    if (Object.values(questionsBySection).flat().length === 0) items.push("At least one question is required.");
    if (ruleReferenceErrors.length > 0) items.push("Validation rule references must be fixed.");

    if (items.length === 0) {
      try {
        const payload = toBackendRulePayload(rules);
        const result = await withSaving(() =>
          validateQuestionnaireDraft(questionnaireId, {
            answers_by_question_id: {},
            group_rules: payload.group_rules,
            form_rules: payload.form_rules,
            final_submit: false,
          }),
        );
        const hasBlocking = Boolean((result as { has_blocking_form_error?: boolean }).has_blocking_form_error);
        if (hasBlocking) items.push("Blocking form-level validation errors must be resolved.");
      } catch {
        items.push("Unable to validate draft readiness.");
      }
    }

    setReadiness({ ok: items.length === 0, items: items.length ? items : ["Ready to publish"] });
    return items.length === 0;
  };

  const publishMutation = useMutation({
    mutationFn: () => withSaving(() => publishQuestionnaireDraft(questionnaireId)),
    onSuccess: (res) => {
      setPublishResult({ versionId: res.version.version_id, publishedAt: res.version.published_at });
      toast.success("Questionnaire published");
      setPublishOpen(false);
    },
    onError: () => toast.error("Publish failed"),
  });

  const openPublishDialog = async () => {
    await runReadinessChecks();
    setPublishOpen(true);
  };
  if (draftQuery.isLoading || sectionsQuery.isLoading || schemaQuery.isLoading || analyticsQuery.isLoading) {
    return <div className="p-6 text-muted-foreground flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Loading builder…</div>;
  }

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 sm:p-6" data-testid="questionnaire-builder">
      <PageHeader
        title="Questionnaire Builder"
        description="Manage metadata, sections, and questions for your draft questionnaire."
        actions={(
          <div className="flex items-center gap-2">
            <Badge variant={unsaved ? "secondary" : "outline"} role="status" aria-live="polite">{unsaved ? "Unsaved changes" : "All changes saved"}</Badge>
            <Button
              type="button"
              variant="outline"
              onClick={() => setSearchParams({ mode: mode === "preview" ? "builder" : "preview" })}
            >
              {mode === "preview" ? "Exit preview" : "Preview mode"}
            </Button>
            <Button type="button" onClick={openPublishDialog}>Publish</Button>
          </div>
        )}
      />

      <QuestionnaireAnalyticsTab
        analytics={analyticsQuery.data?.analytics}
        isLoading={analyticsQuery.isLoading}
        questionnaireId={questionnaireId}
      />

      {mode === "preview" && (
        <Card data-testid="questionnaire-preview-mode">
          <CardHeader>
            <CardTitle>Creator preview</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {((schemaQuery.data?.sections as Array<Record<string, unknown>> | undefined) || []).map((section, sectionIdx) => (
              <div key={String(section.section_id || sectionIdx)} className="rounded border p-3 space-y-2">
                <div className="font-medium">{String(section.title || `Section ${sectionIdx + 1}`)}</div>
                {Array.isArray(section.questions) && section.questions.map((q, qIdx) => (
                  <div key={String((q as Record<string, unknown>).question_id || qIdx)} className="space-y-1">
                    <Label>{String((q as Record<string, unknown>).label || "Untitled question")}</Label>
                    <Input
                      readOnly
                      aria-label={`Preview respondent ${String((q as Record<string, unknown>).question_id || qIdx)}`}
                      placeholder={String(((q as Record<string, unknown>).config_json as Record<string, unknown> | undefined)?.placeholder || "")}
                    />
                    <p className="text-xs text-muted-foreground">{String((q as Record<string, unknown>).hint || "")}</p>
                  </div>
                ))}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Metadata</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2"><Label htmlFor="q-title">Title</Label><Input id="q-title" value={title} onChange={(e) => { setTitle(e.target.value); setMetadataDirty(true); }} /></div>
          <div className="space-y-2"><Label htmlFor="q-description">Description</Label><Textarea id="q-description" value={description} onChange={(e) => { setDescription(e.target.value); setMetadataDirty(true); }} rows={3} /></div>
          <div className="space-y-2">
            <Label>Visibility</Label>
            <Select value={visibility} onValueChange={(value: "private" | "public" | "unlisted") => { setVisibility(value); setMetadataDirty(true); }}>
              <SelectTrigger aria-label="Visibility"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="private">Private</SelectItem>
                <SelectItem value="unlisted">Unlisted</SelectItem>
                <SelectItem value="public">Public</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between"><CardTitle>Sections</CardTitle><Button onClick={createSection}><Plus className="mr-2 h-4 w-4" />Add section</Button></CardHeader>
        <CardContent className="space-y-4">
          {sections.length === 0 && <EmptyState title="No sections yet" description="Create your first section to start structuring the questionnaire." action={{ label: "Add section", onClick: createSection }} />}

          <SortableList
            items={sections}
            getItemId={(s) => s.section_id}
            className="space-y-4"
            onReorder={async (oldIndex, newIndex) => {
              const ordered = arrayMove(sections, oldIndex, newIndex);
              await reorder(ordered);
            }}
            renderItem={(section, index, dragHandleProps) => (
              <div className="rounded-md border p-3 space-y-3 bg-background">
              <div className="flex items-center gap-2">
                <span {...dragHandleProps} data-testid={`section-drag-handle-${section.section_id}`}>
                  <GripVertical className="h-4 w-4 text-muted-foreground" />
                </span>
                <Input aria-label={`Section title ${section.section_id}`} value={section.title} onChange={(e) => handleSectionChange(section.section_id, { title: e.target.value })} />
                <Button variant="ghost" size="icon" onClick={() => moveSection(index, -1)} aria-label="Move up">↑</Button>
                <Button variant="ghost" size="icon" onClick={() => moveSection(index, 1)} aria-label="Move down">↓</Button>
                <Button variant="ghost" size="icon" onClick={() => removeSection(section.section_id)} aria-label="Delete section"><Trash2 className="h-4 w-4" /></Button>
              </div>
              <Textarea aria-label={`Section description ${section.section_id}`} value={section.description || ""} onChange={(e) => handleSectionChange(section.section_id, { description: e.target.value })} rows={2} />

              <div className="border-t pt-3 space-y-3" data-testid={`question-list-${section.section_id}`}>
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium">Questions</h4>
                  <Button size="sm" variant="outline" onClick={() => addQuestion(section.section_id)}><Plus className="mr-1 h-3 w-3" />Add question</Button>
                </div>
                {(questionsBySection[section.section_id] || []).length === 0 && <p className="text-xs text-muted-foreground">No questions in this section yet.</p>}

                {(questionsBySection[section.section_id] || []).map((question) => (
                  <div key={question.question_id} className="rounded border p-3 space-y-2">
                    <div className="grid grid-cols-12 gap-2 items-end">
                      <div className="col-span-5">
                        <Label>Label</Label>
                        <Input value={question.label} onChange={(e) => handleQuestionChange(section.section_id, question.question_id, { label: e.target.value })} />
                      </div>
                      <div className="col-span-3">
                        <Label>Type</Label>
                        <Select value={question.type} onValueChange={(value: BuilderQuestionType) => handleQuestionChange(section.section_id, question.question_id, { type: value, config_json: defaultConfigForType(value) })}>
                          <SelectTrigger aria-label="Question type"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="text">text</SelectItem>
                            <SelectItem value="select">select</SelectItem>
                            <SelectItem value="multiselect">multiselect</SelectItem>
                            <SelectItem value="radio">radio</SelectItem>
                            <SelectItem value="slider">slider</SelectItem>
                            <SelectItem value="date">date</SelectItem>
                            <SelectItem value="time">time</SelectItem>
                            <SelectItem value="timezone">timezone</SelectItem>
                            <SelectItem value="address">address</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="col-span-2">
                        <Label>Required</Label>
                        <input type="checkbox" checked={question.required} onChange={(e) => handleQuestionChange(section.section_id, question.question_id, { required: e.target.checked })} className="h-4 w-4" />
                      </div>
                      <div className="col-span-2 flex justify-end">
                        <Button variant="ghost" size="icon" aria-label="Delete question" onClick={() => removeQuestion(section.section_id, question.question_id)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <Label>Hint text</Label>
                        <Input
                          aria-label="Hint text"
                          value={question.hint || ""}
                          onChange={(e) => handleQuestionChange(section.section_id, question.question_id, { hint: e.target.value })}
                        />
                      </div>
                      <div>
                        <Label>Help text</Label>
                        <Input
                          aria-label="Help text"
                          value={String(question.config_json?.help_text || "")}
                          onChange={(e) =>
                            handleQuestionChange(section.section_id, question.question_id, {
                              config_json: { ...(question.config_json || {}), help_text: e.target.value },
                            })
                          }
                        />
                      </div>
                    </div>

                    <div>
                      <Label>Placeholder</Label>
                      <Input
                        aria-label="Placeholder"
                        value={String(question.config_json?.placeholder || "")}
                        onChange={(e) =>
                          handleQuestionChange(section.section_id, question.question_id, {
                            config_json: { ...(question.config_json || {}), placeholder: e.target.value },
                          })
                        }
                      />
                    </div>

                    <QuestionTypeConfigEditor
                      type={question.type as BuilderQuestionType}
                      config={question.config_json || {}}
                      onChange={(cfg) => handleQuestionChange(section.section_id, question.question_id, { config_json: cfg })}
                    />

                    {questionErrors[question.question_id] && (
                      <p className="text-xs text-destructive" data-testid={`question-error-${question.question_id}`}>{questionErrors[question.question_id]}</p>
                    )}

                    <div className="rounded bg-muted/30 p-2 text-sm" data-testid={`question-preview-${question.question_id}`}>
                      <Label htmlFor={`preview-input-${question.question_id}`}>{question.label || "Untitled question"}</Label>
                      <Input
                        id={`preview-input-${question.question_id}`}
                        aria-label={`Preview ${question.question_id}`}
                        placeholder={String(question.config_json?.placeholder || "")}
                        aria-describedby={`preview-hint-${question.question_id}`}
                        value=""
                        onChange={() => {}}
                      />
                      <p id={`preview-hint-${question.question_id}`} className="text-xs text-muted-foreground" role="note">
                        {[question.hint, String(question.config_json?.help_text || "")].filter(Boolean).join(" ")}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            )}
          />
        </CardContent>
      </Card>



      <Card>
        <CardHeader>
          <CardTitle>Validation rules</CardTitle>
        </CardHeader>
        <CardContent>
          <ValidationRuleBuilder
            rules={rules}
            onChange={setRules}
            onPreview={runRulePreview}
            previewOutput={previewOutput}
            referenceErrors={ruleReferenceErrors}
          />
        </CardContent>
      </Card>

      {publishResult && (
        <Card data-testid="publish-success">
          <CardContent className="pt-6 text-sm">
            Published version <strong>{publishResult.versionId}</strong> at <strong>{publishResult.publishedAt}</strong>
          </CardContent>
        </Card>
      )}

      <Dialog open={publishOpen} onOpenChange={setPublishOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Publish questionnaire</DialogTitle>
            <DialogDescription>Review readiness checks before publishing a new immutable version.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2 text-sm" data-testid="publish-readiness-checklist">
            {readiness.items.map((item) => (
              <div key={item} className={readiness.ok ? "text-green-700" : "text-destructive"}>{item}</div>
            ))}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => void runReadinessChecks()}>Re-run checks</Button>
            <Button type="button" disabled={!readiness.ok || publishMutation.isPending} onClick={() => publishMutation.mutate()}>
              {publishMutation.isPending ? "Publishing…" : "Confirm publish"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="text-xs text-muted-foreground flex items-center gap-2" role="status" aria-live="polite" data-testid="builder-save-indicator"><Save className="h-3 w-3" />{savingCount > 0 ? "Autosaving…" : unsaved ? "Unsaved changes pending" : "All changes saved"}</div>
    </div>
  );
}
