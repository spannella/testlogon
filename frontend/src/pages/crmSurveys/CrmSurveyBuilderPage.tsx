import { useMemo, useState } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Plus,
  Trash2,
  Rocket,
  Send,
  BarChart3,
  Layers,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getSurvey,
  listSections,
  listQuestions,
  createSection,
  deleteSection,
  createQuestion,
  deleteQuestion,
  publishSurvey,
  distributeSurvey,
  type SurveyQuestion,
  type SurveySection,
} from "@/api/endpoints/crmSurveys";

const QUESTION_TYPES: { value: string; label: string }[] = [
  { value: "text", label: "Text" },
  { value: "number", label: "Number" },
  { value: "radio", label: "Single choice (radio)" },
  { value: "select", label: "Dropdown (select)" },
  { value: "multiselect", label: "Multiple choice" },
  { value: "slider", label: "Slider" },
  { value: "date", label: "Date" },
  { value: "boolean", label: "Yes / No" },
];

const NEEDS_OPTIONS = new Set(["radio", "select", "multiselect"]);

function genId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
}

export default function CrmSurveyBuilderPage() {
  const { surveyId = "" } = useParams<{ surveyId: string }>();
  const qc = useQueryClient();

  const surveyQuery = useQuery({
    queryKey: ["crm-surveys", surveyId],
    queryFn: () => getSurvey(surveyId),
    enabled: !!surveyId,
    retry: false,
  });

  const sectionsQuery = useQuery({
    queryKey: ["crm-surveys", surveyId, "sections"],
    queryFn: () => listSections(surveyId),
    enabled: !!surveyId,
    retry: false,
  });

  const sections: SurveySection[] = sectionsQuery.data?.items ?? [];

  const questionQueries = useQueries({
    queries: sections.map((s) => ({
      queryKey: ["crm-surveys", surveyId, "questions", s.section_id],
      queryFn: () => listQuestions(surveyId, s.section_id),
      enabled: !!surveyId,
    })),
  });

  const questionsBySection = useMemo(() => {
    const map: Record<string, SurveyQuestion[]> = {};
    sections.forEach((s, i) => {
      map[s.section_id] = questionQueries[i]?.data?.items ?? [];
    });
    return map;
  }, [sections, questionQueries]);

  const survey = surveyQuery.data?.draft;
  const isDraft = survey?.status === "draft";

  // ── Section dialog ──
  const [sectionOpen, setSectionOpen] = useState(false);
  const [sectionTitle, setSectionTitle] = useState("");
  const [sectionDesc, setSectionDesc] = useState("");

  const sectionMut = useMutation({
    mutationFn: () =>
      createSection(surveyId, {
        section_id: genId("sec"),
        title: sectionTitle.trim(),
        description: sectionDesc.trim(),
      }),
    onSuccess: () => {
      toast.success("Section added");
      setSectionOpen(false);
      setSectionTitle("");
      setSectionDesc("");
      qc.invalidateQueries({ queryKey: ["crm-surveys", surveyId, "sections"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to add section"),
  });

  const delSectionMut = useMutation({
    mutationFn: (sectionId: string) => deleteSection(surveyId, sectionId),
    onSuccess: () => {
      toast.success("Section removed");
      qc.invalidateQueries({ queryKey: ["crm-surveys", surveyId, "sections"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to remove section"),
  });

  // ── Question dialog ──
  const [questionOpen, setQuestionOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const [qLabel, setQLabel] = useState("");
  const [qType, setQType] = useState("text");
  const [qRequired, setQRequired] = useState(false);
  const [qOptions, setQOptions] = useState("");

  const questionMut = useMutation({
    mutationFn: () => {
      const config: Record<string, unknown> = {};
      if (NEEDS_OPTIONS.has(qType)) {
        config.options = qOptions
          .split("\n")
          .map((o) => o.trim())
          .filter(Boolean);
      }
      if (qType === "slider") {
        config.min = 0;
        config.max = 10;
        config.step = 1;
      }
      return createQuestion(surveyId, {
        section_id: activeSection,
        question_id: genId("q"),
        type: qType,
        label: qLabel.trim(),
        required: qRequired,
        config_json: config,
      });
    },
    onSuccess: () => {
      toast.success("Question added");
      setQuestionOpen(false);
      setQLabel("");
      setQType("text");
      setQRequired(false);
      setQOptions("");
      qc.invalidateQueries({ queryKey: ["crm-surveys", surveyId, "questions", activeSection] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to add question"),
  });

  const delQuestionMut = useMutation({
    mutationFn: (args: { questionId: string; sectionId: string }) =>
      deleteQuestion(surveyId, args.questionId, args.sectionId),
    onSuccess: (_d, args) => {
      toast.success("Question removed");
      qc.invalidateQueries({ queryKey: ["crm-surveys", surveyId, "questions", args.sectionId] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to remove question"),
  });

  // ── Publish ──
  const publishMut = useMutation({
    mutationFn: () => publishSurvey(surveyId, {}),
    onSuccess: () => {
      toast.success("Survey published");
      qc.invalidateQueries({ queryKey: ["crm-surveys", surveyId] });
      qc.invalidateQueries({ queryKey: ["crm-surveys"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to publish"),
  });

  // ── Distribute (EVT-008) ──
  const [distOpen, setDistOpen] = useState(false);
  const [recipients, setRecipients] = useState("");
  const [distSubject, setDistSubject] = useState("You've been invited to complete a survey");
  const [distMessage, setDistMessage] = useState("");
  const [distUnavailable, setDistUnavailable] = useState(false);

  const distributeMut = useMutation({
    mutationFn: () =>
      distributeSurvey(surveyId, {
        recipients: recipients
          .split(/[\n,]/)
          .map((r) => r.trim())
          .filter(Boolean),
        subject: distSubject.trim() || undefined,
        message: distMessage.trim() || null,
      }),
    onSuccess: (res) => {
      toast.success(`Sent ${res.sent} · skipped ${res.skipped} · failed ${res.failed}`);
      setDistOpen(false);
      setRecipients("");
      setDistMessage("");
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && (e.status === 404 || e.status === 503)) {
        setDistUnavailable(true);
        toast.error("Survey distribution is not enabled on this platform.");
        return;
      }
      toast.error(e instanceof Error ? e.message : "Failed to distribute");
    },
  });

  if (surveyQuery.isLoading) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          Loading survey…
        </CardContent>
      </Card>
    );
  }

  if (surveyQuery.isError || !survey) {
    return (
      <div className="space-y-4">
        <Button asChild variant="ghost" size="sm">
          <Link to="/crm/surveys">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to surveys
          </Link>
        </Button>
        <Card>
          <CardContent className="py-12 text-center text-sm text-destructive">
            Survey not found or you do not have access.
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/crm/surveys">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to surveys
        </Link>
      </Button>

      <PageHeader
        title={survey.title}
        description={survey.description || "Survey builder"}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={survey.status === "published" ? "default" : "secondary"}>
              {survey.status}
            </Badge>
            <Button asChild variant="outline" size="sm">
              <Link to={`/crm/surveys/${encodeURIComponent(surveyId)}/results`}>
                <BarChart3 className="mr-1.5 h-4 w-4" />
                Results
              </Link>
            </Button>
            {isDraft ? (
              <Button
                size="sm"
                disabled={publishMut.isPending || sections.length === 0}
                onClick={() => publishMut.mutate()}
              >
                <Rocket className="mr-1.5 h-4 w-4" />
                {publishMut.isPending ? "Publishing…" : "Publish"}
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={() => {
                  setDistUnavailable(false);
                  setDistOpen(true);
                }}
              >
                <Send className="mr-1.5 h-4 w-4" />
                Distribute
              </Button>
            )}
          </div>
        }
      />

      {!isDraft ? (
        <Card>
          <CardContent className="py-4 text-sm text-muted-foreground">
            This survey is {survey.status}. Structure is read-only; publish creates an immutable
            version.
          </CardContent>
        </Card>
      ) : null}

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium">Sections</h2>
        {isDraft ? (
          <Button variant="outline" size="sm" onClick={() => setSectionOpen(true)}>
            <Plus className="mr-1.5 h-4 w-4" />
            Add section
          </Button>
        ) : null}
      </div>

      {sectionsQuery.isLoading ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Loading sections…
          </CardContent>
        </Card>
      ) : sections.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <Layers className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No sections yet. Add a section to begin building questions.
            </p>
            {isDraft ? (
              <Button variant="outline" size="sm" onClick={() => setSectionOpen(true)}>
                <Plus className="mr-1.5 h-4 w-4" />
                Add section
              </Button>
            ) : null}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {sections.map((section) => {
            const questions = questionsBySection[section.section_id] ?? [];
            return (
              <Card key={section.section_id}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <CardTitle className="text-base">{section.title}</CardTitle>
                      {section.description ? (
                        <CardDescription>{section.description}</CardDescription>
                      ) : null}
                    </div>
                    {isDraft ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={delSectionMut.isPending}
                        onClick={() => {
                          if (confirm(`Remove section "${section.title}"?`))
                            delSectionMut.mutate(section.section_id);
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    ) : null}
                  </div>
                </CardHeader>
                <CardContent className="space-y-2">
                  {questions.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No questions in this section.</p>
                  ) : (
                    <ul className="space-y-2">
                      {questions.map((q) => (
                        <li
                          key={q.question_id}
                          className="flex items-center justify-between gap-2 rounded-md border p-3"
                        >
                          <div className="min-w-0">
                            <p className="truncate text-sm font-medium">
                              {q.label}
                              {q.required ? <span className="text-destructive"> *</span> : null}
                            </p>
                            <p className="text-xs text-muted-foreground">{q.type}</p>
                          </div>
                          {isDraft ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                delQuestionMut.mutate({
                                  questionId: q.question_id,
                                  sectionId: section.section_id,
                                })
                              }
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  )}
                  {isDraft ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setActiveSection(section.section_id);
                        setQuestionOpen(true);
                      }}
                    >
                      <Plus className="mr-1.5 h-4 w-4" />
                      Add question
                    </Button>
                  ) : null}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Section dialog */}
      <Dialog open={sectionOpen} onOpenChange={setSectionOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add section</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="sec-title">Title</Label>
              <Input
                id="sec-title"
                value={sectionTitle}
                onChange={(e) => setSectionTitle(e.target.value)}
                maxLength={240}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="sec-desc">Description</Label>
              <Textarea
                id="sec-desc"
                value={sectionDesc}
                onChange={(e) => setSectionDesc(e.target.value)}
                maxLength={4000}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSectionOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!sectionTitle.trim() || sectionMut.isPending}
              onClick={() => sectionMut.mutate()}
            >
              {sectionMut.isPending ? "Adding…" : "Add"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Question dialog */}
      <Dialog open={questionOpen} onOpenChange={setQuestionOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add question</DialogTitle>
            <DialogDescription>Add a question to this section.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="q-label">Label</Label>
              <Input
                id="q-label"
                value={qLabel}
                onChange={(e) => setQLabel(e.target.value)}
                maxLength={400}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="q-type">Type</Label>
              <Select value={qType} onValueChange={setQType}>
                <SelectTrigger id="q-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {QUESTION_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {NEEDS_OPTIONS.has(qType) ? (
              <div className="space-y-1.5">
                <Label htmlFor="q-options">Options (one per line)</Label>
                <Textarea
                  id="q-options"
                  value={qOptions}
                  onChange={(e) => setQOptions(e.target.value)}
                  placeholder={"Option 1\nOption 2"}
                />
              </div>
            ) : null}
            <div className="flex items-center gap-2">
              <Switch id="q-required" checked={qRequired} onCheckedChange={setQRequired} />
              <Label htmlFor="q-required">Required</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setQuestionOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={
                !qLabel.trim() ||
                questionMut.isPending ||
                (NEEDS_OPTIONS.has(qType) && !qOptions.split("\n").some((o) => o.trim()))
              }
              onClick={() => questionMut.mutate()}
            >
              {questionMut.isPending ? "Adding…" : "Add"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Distribute dialog */}
      <Dialog open={distOpen} onOpenChange={setDistOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Distribute survey</DialogTitle>
            <DialogDescription>Send survey invitations by email.</DialogDescription>
          </DialogHeader>
          {distUnavailable ? (
            <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
              Survey distribution is not enabled on this platform. Ask an administrator to enable the
              <code className="mx-1">crm_survey_distribution</code> feature.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="dist-recipients">Recipients (comma or newline separated)</Label>
                <Textarea
                  id="dist-recipients"
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                  placeholder={"alice@example.com\nbob@example.com"}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="dist-subject">Subject</Label>
                <Input
                  id="dist-subject"
                  value={distSubject}
                  onChange={(e) => setDistSubject(e.target.value)}
                  maxLength={120}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="dist-message">Message (optional)</Label>
                <Textarea
                  id="dist-message"
                  value={distMessage}
                  onChange={(e) => setDistMessage(e.target.value)}
                  maxLength={2000}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDistOpen(false)}>
              Close
            </Button>
            {!distUnavailable ? (
              <Button
                disabled={
                  distributeMut.isPending ||
                  !recipients.split(/[\n,]/).some((r) => r.trim())
                }
                onClick={() => distributeMut.mutate()}
              >
                {distributeMut.isPending ? "Sending…" : "Send invitations"}
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
