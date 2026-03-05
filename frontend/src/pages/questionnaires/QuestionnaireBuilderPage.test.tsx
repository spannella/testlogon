import { describe, expect, it, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import QuestionnaireBuilderPage from "./QuestionnaireBuilderPage";

const getQuestionnaireDraft = vi.fn();
const listQuestionnaireSections = vi.fn();
const listQuestionnaireQuestions = vi.fn();
const updateQuestionnaireDraft = vi.fn();
const createQuestionnaireSection = vi.fn();
const updateQuestionnaireSection = vi.fn();
const deleteQuestionnaireSection = vi.fn();
const reorderQuestionnaireSections = vi.fn();
const createQuestionnaireQuestion = vi.fn();
const updateQuestionnaireQuestion = vi.fn();
const deleteQuestionnaireQuestion = vi.fn();
const validateQuestionnaireDraft = vi.fn();
const getQuestionnaireDraftSchema = vi.fn();
const getQuestionnaireAnalytics = vi.fn();
const publishQuestionnaireDraft = vi.fn();

vi.mock("@/api/endpoints/questionnaires", () => ({
  getQuestionnaireDraft: (...args: unknown[]) => getQuestionnaireDraft(...args),
  listQuestionnaireSections: (...args: unknown[]) => listQuestionnaireSections(...args),
  listQuestionnaireQuestions: (...args: unknown[]) => listQuestionnaireQuestions(...args),
  updateQuestionnaireDraft: (...args: unknown[]) => updateQuestionnaireDraft(...args),
  createQuestionnaireSection: (...args: unknown[]) => createQuestionnaireSection(...args),
  updateQuestionnaireSection: (...args: unknown[]) => updateQuestionnaireSection(...args),
  deleteQuestionnaireSection: (...args: unknown[]) => deleteQuestionnaireSection(...args),
  reorderQuestionnaireSections: (...args: unknown[]) => reorderQuestionnaireSections(...args),
  createQuestionnaireQuestion: (...args: unknown[]) => createQuestionnaireQuestion(...args),
  updateQuestionnaireQuestion: (...args: unknown[]) => updateQuestionnaireQuestion(...args),
  deleteQuestionnaireQuestion: (...args: unknown[]) => deleteQuestionnaireQuestion(...args),
  validateQuestionnaireDraft: (...args: unknown[]) => validateQuestionnaireDraft(...args),
  getQuestionnaireDraftSchema: (...args: unknown[]) => getQuestionnaireDraftSchema(...args),
  getQuestionnaireAnalytics: (...args: unknown[]) => getQuestionnaireAnalytics(...args),
  publishQuestionnaireDraft: (...args: unknown[]) => publishQuestionnaireDraft(...args),
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/questionnaires/q1/builder"]}>
      <QueryClientProvider client={qc}>
        <Routes>
          <Route path="/questionnaires/:questionnaireId/builder" element={<QuestionnaireBuilderPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("QuestionnaireBuilderPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getQuestionnaireDraft.mockResolvedValue({
      draft: { questionnaire_id: "q1", title: "Initial", description: "Desc", status: "draft", owner_id: "u1", updated_at: "1" },
    });
    listQuestionnaireSections.mockResolvedValue({
      items: [{ questionnaire_id: "q1", section_id: "s1", title: "Section 1", description: "A", position: 0 }],
    });
    listQuestionnaireQuestions.mockResolvedValue({
      items: [
        {
          question_id: "q_slider",
          section_id: "s1",
          type: "slider",
          label: "How many?",
          required: true,
          hint: "Short hint",
          config_json: { min: 1, max: 9, step: 2, placeholder: "Enter number", help_text: "Longer help" },
          position: 0,
        },
      ],
    });
    updateQuestionnaireDraft.mockResolvedValue({ draft: {} });
    createQuestionnaireSection.mockResolvedValue({ section: { questionnaire_id: "q1", section_id: "s2", title: "Section 2", description: "", position: 1 } });
    updateQuestionnaireSection.mockResolvedValue({ section: {} });
    deleteQuestionnaireSection.mockResolvedValue({ section: {} });
    reorderQuestionnaireSections.mockResolvedValue({ items: [] });
    createQuestionnaireQuestion.mockResolvedValue({
      question: {
        question_id: "q_new",
        section_id: "s1",
        type: "text",
        label: "Untitled question",
        required: false,
        hint: "",
        config_json: { minLength: 0, maxLength: 200 },
        position: 1,
      },
    });
    updateQuestionnaireQuestion.mockResolvedValue({ question: {} });
    deleteQuestionnaireQuestion.mockResolvedValue({ question: {} });
    validateQuestionnaireDraft.mockResolvedValue({ errors: {}, is_valid: true, can_submit: true, has_blocking_form_error: false });
    getQuestionnaireDraftSchema.mockResolvedValue({ sections: [{ section_id: "s1", title: "Section 1", questions: [{ question_id: "q_slider", label: "How many?", hint: "Short hint", config_json: { placeholder: "Enter number" } }] }] });
    getQuestionnaireAnalytics.mockResolvedValue({
      analytics: {
        generated_at: "1772565000",
        freshness_sla_seconds: 60,
        versions: [
          {
            version_id: "ver_2",
            version_number: 2,
            funnel: { starts: 10, completions: 7, completion_rate: 0.7 },
            average_completion_seconds: 85,
            dropoff_points: [{ label: "Section 1 / q_slider", count: 2 }],
            validation_hotspots: [{ key: "form:submit", count: 3 }],
          },
        ],
        totals: {
          starts: 10,
          completions: 7,
          top_dropoffs: [{ label: "Section 1 / q_slider", count: 2 }],
          top_validation_hotspots: [{ key: "form:submit", count: 3 }],
        },
      },
    });
    publishQuestionnaireDraft.mockResolvedValue({ version: { version_id: "ver_2", published_at: "2026-03-03T00:00:00Z" } });
  });

  it("supports add/remove/reorder section and question operations", async () => {
    renderPage();

    expect(await screen.findByDisplayValue("Section 1")).toBeInTheDocument();
    expect(await screen.findByDisplayValue("How many?")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /add section/i }));
    await waitFor(() => expect(createQuestionnaireSection).toHaveBeenCalled());

    const moveDown = screen.getAllByRole("button", { name: "Move down" })[0];
    if (moveDown) fireEvent.click(moveDown);
    await waitFor(() => expect(reorderQuestionnaireSections).toHaveBeenCalled());

    const addQuestionButtons = screen.getAllByRole("button", { name: /add question/i });
    if (addQuestionButtons[0]) fireEvent.click(addQuestionButtons[0]);
    await waitFor(() => expect(createQuestionnaireQuestion).toHaveBeenCalled());

    const deleteQuestionButtons = screen.getAllByRole("button", { name: "Delete question" });
    if (deleteQuestionButtons[0]) fireEvent.click(deleteQuestionButtons[0]);
    await waitFor(() => expect(deleteQuestionnaireQuestion).toHaveBeenCalled());
  });

  it("autosaves metadata edits and rehydrates persisted question config", async () => {
    renderPage();

    expect(await screen.findByDisplayValue("1")).toBeInTheDocument(); // slider min
    expect(await screen.findByDisplayValue("9")).toBeInTheDocument(); // slider max
    expect(screen.getByLabelText("Placeholder")).toHaveValue("Enter number");
    const previewInput = screen.getByLabelText("Preview q_slider");
    expect(previewInput).toHaveAttribute("aria-describedby", "preview-hint-q_slider");
    expect(screen.getByText(/Short hint Longer help/)).toBeInTheDocument();

    const title = await screen.findByLabelText("Title");
    fireEvent.change(title, { target: { value: "Updated title" } });
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
    await waitFor(() => expect(updateQuestionnaireDraft).toHaveBeenCalled(), { timeout: 2500 });
  });

  it("prevents saving malformed question config", async () => {
    renderPage();
    const stepInput = await screen.findByLabelText("Slider step");
    fireEvent.change(stepInput, { target: { value: "0" } });

    expect(await screen.findByText(/slider config requires numeric min\/max/i)).toBeInTheDocument();
    await waitFor(() => expect(updateQuestionnaireQuestion).not.toHaveBeenCalled(), { timeout: 1200 });
  });

  it("supports draft→preview→publish flow with readiness checks", async () => {
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /preview mode/i }));
    expect(await screen.findByTestId("questionnaire-preview-mode")).toBeInTheDocument();
    expect(screen.getByLabelText("Preview respondent q_slider")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^publish$/i }));
    expect(await screen.findByTestId("publish-readiness-checklist")).toHaveTextContent("Ready to publish");

    fireEvent.click(screen.getByRole("button", { name: /confirm publish/i }));
    await waitFor(() => expect(publishQuestionnaireDraft).toHaveBeenCalled());
    expect(await screen.findByTestId("publish-success")).toHaveTextContent("ver_2");
  });


  it("announces save state and metadata hints for assistive tech", async () => {
    renderPage();

    expect(await screen.findByTestId("builder-save-indicator")).toHaveAttribute("role", "status");
    expect(screen.getByTestId("builder-save-indicator")).toHaveAttribute("aria-live", "polite");
    expect(screen.getAllByText("All changes saved").length).toBeGreaterThan(0);

    const previewHint = screen.getByText(/Short hint Longer help/);
    expect(previewHint).toHaveAttribute("role", "note");
  });

  it("renders analytics funnel and hotspot widgets", async () => {
    renderPage();

    expect(await screen.findByTestId("questionnaire-analytics-card")).toBeInTheDocument();
    expect(screen.getByTestId("analytics-total-starts")).toHaveTextContent("10");
    expect(screen.getByTestId("analytics-total-completions")).toHaveTextContent("7");
    expect(screen.getByTestId("analytics-funnel-ver_2")).toHaveTextContent("10 starts → 7 completions (70%)");
    expect(screen.getByTestId("analytics-dropoff-list")).toHaveTextContent("Section 1 / q_slider: 2");
    expect(screen.getByTestId("analytics-hotspot-list")).toHaveTextContent("form:submit: 3");
  });

  it("supports rule save/load/edit flows and blocks invalid references", async () => {
    window.localStorage.setItem(
      "qnr_rules_q1",
      JSON.stringify([
        {
          id: "rule1",
          scope: "group",
          group_id: "g1",
          rule_type: "min_answered",
          question_ids: ["q_slider"],
          config: { min_answered: 1 },
        },
      ]),
    );

    renderPage();

    expect(await screen.findByTestId("rule-rule1")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Question IDs (csv)"), { target: { value: "unknown_q" } });
    expect(await screen.findByTestId("rule-reference-errors")).toHaveTextContent("unknown question");

    const runPreview = screen.getByRole("button", { name: /run evaluation preview/i });
    fireEvent.click(runPreview);
    expect(validateQuestionnaireDraft).not.toHaveBeenCalled();
    expect(await screen.findByText(/fix invalid rule references before preview/i)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Question IDs (csv)"), { target: { value: "q_slider" } });
    fireEvent.click(runPreview);
    await waitFor(() => expect(validateQuestionnaireDraft).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      const stored = window.localStorage.getItem("qnr_rules_q1");
      expect(stored).toContain("[]");
    });
  });

});
