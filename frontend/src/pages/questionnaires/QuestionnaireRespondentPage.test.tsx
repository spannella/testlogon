import { describe, expect, it, beforeEach, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import QuestionnaireRespondentPage from "./QuestionnaireRespondentPage";

const getPublishedQuestionnaireBySlug = vi.fn();
const startPublishedResponseSession = vi.fn();
const getPublishedResponseSessionState = vi.fn();
const savePublishedResponseSessionState = vi.fn();
const validatePublishedResponseSession = vi.fn();
const submitPublishedResponseSession = vi.fn();

vi.mock("@/api/endpoints/questionnaires", () => ({
  getPublishedQuestionnaireBySlug: (...args: unknown[]) => getPublishedQuestionnaireBySlug(...args),
  startPublishedResponseSession: (...args: unknown[]) => startPublishedResponseSession(...args),
  getPublishedResponseSessionState: (...args: unknown[]) => getPublishedResponseSessionState(...args),
  savePublishedResponseSessionState: (...args: unknown[]) => savePublishedResponseSessionState(...args),
  validatePublishedResponseSession: (...args: unknown[]) => validatePublishedResponseSession(...args),
  submitPublishedResponseSession: (...args: unknown[]) => submitPublishedResponseSession(...args),
}));

function renderPage(initial = "/questionnaires/published/slug/respond") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <QueryClientProvider client={qc}>
        <Routes>
          <Route path="/questionnaires/published/:publishedSlug/respond" element={<QuestionnaireRespondentPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("QuestionnaireRespondentPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getPublishedQuestionnaireBySlug.mockResolvedValue({
      version: {
        schema_json: {
          sections: [
            { section_id: "s1", title: "S1", questions: [{ question_id: "q1", label: "Q1", required: true }] },
            { section_id: "s2", title: "S2", questions: [{ question_id: "q2", label: "Q2", required: true }] },
          ],
        },
      },
    });
    startPublishedResponseSession.mockResolvedValue({ session: { response_session_id: "sess1" } });
    getPublishedResponseSessionState.mockResolvedValue({
      session: { response_session_id: "sess1", status: "in_progress", current_section_index: 1, current_question_id: "q2" },
      answers_by_question_id: { q1: "saved" },
    });
    savePublishedResponseSessionState.mockResolvedValue({
      session: { response_session_id: "sess1", status: "in_progress", current_section_index: 1, current_question_id: "q2" },
      answers_by_question_id: { q1: "saved", q2: "later" },
    });
    validatePublishedResponseSession.mockResolvedValue({
      is_valid: false,
      can_submit: false,
      has_blocking_form_error: false,
      errors: {
        q2: [{ code: "required", message: "Question is required" }],
        "form:submit": [{ code: "form_blocked", message: "Complete required questions", blocking: true }],
      },
    });
    submitPublishedResponseSession.mockResolvedValue({ session: { status: "submitted" }, result: { can_submit: true } });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("starts a session from start screen", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /start questionnaire/i }));
    await waitFor(() => expect(startPublishedResponseSession).toHaveBeenCalled());
  });

  it("shows inline and summary errors and blocks submit until corrected", async () => {
    renderPage("/questionnaires/published/slug/respond?session_id=sess1");

    expect(await screen.findByText("S2")).toBeInTheDocument();
    expect(screen.getByTestId("respondent-page-progress")).toHaveTextContent("Page 2/2");
    expect(screen.getByTestId("respondent-required-progress")).toHaveTextContent("Required answered 1/2");

    const q2 = screen.getByLabelText("answer-q2");
    fireEvent.change(q2, { target: { value: "x" } });

    await waitFor(() => expect(validatePublishedResponseSession).toHaveBeenCalled(), { timeout: 2000 });
    expect(await screen.findByTestId("field-error-q2")).toHaveTextContent("Question is required");
    expect(screen.getByTestId("respondent-error-summary")).toHaveTextContent("Complete required questions");

    const submitButton = screen.getByRole("button", { name: /submit/i });
    expect(submitButton).toBeDisabled();
    expect(submitPublishedResponseSession).not.toHaveBeenCalled();

    validatePublishedResponseSession.mockResolvedValueOnce({
      is_valid: true,
      can_submit: true,
      has_blocking_form_error: false,
      errors: {},
    });
    fireEvent.change(q2, { target: { value: "ok" } });
    await waitFor(() => expect(validatePublishedResponseSession).toHaveBeenCalledTimes(2), { timeout: 2000 });
    await waitFor(() => expect(screen.getByRole("button", { name: /submit/i })).not.toBeDisabled());
  });


  it("exposes aria bindings for errors and live status announcements", async () => {
    renderPage("/questionnaires/published/slug/respond?session_id=sess1");

    const q2 = await screen.findByLabelText("answer-q2");
    fireEvent.change(q2, { target: { value: "x" } });

    const fieldError = await screen.findByTestId("field-error-q2");
    expect(fieldError).toHaveAttribute("role", "status");
    expect(q2).toHaveAttribute("aria-invalid", "true");
    expect(q2).toHaveAttribute("aria-describedby", "field-error-q2");

    const summaryError = screen.getByTestId("respondent-error-summary");
    expect(summaryError).toHaveAttribute("role", "alert");
    expect(screen.getByTestId("respondent-live-announcer")).toHaveTextContent("Required answered");
  });

  it("shows final answer summary grouped by section and supports edit roundtrip", async () => {
    renderPage("/questionnaires/published/slug/respond?session_id=sess1");

    expect(await screen.findByText("S2")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /review summary/i }));

    expect(await screen.findByTestId("respondent-summary-view")).toBeInTheDocument();
    expect(screen.getByText("S1")).toBeInTheDocument();
    expect(screen.getByText("S2")).toBeInTheDocument();
    expect(screen.getByTestId("summary-answer-q1")).toHaveTextContent("saved");
    expect(screen.getByTestId("summary-answer-q2")).toHaveTextContent("—");

    const q1Row = screen.getByTestId("summary-question-q1");
    fireEvent.click(within(q1Row).getByRole("button", { name: /edit/i }));

    expect(await screen.findByLabelText("answer-q1")).toBeInTheDocument();
    expect(screen.getByTestId("respondent-page-progress")).toHaveTextContent("Page 1/2");

    fireEvent.change(screen.getByLabelText("answer-q1"), { target: { value: "updated" } });
    await waitFor(() => expect(savePublishedResponseSessionState).toHaveBeenCalled(), { timeout: 2000 });

    fireEvent.click(screen.getByRole("button", { name: /^next$/i }));
    fireEvent.click(await screen.findByRole("button", { name: /review summary/i }));

    expect(await screen.findByTestId("summary-answer-q1")).toHaveTextContent("updated");
  });
});
