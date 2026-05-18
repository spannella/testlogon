import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import PaymentIncidentQueuePage from "../PaymentIncidentQueuePage";

const listPaymentIncidents = vi.fn();
const getPaymentIncidentDetail = vi.fn();
const uploadPaymentIncidentEvidence = vi.fn();
const submitPaymentIncidentResponse = vi.fn();

vi.mock("@/api/endpoints/paymentIncidents", () => ({
  listPaymentIncidents: (...args: unknown[]) => listPaymentIncidents(...args),
  getPaymentIncidentDetail: (...args: unknown[]) => getPaymentIncidentDetail(...args),
  uploadPaymentIncidentEvidence: (...args: unknown[]) => uploadPaymentIncidentEvidence(...args),
  submitPaymentIncidentResponse: (...args: unknown[]) => submitPaymentIncidentResponse(...args),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { accessToken: string | null }) => unknown) => selector({ accessToken: "token" }),
}));

const canAccessPaymentIncidentQueue = vi.fn(() => true);
vi.mock("@/lib/adminCapabilities", () => ({
  canAccessPaymentIncidentQueue: (...args: unknown[]) => canAccessPaymentIncidentQueue(...args),
}));

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <PaymentIncidentQueuePage />
    </QueryClientProvider>,
  );
}

describe("PaymentIncidentQueuePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    canAccessPaymentIncidentQueue.mockReturnValue(true);
    listPaymentIncidents.mockResolvedValue({
      items: [
        {
          incident_id: "inc_1",
          provider: "stripe",
          incident_type: "dispute",
          status: "opened",
          response_due_at: String(Math.floor(Date.now() / 1000) + 7200),
        },
      ],
      count: 1,
    });
    getPaymentIncidentDetail.mockResolvedValue({
      incident_id: "inc_1",
      provider: "stripe",
      incident_type: "dispute",
      status: "opened",
      events: [{ event_type: "opened", created_at: "1700000000" }],
      evidence_versions: [],
      ticket_link: null,
    });
    uploadPaymentIncidentEvidence.mockResolvedValue({ version: 1 });
    submitPaymentIncidentResponse.mockResolvedValue({ ok: true });
  });

  it("shows unauthorized state", async () => {
    canAccessPaymentIncidentQueue.mockReturnValue(false);
    renderPage();
    expect(await screen.findByText("Unauthorized")).toBeInTheDocument();
  });

  it("renders queue/detail and performs evidence + submit actions", async () => {
    renderPage();

    expect(await screen.findByText("Queue")).toBeInTheDocument();
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
    expect(screen.getByText(/left|Overdue/)).toBeInTheDocument();

    await userEvent.type(screen.getByPlaceholderText("Evidence summary"), "upload docs");
    await userEvent.type(screen.getByPlaceholderText("File refs (comma-separated)"), "s3://file-1");
    await userEvent.click(screen.getByRole("button", { name: "Upload evidence" }));

    await waitFor(() => {
      expect(uploadPaymentIncidentEvidence).toHaveBeenCalledWith("inc_1", {
        summary: "upload docs",
        file_refs: ["s3://file-1"],
        evidence_items: [],
      });
    });

    await userEvent.type(screen.getByPlaceholderText("Response summary"), "submit this");
    await userEvent.type(screen.getByPlaceholderText("Rationale (optional)"), "documents attached");
    await userEvent.click(screen.getByRole("button", { name: "Submit response" }));

    await waitFor(() => {
      expect(submitPaymentIncidentResponse).toHaveBeenCalledWith("inc_1", {
        response_summary: "submit this",
        rationale: "documents attached",
      });
    });
  });
});
