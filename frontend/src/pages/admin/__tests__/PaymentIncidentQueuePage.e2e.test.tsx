import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";

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

vi.mock("@/lib/adminCapabilities", () => ({
  canAccessPaymentIncidentQueue: () => true,
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

describe("PaymentIncidentQueuePage e2e provider matrix", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listPaymentIncidents.mockResolvedValue({
      items: [
        { incident_id: "inc_s", provider: "stripe", incident_type: "dispute", status: "opened", response_due_at: "1700001000" },
        { incident_id: "inc_p", provider: "paypal", incident_type: "dispute", status: "evidence_required", response_due_at: "1700002000" },
        { incident_id: "inc_c", provider: "ccbill", incident_type: "chargeback", status: "opened", response_due_at: "1700003000" },
      ],
      count: 3,
    });
    getPaymentIncidentDetail.mockResolvedValue({
      incident_id: "inc_s",
      provider: "stripe",
      incident_type: "dispute",
      status: "opened",
      events: [],
      evidence_versions: [],
      ticket_link: null,
    });
    uploadPaymentIncidentEvidence.mockResolvedValue({ version: 1 });
    submitPaymentIncidentResponse.mockResolvedValue({ ok: true });
  });

  it("renders queue rows across stripe/paypal/ccbill", async () => {
    renderPage();
    expect(await screen.findByText(/stripe/i)).toBeInTheDocument();
    expect(screen.getByText(/paypal/i)).toBeInTheDocument();
    expect(screen.getByText(/ccbill/i)).toBeInTheDocument();
  });
});
