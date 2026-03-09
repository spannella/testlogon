import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import ModerationBoardPage from "../ModerationBoardPage";

const listModerationTickets = vi.fn();
const getModerationTicketDetail = vi.fn();
const resolveModerationTicket = vi.fn();
const claimModerationTicket = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/moderation", () => ({
  listModerationTickets: (...args: unknown[]) => listModerationTickets(...args),
  getModerationTicketDetail: (...args: unknown[]) => getModerationTicketDetail(...args),
  resolveModerationTicket: (...args: unknown[]) => resolveModerationTicket(...args),
  claimModerationTicket: (...args: unknown[]) => claimModerationTicket(...args),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { accessToken: string | null; userId: string | null }) => unknown) =>
    selector({ accessToken: "token", userId: "admin_1" }),
}));

vi.mock("@/lib/adminCapabilities", () => ({
  canAccessModerationBoard: vi.fn(() => true),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
  },
}));

const ticket = {
  ticket_id: "modtk_1",
  content_type: "feed_post",
  content_id: "post_1",
  status: "open",
  priority: "high",
  queue: "newsfeed",
  assigned_admin_user_id: "UNASSIGNED",
  report_count: 1,
  aggregated_topics: ["criminal"],
  latest_report_at: 1700000010,
  updated_at: 1700000010,
  created_at: 1700000000,
};

const detail = {
  ticket,
  content_snapshot: { exists: true, author_user_id: "u_offender" },
  linked_reports: [
    {
      report_id: "rpt_1",
      reporter_user_id: "u_reporter",
      topics: ["criminal"],
      reason_text: "Threat",
      created_at: 1700000010,
      metadata: {},
    },
  ],
  offender_history_summary: {
    offender_user_id: "u_offender",
    total_tickets: 2,
    open_tickets: 1,
    total_reports: 3,
  },
  prior_enforcement_history: [],
};

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ModerationBoardPage />
    </QueryClientProvider>,
  );
}

describe("ModerationBoardPage decision panel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listModerationTickets.mockResolvedValue({ items: [ticket], next_cursor: null });
    getModerationTicketDetail.mockResolvedValue(detail);
    resolveModerationTicket.mockResolvedValue({ ...ticket, status: "closed" });
    claimModerationTicket.mockResolvedValue({ ...ticket, assigned_admin_user_id: "admin_1" });
  });

  it("applies no_violation with enforced none action", async () => {
    renderPage();

    expect(await screen.findByText("Decision panel")).toBeInTheDocument();

    const selects = screen.getAllByRole("combobox");
    const [resolutionSelect, enforcementSelect] = selects.slice(-2) as HTMLSelectElement[];

    await userEvent.selectOptions(resolutionSelect, "no_violation");
    expect(enforcementSelect).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Apply decision" }));

    await waitFor(() => {
      expect(resolveModerationTicket).toHaveBeenCalledWith("modtk_1", {
        resolution: "no_violation",
        enforcement_action: "none",
        note: undefined,
      });
    });
    expect(toastSuccess).toHaveBeenCalledWith("Decision recorded");
  });

  it("submits content_removed + warn decision with trimmed note", async () => {
    renderPage();

    expect(await screen.findByText("Decision panel")).toBeInTheDocument();

    const selects = screen.getAllByRole("combobox");
    const [resolutionSelect, enforcementSelect] = selects.slice(-2) as HTMLSelectElement[];

    await userEvent.selectOptions(resolutionSelect, "content_removed");
    await userEvent.selectOptions(enforcementSelect, "warn");

    const note = screen.getByPlaceholderText("Decision note (optional)");
    await userEvent.type(note, "  enforce warning please  ");
    await userEvent.click(screen.getByRole("button", { name: "Apply decision" }));

    await waitFor(() => {
      expect(resolveModerationTicket).toHaveBeenCalledWith("modtk_1", {
        resolution: "content_removed",
        enforcement_action: "warn",
        note: "enforce warning please",
      });
    });
  });
});
