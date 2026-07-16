import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import ModerationBoardPage from "../ModerationBoardPage";

const listModerationTickets = vi.fn();
const getModerationTicketDetail = vi.fn();
const claimModerationTicket = vi.fn();
const dismissModerationCase = vi.fn();
const confirmModerationCase = vi.fn();
const finalCallModerationCase = vi.fn();
const bulkModerationAction = vi.fn();
const getModerationKpis = vi.fn();
const listModerationBans = vi.fn();
const liftModerationBan = vi.fn();
const getTicketAuditTrail = vi.fn();
const unclaimModerationTicket = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

// MODX-17: the board now drives the STATE MACHINE (dismiss / confirm / final-call), not the
// divergent legacy resolve path — the mocks + assertions exercise that surface.
vi.mock("@/api/endpoints/moderation", () => ({
  listModerationTickets: (...args: unknown[]) => listModerationTickets(...args),
  getModerationTicketDetail: (...args: unknown[]) => getModerationTicketDetail(...args),
  claimModerationTicket: (...args: unknown[]) => claimModerationTicket(...args),
  dismissModerationCase: (...args: unknown[]) => dismissModerationCase(...args),
  confirmModerationCase: (...args: unknown[]) => confirmModerationCase(...args),
  finalCallModerationCase: (...args: unknown[]) => finalCallModerationCase(...args),
  bulkModerationAction: (...args: unknown[]) => bulkModerationAction(...args),
  getModerationKpis: (...args: unknown[]) => getModerationKpis(...args),
  listModerationBans: (...args: unknown[]) => listModerationBans(...args),
  liftModerationBan: (...args: unknown[]) => liftModerationBan(...args),
  getTicketAuditTrail: (...args: unknown[]) => getTicketAuditTrail(...args),
  unclaimModerationTicket: (...args: unknown[]) => unclaimModerationTicket(...args),
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
  assigned_admin_user_id: null,
  report_count: 3,
  aggregated_topics: ["violence_threats"],
  latest_report_at: 1700000000,
  updated_at: 1700000000,
  created_at: 1700000000,
};

const detail = {
  ticket,
  content_snapshot: { exists: true, author_user_id: "u_offender" },
  linked_reports: [
    {
      report_id: "rpt_1",
      reporter_user_id: "u_reporter",
      topics: ["violence_threats"],
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
    total_enforcements: 2,
  },
  prior_enforcement_history: [
    {
      user_id: "u_offender",
      enforcement_id: "enf_1",
      enforcement_type: "warn",
      status: "recorded",
      source_ticket_id: "modtk_0",
      created_at: 1699990000,
      created_by_admin_user_id: "admin_9",
      duration_days: 0,
      note: "prior warning",
    },
  ],
  case_state: "under_review",
  hold_until: null,
  owner_user_id: "u_offender",
  distinct_reporter_count: 3,
  needs_human_review: false,
  human_review_reason: null,
  illegal_lane: false,
  sla_deadline: null,
  poster_response: null,
  responded_at: null,
};

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ModerationBoardPage />
    </QueryClientProvider>,
  );
}

describe("ModerationBoardPage state machine", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listModerationTickets.mockResolvedValue({ items: [ticket], next_cursor: null });
    getModerationTicketDetail.mockResolvedValue(detail);
    claimModerationTicket.mockResolvedValue({ ...ticket, assigned_admin_user_id: "admin_1" });
    dismissModerationCase.mockResolvedValue({ ok: true, ticket_id: "modtk_1", case_id: "case_1", state: "dismissed", hidden: false });
    confirmModerationCase.mockResolvedValue({ ok: true, ticket_id: "modtk_1", case_id: "case_1", state: "hold", hidden: true });
    finalCallModerationCase.mockResolvedValue({ ok: true, ticket_id: "modtk_1", case_id: "case_1", state: "reinstated", hidden: false });
    bulkModerationAction.mockResolvedValue({ action: "dismiss", total: 1, succeeded: 1, failed: 0, results: [] });
    getModerationKpis.mockResolvedValue({
      generated_at: 1700000000, lookback_hours: 24, surge_window_minutes: 30, ticket_volume: 5,
      resolution_count: 2, resolution_latency_avg_seconds: 100, resolution_latency_p95_seconds: 300,
      warning_count: 1, ban_count: 0, warning_rate: 0.5, ban_rate: 0, open_ticket_count: 4,
      critical_backlog: 1, oldest_open_age_minutes: 12, on_hold_count: 2, extortion_criminal_reports_window_count: 0,
    });
    listModerationBans.mockResolvedValue({ items: [], next_cursor: null });
    getTicketAuditTrail.mockResolvedValue({
      items: [
        {
          audit_id: "aud_1",
          action: "case_confirmed",
          actor_user_id: "admin_9",
          ticket_id: "modtk_1",
          content_type: "feed_post",
          content_id: "post_1",
          target_user_id: "u_offender",
          created_at: 1700000020,
          metadata: {},
        },
      ],
    });
    unclaimModerationTicket.mockResolvedValue({ ...ticket, assigned_admin_user_id: null });
  });

  it("renders the KPI strip with a hold-excluding backlog", async () => {
    renderPage();
    expect(await screen.findByText("Open backlog")).toBeInTheDocument();
    expect(screen.getByText("On hold")).toBeInTheDocument();
  });

  it("confirms a violation via the state machine (30-day hold)", async () => {
    renderPage();
    const confirmBtn = await screen.findByRole("button", { name: /Confirm violation/i });
    await userEvent.click(confirmBtn);
    await waitFor(() => expect(confirmModerationCase).toHaveBeenCalledWith("modtk_1"));
    expect(toastSuccess).toHaveBeenCalled();
  });

  it("dismisses a case (restores content)", async () => {
    renderPage();
    const dismissBtn = await screen.findByRole("button", { name: /Dismiss \(restore\)/i });
    await userEvent.click(dismissBtn);
    await waitFor(() => expect(dismissModerationCase).toHaveBeenCalledWith("modtk_1"));
  });

  it("renders prior enforcement rows from the real projected fields", async () => {
    renderPage();
    expect(await screen.findByText(/prior warning/i)).toBeInTheDocument();
  });

  it("surfaces the needs-human-review lane signal from the detail DTO", async () => {
    getModerationTicketDetail.mockResolvedValue({
      ...detail,
      needs_human_review: true,
      human_review_reason: "velocity_burst",
    });
    renderPage();
    expect(await screen.findByText(/needs human review/i)).toBeInTheDocument();
  });

  it("lazy-loads the MODX-20 audit trail when opened", async () => {
    renderPage();
    const showBtn = await screen.findByRole("button", { name: /^Show$/i });
    await userEvent.click(showBtn);
    await waitFor(() => expect(getTicketAuditTrail).toHaveBeenCalledWith("modtk_1"));
    expect(await screen.findByText(/case_confirmed/i)).toBeInTheDocument();
  });

  it("releases a claim via the MODX-20 unclaim endpoint", async () => {
    getModerationTicketDetail.mockResolvedValue({
      ...detail,
      ticket: { ...ticket, assigned_admin_user_id: "admin_2" },
    });
    renderPage();
    const releaseBtn = await screen.findByRole("button", { name: /Release claim/i });
    await userEvent.click(releaseBtn);
    await waitFor(() => expect(unclaimModerationTicket).toHaveBeenCalledWith("modtk_1", undefined));
  });
});
