import { describe, expect, it, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { JiraLinkedPanel } from "./JiraLinkedPanel";

const getTicketJiraSyncStatus = vi.fn();
const linkExistingJiraIssueToTicket = vi.fn();
const unlinkJiraIssueFromTicket = vi.fn();
const resolveJiraConflict = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/jira", () => ({
  getTicketJiraSyncStatus: (...args: unknown[]) => getTicketJiraSyncStatus(...args),
  linkExistingJiraIssueToTicket: (...args: unknown[]) => linkExistingJiraIssueToTicket(...args),
  unlinkJiraIssueFromTicket: (...args: unknown[]) => unlinkJiraIssueFromTicket(...args),
  resolveJiraConflict: (...args: unknown[]) => resolveJiraConflict(...args),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
  },
}));

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <JiraLinkedPanel ticketId="tkt_1" currentTicket={{ title: "Local title", status: "To Do" }} />
    </QueryClientProvider>,
  );
}

describe("JiraLinkedPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getTicketJiraSyncStatus.mockResolvedValue({
      ticket_id: "tkt_1",
      linked: false,
      sync_state: "not_linked",
      conflict_fields: [],
      conflict_local_values: {},
      conflict_remote_values: {},
    });
  });

  it("renders empty state and validates link input fields", async () => {
    renderPanel();
    expect(await screen.findByText("No Jira issue linked.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /link jira issue/i }));
    expect(screen.getByText("Workspace ID is required to link a Jira issue.")).toBeInTheDocument();
    expect(linkExistingJiraIssueToTicket).not.toHaveBeenCalled();
  });

  it("renders linked metadata and supports unlink confirmation flow", async () => {
    getTicketJiraSyncStatus.mockResolvedValueOnce({
      ticket_id: "tkt_1",
      linked: true,
      sync_state: "in_sync",
      link_id: "jlink_1",
      external_issue_key: "PROJ-7",
      jira_status: "In Progress",
      last_synced_at: 1700000000,
      conflict_fields: [],
      conflict_local_values: {},
      conflict_remote_values: {},
    });
    unlinkJiraIssueFromTicket.mockResolvedValueOnce({ ticket_id: "tkt_1", link_id: "jlink_1", sync_state: "deleted" });

    renderPanel();
    expect(await screen.findByText(/Jira key:/i)).toBeInTheDocument();
    expect(screen.getByText("PROJ-7")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^unlink$/i }));
    fireEvent.click(await screen.findByRole("button", { name: /^unlink$/i }));

    await waitFor(() => {
      expect(unlinkJiraIssueFromTicket).toHaveBeenCalledWith("tkt_1", "jlink_1");
      expect(toastSuccess).toHaveBeenCalledWith("Jira issue unlinked");
    });
  });

  it("shows conflict modal with local/jira values and resolves without full reload", async () => {
    getTicketJiraSyncStatus.mockResolvedValue({
      ticket_id: "tkt_1",
      linked: true,
      sync_state: "conflict",
      link_id: "jlink_1",
      external_issue_key: "PROJ-7",
      jira_status: "In Progress",
      last_synced_at: 1700000000,
      conflict_fields: ["title", "status"],
      conflict_local_values: { title: "Local title", status: "To Do" },
      conflict_remote_values: { title: "Remote title", status: "In Progress" },
    });
    resolveJiraConflict.mockResolvedValueOnce({
      ticket_id: "tkt_1",
      link_id: "jlink_1",
      action: "keep_internal",
      sync_state: "in_sync",
      follow_up_tasks: 1,
    });

    renderPanel();
    fireEvent.change(screen.getByLabelText("Workspace ID"), { target: { value: "ws_1" } });
    fireEvent.click(await screen.findByRole("button", { name: /resolve conflict/i }));

    expect(await screen.findByText("Resolve Jira Sync Conflict")).toBeInTheDocument();
    expect(screen.getByText("Local title")).toBeInTheDocument();
    expect(screen.getByText("Remote title")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /keep internal/i }));
    await waitFor(() => {
      expect(resolveJiraConflict).toHaveBeenCalledWith({
        ticketId: "tkt_1",
        linkId: "jlink_1",
        workspaceId: "ws_1",
        action: "keep_internal",
        currentTicket: { title: "Local title", status: "To Do" },
      });
      expect(toastSuccess).toHaveBeenCalledWith("Conflict resolved");
    });
  });

  it("surfaces sync-status load error state", async () => {
    getTicketJiraSyncStatus.mockRejectedValueOnce(new Error("fetch failed"));
    renderPanel();
    expect(await screen.findByText("Failed to load Jira sync status.")).toBeInTheDocument();
  });
});
