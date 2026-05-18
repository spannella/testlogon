import { describe, expect, it, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import { JiraIntegrationSettings } from "./JiraIntegrationSettings";

const getJiraStatus = vi.fn();
const beginJiraConnect = vi.fn();
const completeJiraCallback = vi.fn();
const disconnectJira = vi.fn();
const listJiraProjects = vi.fn();
const getJiraPreferences = vi.fn();
const putJiraPreferences = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/jira", () => ({
  getJiraStatus: (...args: unknown[]) => getJiraStatus(...args),
  beginJiraConnect: (...args: unknown[]) => beginJiraConnect(...args),
  completeJiraCallback: (...args: unknown[]) => completeJiraCallback(...args),
  disconnectJira: (...args: unknown[]) => disconnectJira(...args),
  listJiraProjects: (...args: unknown[]) => listJiraProjects(...args),
  getJiraPreferences: (...args: unknown[]) => getJiraPreferences(...args),
  putJiraPreferences: (...args: unknown[]) => putJiraPreferences(...args),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
  },
}));

function renderPage(initial = "/settings") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <QueryClientProvider client={qc}>
        <JiraIntegrationSettings />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("JiraIntegrationSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getJiraStatus.mockResolvedValue({ connected: false, items: [] });
    listJiraProjects.mockResolvedValue({ items: [] });
    getJiraPreferences.mockResolvedValue({ workspace_id: "ws_1", cloud_id: "cloud_1", project_keys: [] });
    putJiraPreferences.mockResolvedValue({ workspace_id: "ws_1", cloud_id: "cloud_1", project_keys: [] });
  });

  it("shows validation error for missing workspace on connect", async () => {
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: /connect jira/i }));
    expect(screen.getByText("Workspace ID is required.")).toBeInTheDocument();
    expect(beginJiraConnect).not.toHaveBeenCalled();
  });

  it("renders empty connection state and handles status error", async () => {
    getJiraStatus.mockRejectedValueOnce(new Error("boom"));
    renderPage();
    fireEvent.change(screen.getByLabelText("Workspace ID"), { target: { value: "ws_1" } });
    await waitFor(() => expect(getJiraStatus).toHaveBeenCalledWith("ws_1"));
    expect(await screen.findByText("Failed to load Jira connection status.")).toBeInTheDocument();
  });

  it("loads connected state and saves project preferences", async () => {
    getJiraStatus.mockResolvedValueOnce({
      connected: true,
      items: [{ connection_id: "conn_1", workspace_id: "ws_1", cloud_id: "cloud_1", site_url: "https://example.atlassian.net", status: "active", scopes: [] }],
    });
    listJiraProjects.mockResolvedValueOnce({
      items: [{ cloud_id: "cloud_1", project_id: "p1", project_key: "PROJ", name: "Project", is_private: false }],
    });
    getJiraPreferences.mockResolvedValueOnce({ workspace_id: "ws_1", cloud_id: "cloud_1", project_keys: [] });
    putJiraPreferences.mockResolvedValueOnce({ workspace_id: "ws_1", cloud_id: "cloud_1", project_keys: ["PROJ"] });

    renderPage();
    fireEvent.change(screen.getByLabelText("Workspace ID"), { target: { value: "ws_1" } });

    expect(await screen.findByText(/Connected to https:\/\/example.atlassian.net/i)).toBeInTheDocument();
    const checkbox = await screen.findByRole("checkbox");
    fireEvent.click(checkbox);
    fireEvent.click(screen.getByRole("button", { name: /save project preferences/i }));

    await waitFor(() => {
      expect(putJiraPreferences).toHaveBeenCalledWith("ws_1", "cloud_1", ["PROJ"]);
      expect(toastSuccess).toHaveBeenCalledWith("Jira project preferences saved");
    });
  });

  it("completes oauth callback flow when code/state exist in url", async () => {
    completeJiraCallback.mockResolvedValueOnce({ status: "connected", connection_id: "conn_1" });
    renderPage("/settings?code=abc&state=st_1");
    await waitFor(() => expect(completeJiraCallback).toHaveBeenCalledWith("abc", "st_1"));
    expect(toastSuccess).toHaveBeenCalledWith("Jira connected");
  });
});
