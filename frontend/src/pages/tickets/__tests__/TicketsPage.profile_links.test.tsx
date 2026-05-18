import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import TicketsPage from "../TicketsPage";

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { userId: string; accessToken: string | null }) => unknown) => selector({ userId: "admin-1", accessToken: "token" }),
}));

vi.mock("@/lib/adminCapabilities", () => ({
  getRoleFromAccessToken: () => "admin",
}));

vi.mock("@/api/endpoints/tickets", () => ({
  listTickets: vi.fn(async () => ({
    items: [{
      ticket_id: "t1",
      subject: "Printer broken",
      owner_sub: "user-owner",
      assigned_admin_sub: "admin-2",
      status: "open",
      updated_at: 1,
      messages: [],
      activity: [],
    }],
    next_cursor: null,
  })),
  getAdminTicketSummary: vi.fn(async () => ({ summary: { by_status: { open: 1 }, unassigned_count: 0 } })),
  getTicket: vi.fn(async () => ({ ticket: {
    ticket_id: "t1",
    subject: "Printer broken",
    owner_sub: "user-owner",
    assigned_admin_sub: "admin-2",
    status: "open",
    updated_at: 1,
    messages: [{ message_id: "m1", sender_sub: "user-reporter", sender_role: "user", body: "Need help", created_at: 1 }],
    activity: [],
  } })),
  createTicket: vi.fn(),
  addTicketMessage: vi.fn(),
  assignTicket: vi.fn(),
  setTicketStatus: vi.fn(),
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <TicketsPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("TicketsPage profile links", () => {
  it("renders owner/assignee/reporter as canonical profile links", async () => {
    renderPage();

    const owner = await screen.findByRole("link", { name: /open user-owner profile/i });
    const assignee = await screen.findByRole("link", { name: /open admin-2 profile/i });
    const reporter = await screen.findByRole("link", { name: /open user-reporter profile/i });

    expect(owner).toHaveAttribute("href", "/u/user-owner");
    expect(assignee).toHaveAttribute("href", "/u/admin-2");
    expect(reporter).toHaveAttribute("href", "/u/user-reporter");
  });
});
