import { describe, expect, it, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import TicketSpacesPage from "../TicketSpacesPage";
import TicketSpaceDetailPage from "../TicketSpaceDetailPage";

const createTicketSpace = vi.fn();
const listTicketSpaces = vi.fn();
const getTicketSpace = vi.fn();
const listSpaceTickets = vi.fn();
const getSpaceTicket = vi.fn();
const assignSpaceTicket = vi.fn();
const addSpaceTicketMessage = vi.fn();
const setSpaceTicketStatus = vi.fn();
const addTicketSpaceMember = vi.fn();
const removeTicketSpaceMember = vi.fn();

vi.mock("@/api/endpoints/tickets", () => ({
  createTicketSpace: (...args: unknown[]) => createTicketSpace(...args),
  listTicketSpaces: (...args: unknown[]) => listTicketSpaces(...args),
  getTicketSpace: (...args: unknown[]) => getTicketSpace(...args),
  listSpaceTickets: (...args: unknown[]) => listSpaceTickets(...args),
  getSpaceTicket: (...args: unknown[]) => getSpaceTicket(...args),
  assignSpaceTicket: (...args: unknown[]) => assignSpaceTicket(...args),
  addSpaceTicketMessage: (...args: unknown[]) => addSpaceTicketMessage(...args),
  setSpaceTicketStatus: (...args: unknown[]) => setSpaceTicketStatus(...args),
  addTicketSpaceMember: (...args: unknown[]) => addTicketSpaceMember(...args),
  removeTicketSpaceMember: (...args: unknown[]) => removeTicketSpaceMember(...args),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { userId: string | null }) => unknown) => selector({ userId: "user-1" }),
}));

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

function renderWithQuery(ui: React.ReactNode, initialPath = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Ticket spaces integration", () => {
  beforeEach(() => {
    createTicketSpace.mockReset();
    listTicketSpaces.mockReset();
    getTicketSpace.mockReset();
    listSpaceTickets.mockReset();
    getSpaceTicket.mockReset();
    assignSpaceTicket.mockReset();
    addSpaceTicketMessage.mockReset();
    setSpaceTicketStatus.mockReset();
    addTicketSpaceMember.mockReset();
    removeTicketSpaceMember.mockReset();
  });

  it("supports create and list flow on /tickets/spaces", async () => {
    listTicketSpaces
      .mockResolvedValueOnce({ items: [], next_cursor: null })
      .mockResolvedValueOnce({
        items: [
          {
            space_id: "spc_1",
            owner_sub: "user-1",
            name: "Ops",
            visibility: "shared",
            created_at: 1,
            updated_at: 1,
            members: [{ space_id: "spc_1", member_sub: "user-1", role: "owner", created_at: 1, updated_at: 1 }],
          },
        ],
        next_cursor: null,
      });
    createTicketSpace.mockResolvedValue({
      space: {
        space_id: "spc_1",
        owner_sub: "user-1",
        name: "Ops",
        visibility: "shared",
        created_at: 1,
        updated_at: 1,
        members: [{ space_id: "spc_1", member_sub: "user-1", role: "owner", created_at: 1, updated_at: 1 }],
      },
    });

    renderWithQuery(<TicketSpacesPage />);

    fireEvent.change(screen.getByPlaceholderText("Space name"), { target: { value: "Ops" } });
    fireEvent.click(screen.getByRole("button", { name: "Shared" }));
    fireEvent.click(screen.getByRole("button", { name: "Create space" }));

    await waitFor(() => {
      expect(createTicketSpace).toHaveBeenCalledWith({ name: "Ops", visibility: "shared" });
    });

    await waitFor(() => {
      expect(screen.getByText("Ops")).toBeInTheDocument();
    });
  });

  it("supports member management + assign/reply/status triage in space detail", async () => {
    getTicketSpace.mockResolvedValue({
      space: {
        space_id: "spc_1",
        owner_sub: "user-1",
        name: "Ops Board",
        visibility: "shared",
        created_at: 1,
        updated_at: 1,
        members: [
          { space_id: "spc_1", member_sub: "user-1", role: "owner", created_at: 1, updated_at: 1 },
          { space_id: "spc_1", member_sub: "user-2", role: "editor", created_at: 1, updated_at: 1 },
        ],
      },
    });
    listSpaceTickets.mockResolvedValue({
      items: [
        {
          ticket_id: "tkt_1",
          subject: "Space ticket",
          owner_sub: "user-1",
          status: "open",
          assigned_to_sub: null,
          assigned_admin_sub: null,
          assigned_by: null,
          assigned_at: null,
          created_at: 1,
          updated_at: 1,
          version: 1,
          messages: [],
          activity: [],
        },
      ],
      next_cursor: null,
    });
    getSpaceTicket.mockResolvedValue({
      ticket: {
        ticket_id: "tkt_1",
        subject: "Space ticket",
        owner_sub: "user-1",
        status: "open",
        assigned_to_sub: null,
        assigned_admin_sub: null,
        assigned_by: null,
        assigned_at: null,
        created_at: 1,
        updated_at: 1,
        version: 1,
        messages: [{ message_id: "m1", sender_sub: "user-1", sender_role: "user", body: "hello", created_at: 1, email_alert_queued_for: [] }],
        activity: [],
      },
    });
    addTicketSpaceMember.mockResolvedValue({ ok: true });
    removeTicketSpaceMember.mockResolvedValue({ ok: true });
    assignSpaceTicket.mockResolvedValue({ ticket: { ticket_id: "tkt_1" } });
    addSpaceTicketMessage.mockResolvedValue({ ticket: { ticket_id: "tkt_1" } });
    setSpaceTicketStatus.mockResolvedValue({ ticket: { ticket_id: "tkt_1" } });

    renderWithQuery(
      <Routes>
        <Route path="/tickets/spaces/:spaceId" element={<TicketSpaceDetailPage />} />
      </Routes>,
      "/tickets/spaces/spc_1",
    );

    await waitFor(() => {
      expect(screen.getByText("Ops Board")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Manage members" }));
    fireEvent.change(screen.getByPlaceholderText("member sub"), { target: { value: "user-3" } });
    fireEvent.click(screen.getByRole("button", { name: "Add member" }));
    await waitFor(() => expect(addTicketSpaceMember).toHaveBeenCalledWith("spc_1", { member_sub: "user-3", role: "viewer" }));

    const removeButtons = screen.getAllByRole("button", { name: "Remove" });
    fireEvent.click(removeButtons[1]!);
    await waitFor(() => expect(removeTicketSpaceMember).toHaveBeenCalledWith("spc_1", "user-2"));

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    const rowButton = screen.getByText("Space ticket").closest("button");
    expect(rowButton).toBeTruthy();
    fireEvent.click(rowButton as HTMLButtonElement);
    await waitFor(() => {
      expect(getSpaceTicket).toHaveBeenCalledWith("spc_1", "tkt_1");
    });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Assign to me" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Assign to me" }));
    fireEvent.click(screen.getByRole("button", { name: /^Assign$/ }));
    await waitFor(() => expect(assignSpaceTicket).toHaveBeenCalledWith("spc_1", "tkt_1", "user-1"));

    fireEvent.change(screen.getByPlaceholderText("Reply in thread..."), { target: { value: "ack" } });
    fireEvent.click(screen.getByRole("button", { name: "Send reply" }));
    await waitFor(() => expect(addSpaceTicketMessage).toHaveBeenCalledWith("spc_1", "tkt_1", "ack"));

    fireEvent.click(screen.getByRole("button", { name: "Mark done" }));
    await waitFor(() => expect(setSpaceTicketStatus).toHaveBeenCalledWith("spc_1", "tkt_1", "done"));
  });
});
