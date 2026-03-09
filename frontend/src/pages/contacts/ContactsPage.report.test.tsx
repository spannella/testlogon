import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import ContactsPage from "./ContactsPage";

const createModerationReport = vi.fn();

vi.mock("@/api/endpoints/contacts", () => ({
  getContacts: vi.fn(async () => ([
    {
      contact_id: "u2",
      display_name: "Alex",
      profile_photo_url: "https://example.com/photo.jpg",
      is_favorite: false,
      is_blocked: false,
    },
  ])),
  addContact: vi.fn(async () => ({})),
  removeContact: vi.fn(async () => ({})),
  updateContact: vi.fn(async () => ({})),
}));

vi.mock("@/api/endpoints/messaging", () => ({
  findOrCreateDm: vi.fn(async () => ({ conversation_id: "c1" })),
  sendFileShareMessage: vi.fn(async () => ({})),
  sendCalendarShareMessage: vi.fn(async () => ({})),
}));

vi.mock("@/api/endpoints/moderation", () => ({
  createModerationReport: (...args: unknown[]) => createModerationReport(...args),
}));

vi.mock("@/pages/messages/UserSearch", () => ({ UserSearch: () => null }));
vi.mock("@/pages/messages/FilePickerDialog", () => ({ FilePickerDialog: () => null }));
vi.mock("@/pages/messages/CalendarPickerDialog", () => ({ CalendarPickerDialog: () => null }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <ContactsPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Contacts profile photo reporting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("submits report with content_type=profile_photo", async () => {
    createModerationReport.mockResolvedValue({ ok: true, report_id: "r1" });
    renderPage();

    await userEvent.click(await screen.findByRole("button", { name: /Open Alex profile photo/i }));
    await userEvent.click(await screen.findByRole("button", { name: /Report profile photo/i }));

    await userEvent.click(screen.getByLabelText("Spam"));
    await userEvent.type(screen.getByLabelText("Reason"), "This photo is spam.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(createModerationReport).toHaveBeenCalledWith({
        content_type: "profile_photo",
        content_id: "u2",
        profile_user_id: "u2",
        topics: ["spam"],
        reason_text: "This photo is spam.",
      });
    });
  });
});
