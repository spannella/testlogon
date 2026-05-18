import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { CalendarSharing } from "./CalendarSharing";

vi.mock("@/api/endpoints/calendar", () => ({
  getCalendars: vi.fn(async () => [{ calendar_id: "cal_1", name: "Work" }]),
  getCalendarShares: vi.fn(async () => [{
    calendar_id: "cal_1",
    user_sub: "user-2",
    permission: "write",
    created_at_utc: new Date().toISOString(),
  }]),
  shareCalendar: vi.fn(async () => ({ ok: true })),
  removeCalendarShare: vi.fn(async () => ({ ok: true })),
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <CalendarSharing />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("CalendarSharing profile links", () => {
  it("renders collaborator identity as canonical profile link", async () => {
    renderPage();
    const link = await screen.findByRole("link", { name: /open user-2 profile/i });
    expect(link).toHaveAttribute("href", "/u/user-2");
  });
});
