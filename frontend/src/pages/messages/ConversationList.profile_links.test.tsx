import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ConversationList } from "./ConversationList";

const getConversations = vi.fn();

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: { userId: string }) => unknown) => selector({ userId: "u1" }),
}));

vi.mock("@/api/endpoints/messaging", () => ({
  getConversations: (...args: unknown[]) => getConversations(...args),
  startConversation: vi.fn(),
  startGroupConversation: vi.fn(),
}));

vi.mock("./PresenceDot", () => ({ PresenceDot: () => null }));
vi.mock("./UserSearch", () => ({ UserSearch: () => null }));

function renderList(onSelect = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/messages"]}>
      <QueryClientProvider client={client}>
        <Routes>
          <Route path="/messages" element={<ConversationList onSelect={onSelect} />} />
          <Route path="/u/:identifier" element={<div data-testid="profile-route">Profile Route</div>} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("ConversationList profile links", () => {
  it("navigates to canonical profile route from avatar/name links", async () => {
    getConversations.mockResolvedValue({
      conversations: [
        {
          conversation_id: "c1",
          type: "dm",
          participants: [
            { user_id: "u1", display_name: "Alice" },
            { user_id: "u2", display_name: "Bob" },
          ],
          unread_count: 0,
          last_message: { created_at: 1, text: "hi" },
        },
      ],
    });

    renderList();

    const profileTriggers = await screen.findAllByRole("link", { name: /open bob profile/i });
    await userEvent.click(profileTriggers[0]!);

    expect(await screen.findByTestId("profile-route")).toBeInTheDocument();
  });

  it("still selects conversation when row body is clicked", async () => {
    getConversations.mockResolvedValue({
      conversations: [
        {
          conversation_id: "c1",
          type: "dm",
          participants: [
            { user_id: "u1", display_name: "Alice" },
            { user_id: "u2", display_name: "Bob" },
          ],
          unread_count: 0,
          last_message: { created_at: 1, text: "hi" },
        },
      ],
    });

    const onSelect = vi.fn();
    renderList(onSelect);

    const row = await screen.findByRole("button", { name: /bob/i });
    await userEvent.click(row);

    expect(onSelect).toHaveBeenCalledTimes(1);
  });
});
