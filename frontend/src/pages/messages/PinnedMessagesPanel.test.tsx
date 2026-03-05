import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { PinnedMessagesPanel } from "./PinnedMessagesPanel";

const getPinnedMessages = vi.fn();
const unpinMessage = vi.fn();

vi.mock("@/api/endpoints/messaging", () => ({
  getPinnedMessages: (...args: unknown[]) => getPinnedMessages(...args),
  unpinMessage: (...args: unknown[]) => unpinMessage(...args),
}));

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderPanel(onJumpToMessage: (id: string) => void = () => {}) {
  const qc = makeClient();
  return render(
    <QueryClientProvider client={qc}>
      <PinnedMessagesPanel
        open
        onOpenChange={() => {}}
        conversationId="c1"
        participants={[
          { user_id: "u2", display_name: "Author Two" },
          { user_id: "u9", display_name: "Pin User" },
        ]}
        messageById={new Map([["m1", { message_id: "m1", conversation_id: "c1", sender_id: "u2", created_at: 1, kind: "text", text: "pin me" }]])}
        onJumpToMessage={onJumpToMessage}
      />
    </QueryClientProvider>,
  );
}

describe("PinnedMessagesPanel", () => {
  beforeEach(() => {
    getPinnedMessages.mockReset();
    unpinMessage.mockReset();
  });

  it("lists active pins with metadata", async () => {
    getPinnedMessages.mockResolvedValue({
      items: [
        { conversation_id: "c1", message_id: "m1", pinned_by_user_id: "u9", pinned_at: 3, is_active: true },
      ],
    });

    renderPanel();

    expect(await screen.findByText("pin me")).toBeInTheDocument();
    expect(screen.getByText(/Author: Author Two/i)).toBeInTheDocument();
    expect(screen.getByText(/Pinned by: Pin User/i)).toBeInTheDocument();
  });

  it("unpinned action calls API", async () => {
    getPinnedMessages.mockResolvedValue({
      items: [{ conversation_id: "c1", message_id: "m1", pinned_by_user_id: "u9", pinned_at: 3, is_active: true }],
    });
    unpinMessage.mockResolvedValue({ ok: true });

    renderPanel();

    await userEvent.click(await screen.findByRole("button", { name: "Unpin" }));

    await waitFor(() => {
      expect(unpinMessage).toHaveBeenCalledWith("c1", "m1");
    });
  });

  it("jump action invokes callback", async () => {
    const onJump = vi.fn();
    getPinnedMessages.mockResolvedValue({
      items: [{ conversation_id: "c1", message_id: "m1", pinned_by_user_id: "u9", pinned_at: 3, is_active: true }],
    });

    renderPanel(onJump);

    await userEvent.click(await screen.findByRole("button", { name: /Jump to message/i }));
    expect(onJump).toHaveBeenCalledWith("m1");
  });
});
