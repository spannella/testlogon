import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HiddenMessagesPanel } from "./HiddenMessagesPanel";

const getHiddenMessages = vi.fn();
const unhideMessage = vi.fn();

vi.mock("@/api/endpoints/messaging", () => ({
  getHiddenMessages: (...args: unknown[]) => getHiddenMessages(...args),
  unhideMessage: (...args: unknown[]) => unhideMessage(...args),
}));

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderPanel(onJumpToMessage: (id: string) => void = () => {}) {
  const qc = makeClient();
  return render(
    <QueryClientProvider client={qc}>
      <HiddenMessagesPanel open onOpenChange={() => {}} conversationId="c1" onJumpToMessage={onJumpToMessage} />
    </QueryClientProvider>,
  );
}

describe("HiddenMessagesPanel", () => {
  beforeEach(() => {
    getHiddenMessages.mockReset();
    unhideMessage.mockReset();
  });

  it("lists hidden items in chronological order", async () => {
    getHiddenMessages.mockResolvedValue({
      items: [
        { message_id: "m2", conversation_id: "c1", sender_id: "u2", created_at: 2, kind: "text", text: "later" },
        { message_id: "m1", conversation_id: "c1", sender_id: "u2", created_at: 1, kind: "text", text: "earlier" },
      ],
    });

    renderPanel();

    const previews = await screen.findAllByText(/earlier|later/i);
    expect(previews[0]).toHaveTextContent("earlier");
    expect(previews[1]).toHaveTextContent("later");
  });

  it("unhides a message and calls API", async () => {
    getHiddenMessages.mockResolvedValue({
      items: [
        { message_id: "m1", conversation_id: "c1", sender_id: "u2", created_at: 1, kind: "text", text: "hidden" },
      ],
    });
    unhideMessage.mockResolvedValue({ ok: true });

    renderPanel();

    await userEvent.click(await screen.findByRole("button", { name: "Unhide" }));

    await waitFor(() => {
      expect(unhideMessage).toHaveBeenCalledWith("c1", "m1");
    });
  });

  it("invokes jump callback", async () => {
    const onJump = vi.fn();
    getHiddenMessages.mockResolvedValue({
      items: [
        { message_id: "m1", conversation_id: "c1", sender_id: "u2", created_at: 1, kind: "text", text: "hidden" },
      ],
    });

    renderPanel(onJump);

    await userEvent.click(await screen.findByRole("button", { name: /Jump to original position/i }));
    expect(onJump).toHaveBeenCalledWith("m1");
  });
});
