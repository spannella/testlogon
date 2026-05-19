import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MessageBubble } from "./MessageBubble";

const unlockLotteryMessage = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(async () => ({ ok: true })),
  editMessage: vi.fn(async () => ({ ok: true })),
  reactToMessage: vi.fn(async () => ({ ok: true })),
  hideMessage: vi.fn(async () => ({ ok: true })),
  reportMessage: vi.fn(async () => ({ ok: true })),
  createOnceMediaAttachmentGrant: vi.fn(),
  consumeOnceMediaAttachment: vi.fn(),
  buildAttachmentDownloadUrl: vi.fn(),
  sendMessageTip: vi.fn(),
  unlockMessage: vi.fn(),
  unlockLotteryMessage: (...args: unknown[]) => unlockLotteryMessage(...args),
  getMeetingPoll: vi.fn(),
  voteMeetingPoll: vi.fn(),
  confirmMeetingPoll: vi.fn(),
  markViewed: vi.fn(async () => ({ ok: true })),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
  },
}));

vi.mock("./ReadReceipts", () => ({ ReadReceipts: () => null, ViewTracker: () => null }));
vi.mock("./ForwardDialog", () => ({ ForwardDialog: () => null }));
vi.mock("./MessageDetailsSheet", () => ({ MessageDetailsSheet: () => null }));
vi.mock("@/api/endpoints/billing", () => ({ getPaymentMethods: vi.fn(async () => []) }));
vi.mock("@/lib/featureFlags", () => ({ isMessagingEncryptionEnabled: vi.fn(() => true) }));

function lotteryMessage(lockState: "locked" | "unlocked") {
  return {
    message_id: "m-lottery",
    conversation_id: "c1",
    sender_id: "u-sender",
    kind: "text" as const,
    created_at: 1,
    text: "🎲 Lottery message",
    lottery: {
      message_type: "lottery_dm" as const,
      lock_state: lockState,
      selected_outcome:
        lockState === "unlocked"
          ? {
              outcome_id: "o_1",
              payload_type: "text" as const,
              text_content: "Revealed winner",
            }
          : undefined,
    },
  };
}

function renderBubble(message: ReturnType<typeof lotteryMessage>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble conversationId="c1" isOwn={false} message={message} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MessageBubble lottery reveal flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows unlock error and allows retry", async () => {
    unlockLotteryMessage.mockRejectedValueOnce(new Error("boom"));
    unlockLotteryMessage.mockResolvedValueOnce({
      message_id: "m-lottery",
      lock_state: "unlocked",
      selected_outcome: { outcome_id: "o_1", payload_type: "text", text_content: "Revealed winner" },
      unlocked_at: 123,
    });

    renderBubble(lotteryMessage("locked"));

    await userEvent.click(screen.getByRole("button", { name: /Unlock outcome/i }));
    await waitFor(() => expect(screen.getByText(/Unlock failed:/i)).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: /Unlock outcome/i }));
    await waitFor(() => expect(unlockLotteryMessage).toHaveBeenCalledTimes(2));
  });

  it("transitions unlocking -> revealing and renders revealed payload after hydration", async () => {
    unlockLotteryMessage.mockResolvedValue({
      message_id: "m-lottery",
      lock_state: "unlocked",
      selected_outcome: { outcome_id: "o_1", payload_type: "text", text_content: "Revealed winner" },
      unlocked_at: 123,
    });

    const view = renderBubble(lotteryMessage("locked"));

    await userEvent.click(screen.getByRole("button", { name: /Unlock outcome/i }));
    expect(await screen.findByText(/Unlocking…/i)).toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(900);
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith("Lottery unlocked!"));

    // Simulate reload/query hydration where server now returns unlocked state.
    view.rerender(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
          <MessageBubble conversationId="c1" isOwn={false} message={lotteryMessage("unlocked")} />
        </QueryClientProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByText(/Revealed winner/i)).toBeInTheDocument();
  });

  it("minimizes reveal animation when reduced motion is enabled", async () => {
    (window.matchMedia as unknown as ReturnType<typeof vi.fn>).mockImplementation((query: string) => ({
      matches: query.includes("prefers-reduced-motion"),
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));

    unlockLotteryMessage.mockResolvedValue({
      message_id: "m-lottery",
      lock_state: "unlocked",
      selected_outcome: { outcome_id: "o_1", payload_type: "text", text_content: "Revealed winner" },
      unlocked_at: 123,
    });

    renderBubble(lotteryMessage("locked"));
    await userEvent.click(screen.getByRole("button", { name: /Unlock outcome/i }));

    expect(await screen.findByText(/Reduced motion enabled/i)).toBeInTheDocument();
    expect(screen.queryByText(/Revealing…/i)).not.toBeInTheDocument();
  });
});
