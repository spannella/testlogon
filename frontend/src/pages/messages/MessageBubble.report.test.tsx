import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MessageBubble } from "./MessageBubble";

const reportMessage = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(async () => ({ ok: true })),
  editMessage: vi.fn(async () => ({ ok: true })),
  reactToMessage: vi.fn(async () => ({ ok: true })),
  hideMessage: vi.fn(async () => ({ ok: true })),
  reportMessage: (...args: unknown[]) => reportMessage(...args),
  createOnceMediaAttachmentGrant: vi.fn(),
  consumeOnceMediaAttachment: vi.fn(),
  buildAttachmentDownloadUrl: vi.fn(),
  sendMessageTip: vi.fn(),
  unlockMessage: vi.fn(),
  getMeetingPoll: vi.fn(),
  voteMeetingPoll: vi.fn(),
  confirmMeetingPoll: vi.fn(),
  markViewed: vi.fn(),
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

if (!Element.prototype.scrollIntoView) {
  Object.defineProperty(Element.prototype, "scrollIntoView", {
    value: () => {},
  });
}

if (!HTMLElement.prototype.hasPointerCapture) {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    value: () => false,
  });
}
if (!HTMLElement.prototype.setPointerCapture) {
  Object.defineProperty(HTMLElement.prototype, "setPointerCapture", {
    value: () => {},
  });
}
if (!HTMLElement.prototype.releasePointerCapture) {
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    value: () => {},
  });
}

function renderBubble() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble
          conversationId="c1"
          isOwn={false}
          message={{
            message_id: "m1",
            conversation_id: "c1",
            sender_id: "u2",
            kind: "text",
            created_at: 1,
            text: "hello",
          }}
        />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MessageBubble report action", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });


  it("renders accessible report dialog copy and controls", async () => {
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    expect(await screen.findByRole("heading", { name: "Report message" })).toBeInTheDocument();
    expect(screen.getByText(/Recent conversation context will be included automatically/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Report reason")).toBeInTheDocument();
    expect(screen.getByLabelText("Statement")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit report" })).toBeInTheDocument();
  });
  it("blocks submit until reason and statement are valid", async () => {
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    const submit = await screen.findByRole("button", { name: "Submit report" });
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Statement"), "Too short");
    expect(submit).toBeDisabled();

    await userEvent.click(screen.getByLabelText("Report reason"));
    await userEvent.click(await screen.findByText("Spam or scam"));

    expect(submit).toBeEnabled();
  });

  it("submits report and shows success toast", async () => {
    reportMessage.mockResolvedValue({ ok: true, report_id: "r1" });
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    await userEvent.click(screen.getByLabelText("Report reason"));
    await userEvent.click(await screen.findByText("Harassment or bullying"));
    await userEvent.type(screen.getByLabelText("Statement"), "This message includes targeted harassment.");

    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(reportMessage).toHaveBeenCalledWith("c1", "m1", {
        reason_code: "harassment",
        statement: "This message includes targeted harassment.",
      });
    });
    expect(toastSuccess).toHaveBeenCalledWith("Report submitted");
  });

  it("shows recoverable error when report submission fails", async () => {
    reportMessage.mockRejectedValueOnce(new Error("boom"));
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    await userEvent.click(screen.getByLabelText("Report reason"));
    await userEvent.click(await screen.findByText("Other"));
    await userEvent.type(screen.getByLabelText("Statement"), "Report details for moderators.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Could not submit report. Please try again."));
  });
});
