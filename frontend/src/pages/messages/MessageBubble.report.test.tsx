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



function renderImageBubble() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <MessageBubble
          conversationId="c1"
          isOwn={false}
          message={{
            message_id: "m2",
            conversation_id: "c1",
            sender_id: "u2",
            kind: "image",
            created_at: 1,
            image: { url: "https://example.com/img.jpg" },
          }}
        />
      </QueryClientProvider>
    </MemoryRouter>,
  );
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
    expect(screen.getByRole("group", { name: "Report topics" })).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Submit report" })).toBeInTheDocument();
  });

  it("prevents submit without topics", async () => {
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    await userEvent.type(screen.getByLabelText("Reason"), "This should be reviewed.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    expect(screen.getByRole("alert")).toHaveTextContent("Select at least one topic.");
    expect(reportMessage).not.toHaveBeenCalled();
  });

  it("submits report and shows success toast", async () => {
    reportMessage.mockResolvedValue({ ok: true, report_id: "r1" });
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    await userEvent.click(screen.getByLabelText("Sexual"));
    await userEvent.type(screen.getByLabelText("Reason"), "This message includes sexual content.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(reportMessage).toHaveBeenCalledWith("c1", "m1", {
        reason_code: "sexual",
        statement: "This message includes sexual content.",
      });
    });
    expect(toastSuccess).toHaveBeenCalledWith("Report received");
  });



  it("supports reporting image attachments from lightbox", async () => {
    reportMessage.mockResolvedValue({ ok: true, report_id: "r2" });
    renderImageBubble();

    await userEvent.click(screen.getByRole("button", { name: "Open message image" }));
    await userEvent.click(await screen.findByRole("button", { name: /Report image/i }));

    expect(await screen.findByRole("heading", { name: "Report attachment" })).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText("Criminal"));
    await userEvent.type(screen.getByLabelText("Reason"), "This attachment appears criminal.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(reportMessage).toHaveBeenCalledWith("c1", "m2", {
        reason_code: "criminal",
        statement: "This attachment appears criminal.",
      });
    });
    expect(toastSuccess).toHaveBeenCalledWith("Report received");
  });

  it("shows recoverable error when report submission fails", async () => {
    reportMessage.mockRejectedValueOnce(new Error("boom"));
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: "Message actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /Report message/i }));

    await userEvent.click(screen.getByLabelText("Spam"));
    await userEvent.type(screen.getByLabelText("Reason"), "Spam content to review.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Could not submit report. Please try again."));
  });
});
