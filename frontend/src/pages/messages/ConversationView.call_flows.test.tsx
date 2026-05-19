import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api/client";
import { ConversationView } from "./ConversationView";

const getMessages = vi.fn();
const createCallInvite = vi.fn();
const acceptCallInvite = vi.fn();
const declineCallInvite = vi.fn();
const endCall = vi.fn();

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: { userId: string }) => unknown) => selector({ userId: "u1" }),
}));

vi.mock("@/api/endpoints/messaging", () => ({
  getMessages: (...args: unknown[]) => getMessages(...args),
  sendTextMessage: vi.fn(async () => ({})),
  sendImageMessage: vi.fn(async () => ({})),
  sendGalleryMessage: vi.fn(async () => ({})),
  sendFileShareMessage: vi.fn(async () => ({})),
  sendCalendarShareMessage: vi.fn(async () => ({})),
  sendCalendarEventMessage: vi.fn(async () => ({})),
  sendMeetingPollMessage: vi.fn(async () => ({})),
  markRead: vi.fn(async () => ({ ok: true })),
  claimHelpdeskConversation: vi.fn(async () => ({ ok: true })),
  createCallInvite: (...args: unknown[]) => createCallInvite(...args),
  acceptCallInvite: (...args: unknown[]) => acceptCallInvite(...args),
  declineCallInvite: (...args: unknown[]) => declineCallInvite(...args),
  endCall: (...args: unknown[]) => endCall(...args),
}));

vi.mock("@/lib/featureFlags", async () => {
  const actual = await vi.importActual<object>("@/lib/featureFlags");
  return {
    ...actual,
    isMessagingGalleryEnabled: () => false,
    isMessagingWebrtcDirectCallEnabled: () => true,
  };
});

vi.mock("./MessageBubble", () => ({ MessageBubble: () => <div data-testid="message-bubble" /> }));
vi.mock("./ComposeBar", () => ({ ComposeBar: () => null }));
vi.mock("./TypingIndicator", () => ({ TypingIndicator: () => null, useTypingSignal: () => () => {} }));
vi.mock("./PresenceDot", () => ({ PresenceDot: () => null }));
vi.mock("./ParticipantsPanel", () => ({ ParticipantsPanel: () => null }));
vi.mock("./ConversationGallery", () => ({ ConversationGallery: () => null }));
vi.mock("./ScheduledMessages", () => ({ ScheduledMessages: () => null }));
vi.mock("./HiddenMessagesPanel", () => ({ HiddenMessagesPanel: () => null }));
vi.mock("./PinnedMessagesPanel", () => ({ PinnedMessagesPanel: () => null }));
vi.mock("./PinnedMessageBanner", () => ({ PinnedMessageBanner: () => null }));

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const conversation = {
    conversation_id: "c1",
    type: "dm",
    participants: [{ user_id: "u1" }, { user_id: "u2", display_name: "U2" }],
    unread_count: 0,
  } as any;

  return render(
    <QueryClientProvider client={client}>
      <ConversationView conversation={conversation} />
    </QueryClientProvider>,
  );
}

describe("ConversationView call flows", () => {
  beforeEach(() => {
    getMessages.mockReset();
    createCallInvite.mockReset();
    acceptCallInvite.mockReset();
    declineCallInvite.mockReset();
    endCall.mockReset();
    getMessages.mockResolvedValue({ messages: [], next_cursor: undefined });
  });

  it("shows deterministic outgoing call state transitions", async () => {
    createCallInvite.mockResolvedValue({ call_id: "call-1" });
    renderView();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Start audio call" }));

    await waitFor(() => {
      expect(screen.getByText(/(Ringing U2…|Connecting to U2…|Connected with U2\.)/)).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText("Connected with U2.")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "End call" }));
    expect(await screen.findByText("Call ended.")).toBeInTheDocument();
  });

  it("allows accepting an incoming call from modal", async () => {
    acceptCallInvite.mockResolvedValue({ call_id: "incoming-1" });
    renderView();
    const user = userEvent.setup();

    act(() => {
      window.dispatchEvent(
        new CustomEvent("messaging:call-event", {
        detail: {
          event_type: "call.invite",
          conversation_id: "c1",
          call_id: "incoming-1",
          caller_user_id: "u2",
          callee_user_id: "u1",
          mode: "video",
        },
        }),
      );
    });

    expect(await screen.findByText("U2 is calling you.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Accept call" }));
    expect(await screen.findByText("Connected with U2.")).toBeInTheDocument();
  });

  it("shows busy outcome messaging when invite is rejected as busy", async () => {
    createCallInvite.mockRejectedValue(
      new ApiError(409, "busy", { detail: { code: "call_busy" } }),
    );
    renderView();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Start video call" }));

    await waitFor(() => {
      expect(screen.getByText("User is busy on another call.")).toBeInTheDocument();
    });
  });

  it("ignores delayed stale call events after a newer event has been applied", async () => {
    renderView();

    act(() => {
      window.dispatchEvent(
        new CustomEvent("messaging:call-event", {
          detail: {
            event_type: "call.invite",
            conversation_id: "c1",
            caller_user_id: "u2",
            callee_user_id: "u1",
            mode: "audio",
            event_ts: 200,
          },
        }),
      );
    });
    expect(screen.getByText("U2 is calling you.")).toBeInTheDocument();

    act(() => {
      window.dispatchEvent(
        new CustomEvent("messaging:call-event", {
          detail: {
            event_type: "call.end",
            conversation_id: "c1",
            event_ts: 300,
          },
        }),
      );
    });
    expect(screen.getByText("Call ended.")).toBeInTheDocument();

    act(() => {
      window.dispatchEvent(
        new CustomEvent("messaging:call-event", {
          detail: {
            event_type: "call.invite",
            conversation_id: "c1",
            caller_user_id: "u2",
            callee_user_id: "u1",
            mode: "audio",
            event_ts: 100,
          },
        }),
      );
    });

    expect(screen.queryByText("U2 is calling you.")).not.toBeInTheDocument();
  });
});
