import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MessageBubble } from "./MessageBubble";
import { ApiError } from "@/api/client";

vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(async () => ({ ok: true })),
  createOnceMediaAttachmentGrant: vi.fn(async () => ({ grant_token: "g1", expires_at: 123, conversation_id: "c1", message_id: "m1" })),
  consumeOnceMediaAttachment: vi.fn(async () => ({ ok: true, conversation_id: "c1", message_id: "m1", consumption_state: "consumed", consumed_at: 1, consumption_attempt_id: "a1" })),
  buildAttachmentDownloadUrl: vi.fn(() => "/messaging/conversations/c1/messages/m1/attachment?grant_token=g1"),
}));

vi.mock("./ReadReceipts", () => ({
  ReadReceipts: () => null,
  ViewTracker: () => null,
}));

vi.mock("./ForwardDialog", () => ({
  ForwardDialog: () => null,
}));

vi.mock("@/lib/featureFlags", () => ({
  isMessagingEncryptionEnabled: vi.fn(() => true),
}));

const renderWithClient = (ui: JSX.Element) => {
  const client = new QueryClient();
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
};

describe("MessageBubble once-media rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(window, "open").mockImplementation(() => null);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        blob: async () => new Blob(["once-media"]),
      })) as unknown as typeof fetch,
    );
    Object.defineProperty(URL, "createObjectURL", {
      value: vi.fn(() => "blob:once-media"),
      writable: true,
      configurable: true,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      value: vi.fn(() => undefined),
      writable: true,
      configurable: true,
    });
  });

  it("shows pending badge and opens once-media through grant+consume flow", async () => {
    renderWithClient(
      <MessageBubble
        conversationId="c1"
        isOwn={false}
        message={{
          message_id: "m1",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "image",
          created_at: 1,
          image: { url: "https://example.com/x.png" },
          consumption_policy: "view_once",
          media_kind: "image",
          consumption_state: "pending",
        }}
      />,
    );

    expect(screen.getByText(/View once/i)).toBeInTheDocument();
    expect(screen.getByText(/pending/i)).toBeInTheDocument();

    await userEvent.click(screen.getByAltText(/Shared image/i));

    await waitFor(() => expect(window.open).toHaveBeenCalled());
    expect(fetch).toHaveBeenCalledWith(
      "/messaging/conversations/c1/messages/m1/attachment?grant_token=g1",
      expect.objectContaining({
        method: "GET",
        credentials: "include",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      }),
    );
    expect(URL.createObjectURL).toHaveBeenCalled();
  });

  it("renders consumed state as non-replayable", () => {
    renderWithClient(
      <MessageBubble
        conversationId="c1"
        isOwn={false}
        message={{
          message_id: "m2",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "audio",
          created_at: 1,
          file: { name: "voice-note.mp3", url: "/f" },
          consumption_policy: "listen_once",
          media_kind: "audio",
          consumption_state: "consumed",
        }}
      />,
    );

    expect(screen.getByText(/Listen once/i)).toBeInTheDocument();
    expect(screen.getAllByText(/consumed/i).length).toBeGreaterThan(0);
    const button = screen.getByRole("button", { name: /voice-note.mp3/i });
    expect(button).toBeDisabled();
  });

  it("hides forward action for once-media to reduce forwarding vectors", () => {
    renderWithClient(
      <MessageBubble
        conversationId="c1"
        isOwn={false}
        message={{
          message_id: "m3",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "image",
          created_at: 1,
          image: { url: "https://example.com/y.png" },
          consumption_policy: "view_once",
          media_kind: "image",
          consumption_state: "pending",
        }}
      />,
    );

    expect(screen.queryByText(/Forward/i)).not.toBeInTheDocument();
  });

  it("shows retry guidance when playback threshold is not met (interrupted playback)", async () => {
    const messagingApi = await import("@/api/endpoints/messaging");
    vi.mocked(messagingApi.consumeOnceMediaAttachment).mockRejectedValueOnce(
      new ApiError(422, "threshold", { detail: { code: "consume_threshold_not_met" } }),
    );

    renderWithClient(
      <MessageBubble
        conversationId="c1"
        isOwn={false}
        message={{
          message_id: "m4",
          conversation_id: "c1",
          sender_id: "u2",
          kind: "audio",
          created_at: 1,
          file: { name: "voice-note.mp3", url: "/f" },
          consumption_policy: "listen_once",
          media_kind: "audio",
          consumption_state: "pending",
        }}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: /voice-note.mp3/i }));

    await waitFor(() => {
      expect(screen.getByText(/Playback threshold not reached yet/i)).toBeInTheDocument();
    });
    expect(fetch).not.toHaveBeenCalled();
  });

});
