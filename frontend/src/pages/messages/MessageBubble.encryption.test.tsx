import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { isMessageCryptoSupported } from "@/lib/messageEncryption";
import type { Message } from "@/api/types";
import { MessageBubble } from "./MessageBubble";

vi.mock("@/lib/featureFlags", () => ({
  isMessagingEncryptionEnabled: vi.fn(() => true),
}));

vi.mock("@/lib/messageEncryption", () => {
  class MockMessageCryptoError extends Error {
    code: string;

    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  }

  return {
    MessageCryptoError: MockMessageCryptoError,
    isMessageCryptoSupported: vi.fn(() => true),
    decryptMessage: vi.fn(async (_envelope, password: string) => {
      if (password === "correct-password") return "decrypted hello";
      throw new MockMessageCryptoError("wrong_password", "wrong password");
    }),
  };
});

vi.mock("@/api/endpoints/messaging", () => ({
  deleteMessage: vi.fn(async () => ({ ok: true })),
}));

vi.mock("./ReadReceipts", () => ({
  ReadReceipts: () => null,
  ViewTracker: () => null,
}));

vi.mock("./ForwardDialog", () => ({
  ForwardDialog: () => null,
}));

const mockIsMessageCryptoSupported = vi.mocked(isMessageCryptoSupported);

const baseMessage: Message = {
  message_id: "m1",
  conversation_id: "c1",
  sender_id: "u2",
  kind: "text" as const,
  created_at: Math.floor(Date.now() / 1000),
  is_encrypted: true,
  encryption: {
    version: 1 as const,
    alg: "AES-256-GCM" as const,
    kdf: "PBKDF2-SHA256" as const,
    iterations: 600000,
    salt_b64: "salt",
    iv_b64: "iv",
    ciphertext_b64: "cipher",
  },
};

function renderBubble(message: Message = baseMessage) {
  const queryClient = new QueryClient();
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <MessageBubble message={message} isOwn={false} conversationId="c1" />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MessageBubble decrypt prompt", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsMessageCryptoSupported.mockReturnValue(true);
  });

  it("decrypts and renders plaintext in-memory with correct password", async () => {
    renderBubble();

    expect(screen.getByText(/To change content, delete and resend this encrypted message/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Decrypt message/i }));
    await userEvent.type(screen.getByPlaceholderText(/Password/i), "correct-password");
    await userEvent.click(screen.getByRole("button", { name: /^Decrypt$/i }));

    await waitFor(() => expect(screen.getByText("decrypted hello")).toBeInTheDocument());
  });

  it("shows wrong-password error and allows retry", async () => {
    renderBubble();

    await userEvent.click(screen.getByRole("button", { name: /Decrypt message/i }));
    await userEvent.type(screen.getByPlaceholderText(/Password/i), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /^Decrypt$/i }));

    await waitFor(() => expect(screen.getByText(/Wrong password/i)).toBeInTheDocument());

    const passwordInput = screen.getByPlaceholderText(/Password/i);
    await userEvent.clear(passwordInput);
    await userEvent.type(passwordInput, "correct-password");
    await userEvent.click(screen.getByRole("button", { name: /^Decrypt$/i }));

    await waitFor(() => expect(screen.getByText("decrypted hello")).toBeInTheDocument());
  });

  it("shows non-breaking unsupported fallback when crypto is unavailable", () => {
    mockIsMessageCryptoSupported.mockReturnValue(false);
    renderBubble();

    expect(screen.getByText(/Encrypted message unsupported/i)).toBeInTheDocument();
    expect(screen.getByText(/Update to a client with encrypted messaging support/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Decrypt message/i })).not.toBeInTheDocument();
  });

  it("shows unsupported fallback when encryption envelope is missing", () => {
    renderBubble({ ...baseMessage, encryption: undefined, is_encrypted: true });

    expect(screen.getByText(/Encrypted message unsupported/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Decrypt message/i })).not.toBeInTheDocument();
  });
});
