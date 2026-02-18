import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ComposeBar } from "./ComposeBar";

vi.mock("@/lib/featureFlags", () => ({
  isMessagingEncryptionEnabled: vi.fn(() => true),
}));

vi.mock("@/lib/messageEncryption", () => ({
  encryptMessage: vi.fn(async () => ({
    version: 1,
    alg: "AES-256-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: 600000,
    salt_b64: "salt",
    iv_b64: "iv",
    ciphertext_b64: "cipher",
  })),
}));

describe("ComposeBar encrypted send UX", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("sends encrypted payload only (no plaintext/password fields)", async () => {
    const onSendText = vi.fn();
    render(<ComposeBar onSendText={onSendText} />);

    await userEvent.click(screen.getByLabelText(/Encrypt message/i));
    await userEvent.type(screen.getByPlaceholderText(/Encryption password/i), "Str0ng!Password");
    await userEvent.type(screen.getByPlaceholderText(/Confirm password/i), "Str0ng!Password");
    await userEvent.type(screen.getByPlaceholderText(/Type an encrypted message/i), "hello encrypted world");
    await userEvent.click(screen.getByLabelText(/Send message/i));

    await waitFor(() => expect(onSendText).toHaveBeenCalledTimes(1));
    const payload = onSendText.mock.calls[0]?.[0];
    expect(payload?.encryption).toBeTruthy();
    expect(payload?.text).toBeUndefined();
    expect(payload?.password).toBeUndefined();
  });

  it("shows validation when password confirmation mismatches and does not send", async () => {
    const onSendText = vi.fn();
    render(<ComposeBar onSendText={onSendText} />);

    await userEvent.click(screen.getByLabelText(/Encrypt message/i));
    await userEvent.type(screen.getByPlaceholderText(/Encryption password/i), "A");
    await userEvent.type(screen.getByPlaceholderText(/Confirm password/i), "B");
    await userEvent.type(screen.getByPlaceholderText(/Type an encrypted message/i), "hello");
    await userEvent.click(screen.getByLabelText(/Send message/i));

    expect(onSendText).not.toHaveBeenCalled();
    expect(screen.getByText(/Passwords must match/i)).toBeInTheDocument();
  });
});
