import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ComposeBar } from "./ComposeBar";
import { isMessagingViewOnceImageEnabled } from "@/lib/featureFlags";

vi.mock("@/lib/featureFlags", () => ({
  isMessagingEncryptionEnabled: vi.fn(() => true),
  isMessagingViewOnceImageEnabled: vi.fn(() => true),
  isMessagingViewOnceVideoEnabled: vi.fn(() => false),
  isMessagingListenOnceAudioEnabled: vi.fn(() => false),
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
    vi.mocked(isMessagingViewOnceImageEnabled).mockReturnValue(true);
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


describe("ComposeBar once-media toggles", () => {
  beforeEach(() => {
    vi.mocked(isMessagingViewOnceImageEnabled).mockReturnValue(true);
  });
  it("sends image with view-once metadata when toggle is enabled", async () => {
    const onSendText = vi.fn();
    const onSendImage = vi.fn();
    render(<ComposeBar onSendText={onSendText} onSendImage={onSendImage} />);

    await userEvent.click(screen.getByLabelText(/View once \(image\)/i));
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["abc"], "photo.png", { type: "image/png" });
    await userEvent.upload(fileInput, file);

    expect(onSendImage).toHaveBeenCalledTimes(1);
    expect(onSendImage.mock.calls[0][1]).toEqual({ consumption_policy: "view_once" });
  });

  it("does not render once-media toggles when feature flags are disabled", () => {
    vi.mocked(isMessagingViewOnceImageEnabled).mockReturnValue(false);
    const onSendText = vi.fn();
    render(<ComposeBar onSendText={onSendText} onSendImage={vi.fn()} />);
    expect(screen.queryByLabelText(/View once \(image\)/i)).not.toBeInTheDocument();
  });
});
