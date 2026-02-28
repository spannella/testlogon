import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ComposeBar } from "./ComposeBar";
import { isMessagingViewOnceImageEnabled } from "@/lib/featureFlags";

function renderWithClient(ui: JSX.Element) {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

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
    renderWithClient(<ComposeBar onSendText={onSendText} />);

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
    renderWithClient(<ComposeBar onSendText={onSendText} />);

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
    Object.defineProperty(URL, "createObjectURL", {
      value: vi.fn(() => "blob:preview"),
      writable: true,
      configurable: true,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      value: vi.fn(() => undefined),
      writable: true,
      configurable: true,
    });
  });
  it("sends image with view-once metadata when toggle is enabled", async () => {
    const onSendText = vi.fn();
    const onSendImage = vi.fn();
    renderWithClient(<ComposeBar onSendText={onSendText} onSendImage={onSendImage} />);

    // Upload a file first — the view-once checkbox appears in the file preview panel
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["abc"], "photo.png", { type: "image/png" });
    await userEvent.upload(fileInput, file);

    // Now the "Recipient can only view once" checkbox is visible — enable it
    await userEvent.click(screen.getByLabelText(/Recipient can only view once/i));

    // Click Send to trigger onSendImage
    await userEvent.click(screen.getByLabelText(/Send message/i));

    expect(onSendImage).toHaveBeenCalledTimes(1);
    const firstCall = onSendImage.mock.calls[0];
    expect(firstCall).toBeTruthy();
    const metadata = firstCall?.[1];
    expect(metadata).toEqual(expect.objectContaining({ consumption_policy: "view_once" }));
  });

  it("does not render once-media toggles when feature flags are disabled", async () => {
    vi.mocked(isMessagingViewOnceImageEnabled).mockReturnValue(false);
    const onSendText = vi.fn();
    renderWithClient(<ComposeBar onSendText={onSendText} onSendImage={vi.fn()} />);

    // Upload a file — view-once checkbox should not appear when flag is disabled
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["abc"], "photo.png", { type: "image/png" });
    await userEvent.upload(fileInput, file);

    expect(screen.queryByLabelText(/Recipient can only view once/i)).not.toBeInTheDocument();
  });
});
