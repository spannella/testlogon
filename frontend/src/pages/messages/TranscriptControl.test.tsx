import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { TranscriptControl } from "./TranscriptControl";

vi.mock("@/lib/featureFlags", () => ({
  isMessagingTranscriptionEnabled: vi.fn(() => true),
}));

const transcribeMessage = vi.fn();
vi.mock("@/api/endpoints/messagingAi", () => ({
  transcribeMessage: (...args: unknown[]) => transcribeMessage(...args),
}));

import { isMessagingTranscriptionEnabled } from "@/lib/featureFlags";

const renderWithClient = (ui: JSX.Element) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
};

describe("TranscriptControl (MVA-008)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (isMessagingTranscriptionEnabled as unknown as ReturnType<typeof vi.fn>).mockReturnValue(true);
  });

  it("renders nothing when transcription is disabled", () => {
    (isMessagingTranscriptionEnabled as unknown as ReturnType<typeof vi.fn>).mockReturnValue(false);
    const { container } = renderWithClient(
      <TranscriptControl conversationId="c1" messageId="m1" />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("calls the transcribe endpoint on first click and shows the transcript", async () => {
    transcribeMessage.mockResolvedValueOnce({
      transcript: "hello world",
      transcript_lang: "en",
      cached: false,
    });
    renderWithClient(<TranscriptControl conversationId="c1" messageId="m1" />);

    const btn = screen.getByTestId("show-transcript");
    expect(btn).toHaveTextContent("Show transcript");
    await userEvent.click(btn);

    await waitFor(() => expect(transcribeMessage).toHaveBeenCalledWith("c1", "m1"));
    expect(await screen.findByTestId("transcript-text")).toHaveTextContent("hello world");
  });

  it("renders an existing transcript without calling the endpoint and toggles it", async () => {
    renderWithClient(
      <TranscriptControl
        conversationId="c1"
        messageId="m1"
        existingTranscript="cached transcript"
        existingLang="en"
      />,
    );
    // Already shown because it was passed in.
    expect(screen.getByTestId("transcript-text")).toHaveTextContent("cached transcript");
    const btn = screen.getByTestId("show-transcript");
    expect(btn).toHaveTextContent("Hide transcript");
    await userEvent.click(btn);
    expect(screen.queryByTestId("transcript-text")).toBeNull();
    expect(transcribeMessage).not.toHaveBeenCalled();
  });
});
