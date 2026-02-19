import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConversationGallery } from "./ConversationGallery";

const getConversationGallery = vi.fn();
vi.mock("@/api/endpoints/messaging", () => ({
  getConversationGallery: (...args: unknown[]) => getConversationGallery(...args),
}));

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderGallery(onJumpToMessage: (id: string) => void = () => {}) {
  const qc = makeClient();
  return render(
    <QueryClientProvider client={qc}>
      <ConversationGallery open onOpenChange={() => {}} conversationId="c1" onJumpToMessage={onJumpToMessage} />
    </QueryClientProvider>,
  );
}

describe("ConversationGallery", () => {
  beforeEach(() => {
    getConversationGallery.mockReset();
  });

  it("shows loading state while tab query is in flight", async () => {
    let release!: (value: { items: never[] }) => void;
    getConversationGallery.mockImplementation(
      () => new Promise((resolve) => {
        release = resolve as (value: { items: never[] }) => void;
      }),
    );

    renderGallery();

    expect(await screen.findByText(/Loading images/i)).toBeInTheDocument();
    release({ items: [] });
  });

  it("shows empty state copy for tabs with no items", async () => {
    getConversationGallery.mockResolvedValue({ items: [] });

    renderGallery();

    expect(await screen.findByText(/No images yet in this conversation/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "Files" }));
    expect(await screen.findByText(/No files yet in this conversation/i)).toBeInTheDocument();
  });

  it("shows recoverable error state and retry action", async () => {
    getConversationGallery.mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce({ items: [] });

    renderGallery();

    expect(await screen.findByText(/Couldn't load images right now/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => {
      expect(getConversationGallery).toHaveBeenCalledTimes(2);
    });
  });

  it("renders content rows/cards for each tab type", async () => {
    getConversationGallery.mockImplementation((_conversationId: string, query: { type: string }) => {
      if (query.type === "image") {
        return Promise.resolve({ items: [{ message_id: "i1", conversation_id: "c1", sender_id: "u1", created_at: 1, type: "image", url: "https://img/1", title: "Image One" }] });
      }
      if (query.type === "video") {
        return Promise.resolve({ items: [{ message_id: "v1", conversation_id: "c1", sender_id: "u1", created_at: 2, type: "video", url: "https://vid/1", file_name: "movie.mp4" }] });
      }
      if (query.type === "file") {
        return Promise.resolve({ items: [{ message_id: "f1", conversation_id: "c1", sender_id: "u1", created_at: 3, type: "file", url: "https://file/1", file_name: "doc.pdf", size: 42 }] });
      }
      return Promise.resolve({ items: [{ message_id: "l1", conversation_id: "c1", sender_id: "u1", created_at: 4, type: "link", url: "https://example.com", title: "Example" }] });
    });

    renderGallery();

    expect(await screen.findByRole("img", { name: "Image One" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: "Videos" }));
    expect(await screen.findByText("movie.mp4")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "Files" }));
    expect(await screen.findByText("doc.pdf")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download/i })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("tab", { name: "Links" }));
    expect(await screen.findByText("Example")).toBeInTheDocument();
  });

  it("loads next gallery page using next_cursor", async () => {
    getConversationGallery
      .mockResolvedValueOnce({
        items: [{ message_id: "m1", conversation_id: "c1", sender_id: "u1", created_at: 1, type: "image", url: "https://img/1" }],
        next_cursor: "cursor-1",
      })
      .mockResolvedValueOnce({
        items: [{ message_id: "m0", conversation_id: "c1", sender_id: "u1", created_at: 0, type: "image", url: "https://img/0" }],
      });

    renderGallery();

    const loadMore = await screen.findByRole("button", { name: "Load more" });
    await userEvent.click(loadMore);

    await waitFor(() =>
      expect(getConversationGallery).toHaveBeenLastCalledWith(
        "c1",
        expect.objectContaining({ type: "image", cursor: "cursor-1" }),
      ),
    );
  });

  it("handles broken image preview and exposes retry preview affordance", async () => {
    getConversationGallery.mockResolvedValue({
      items: [{ message_id: "m1", conversation_id: "c1", sender_id: "u1", created_at: 1, type: "image", url: "https://img/broken.jpg", title: "Broken" }],
    });

    renderGallery();

    const img = await screen.findByRole("img", { name: "Broken" });
    fireEvent.error(img);

    await waitFor(() => {
      expect(screen.getByText(/Image preview unavailable/i)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Retry preview/i })).toBeInTheDocument();
    });
  });

  it("calls jump callback and keeps open/download actions available", async () => {
    const onJump = vi.fn();
    getConversationGallery.mockResolvedValue({
      items: [{ message_id: "m1", conversation_id: "c1", sender_id: "u1", created_at: 1, type: "file", url: "https://file/1", file_name: "doc.pdf" }],
    });

    renderGallery(onJump);

    expect(await screen.findByRole("button", { name: /Open/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Jump to message" }));

    expect(onJump).toHaveBeenCalledWith("m1");
  });
});
