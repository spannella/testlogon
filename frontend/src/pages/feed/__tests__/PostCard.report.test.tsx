import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { PostCard } from "../PostCard";

const reportFeedContent = vi.fn();

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { userId: string }) => string) => selector({ userId: "viewer" }),
}));

vi.mock("@/api/endpoints/newsfeed", () => ({
  likePost: vi.fn(async () => ({ ok: true })),
  unlikePost: vi.fn(async () => ({ ok: true })),
  unlockPost: vi.fn(async () => ({ ok: true })),
  addPostReaction: vi.fn(async () => ({ ok: true })),
  removePostReaction: vi.fn(async () => ({ ok: true })),
  reportFeedContent: (...args: unknown[]) => reportFeedContent(...args),
}));

vi.mock("@/api/endpoints/billing", () => ({ getPaymentMethods: vi.fn(async () => []) }));
vi.mock("../CommentsThread", () => ({ CommentsThread: () => null }));
vi.mock("../PostActions", () => ({ PostActions: () => null }));
vi.mock("../EditPostDialog", () => ({ EditPostDialog: () => null }));
vi.mock("../TipDialog", () => ({ TipDialog: () => null }));
vi.mock("../SharePostDialog", () => ({ SharePostDialog: () => null }));
vi.mock("../RichContentRenderer", () => ({ RichContentRenderer: () => <div>post body</div> }));
vi.mock("@/pages/files/FilePreview", () => ({ FilePreview: () => null }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function renderCard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <PostCard
        post={{
          post_id: "p1",
          author_id: "author2",
          body: "hello",
          created_at: new Date().toISOString(),
          image_urls: ["https://example.com/a.jpg"],
        } as never}
      />
    </QueryClientProvider>,
  );
}

describe("PostCard media reporting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("submits report with feed_media metadata", async () => {
    reportFeedContent.mockResolvedValue({ ok: true, report_id: "r1" });
    renderCard();

    await userEvent.click(screen.getByRole("button", { name: "Open image 1" }));
    await userEvent.click(await screen.findByRole("button", { name: /report image/i }));

    await userEvent.click(screen.getByLabelText("Criminal"));
    await userEvent.type(screen.getByLabelText("Reason"), "Criminal activity shown.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(reportFeedContent).toHaveBeenCalledWith({
        content_type: "feed_media",
        content_id: "p1:0",
        topics: ["criminal"],
        reason_text: "Criminal activity shown.",
        post_id: "p1",
        media_index: 0,
      });
    });
  });
});
