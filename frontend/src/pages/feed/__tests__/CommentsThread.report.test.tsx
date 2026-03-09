import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { CommentsThread } from "../CommentsThread";

const reportFeedContent = vi.fn();

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { userId: string }) => string) => selector({ userId: "viewer" }),
}));

vi.mock("@/api/endpoints/newsfeed", () => ({
  getComments: vi.fn(async () => ({
    items: [
      {
        comment_id: "c1",
        post_id: "p1",
        author_id: "author2",
        body: "test",
        created_at: new Date().toISOString(),
      },
    ],
  })),
  createComment: vi.fn(async () => ({})),
  editComment: vi.fn(async () => ({})),
  deleteComment: vi.fn(async () => ({ ok: true })),
  reportFeedContent: (...args: unknown[]) => reportFeedContent(...args),
}));

vi.mock("../MarkdownComposer", () => ({
  MarkdownComposer: () => null,
  richDocToPlain: () => "",
  buildContentPayload: () => ({ body: "x" }),
}));
vi.mock("../RichContentRenderer", () => ({ RichContentRenderer: () => <div>body</div> }));
vi.mock("../TipDialog", () => ({ TipDialog: () => null }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function renderThread() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <CommentsThread postId="p1" />
    </QueryClientProvider>,
  );
}

describe("CommentsThread report", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("submits report with feed_comment metadata", async () => {
    reportFeedContent.mockResolvedValue({ ok: true, report_id: "r1" });
    renderThread();

    await screen.findByText("body");
    await userEvent.click(screen.getByRole("button", { name: "Comment actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /report comment/i }));

    await userEvent.click(screen.getByLabelText("Racist"));
    await userEvent.type(screen.getByLabelText("Reason"), "Racist slur in comment.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(reportFeedContent).toHaveBeenCalledWith({
        content_type: "feed_comment",
        content_id: "c1",
        topics: ["racist"],
        reason_text: "Racist slur in comment.",
        post_id: "p1",
        comment_id: "c1",
      });
    });
  });
});
