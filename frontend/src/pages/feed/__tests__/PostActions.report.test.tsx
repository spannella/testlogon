import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { PostActions } from "../PostActions";

const reportFeedContent = vi.fn();

vi.mock("@/api/endpoints/newsfeed", () => ({
  deletePost: vi.fn(async () => ({ ok: true })),
  hidePost: vi.fn(async () => ({ ok: true })),
  reportFeedContent: (...args: unknown[]) => reportFeedContent(...args),
}));

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

function renderActions() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <PostActions postId="p1" isOwn={false} onEdit={vi.fn()} />
    </QueryClientProvider>,
  );
}

describe("PostActions report", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("submits report with feed_post metadata", async () => {
    reportFeedContent.mockResolvedValue({ ok: true, report_id: "r1" });
    renderActions();

    await userEvent.click(screen.getByRole("button"));
    await userEvent.click(await screen.findByRole("menuitem", { name: /report/i }));

    await userEvent.click(screen.getByLabelText("Spam"));
    await userEvent.type(screen.getByLabelText("Reason"), "Spam post content.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(reportFeedContent).toHaveBeenCalledWith({
        content_type: "feed_post",
        content_id: "p1",
        topics: ["spam"],
        reason_text: "Spam post content.",
        post_id: "p1",
      });
    });
  });
});
