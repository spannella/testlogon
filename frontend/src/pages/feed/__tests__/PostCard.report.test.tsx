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

function renderCard(postOverrides?: Partial<Record<string, unknown>>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const basePost = {
    post_id: "p1",
    author_id: "author2",
    body: "hello",
    created_at: new Date().toISOString(),
    image_urls: ["https://example.com/a.jpg"],
  };
  return render(
    <QueryClientProvider client={client}>
      <PostCard
        post={{ ...basePost, ...(postOverrides ?? {}) } as never}
      />
    </QueryClientProvider>,
  );
}

describe("PostCard media reporting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (window as any).__TIP_LOTTERY_ENABLED__ = true;
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

  it("renders author profile links to canonical route", () => {
    renderCard();
    const links = screen.getAllByRole("link", { name: /open author2 profile/i });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link).toHaveAttribute("href", "/u/author2");
    }
  });

  it("renders lottery lock strategy metadata safely", async () => {
    renderCard({
      locked: true,
      unlocked: false,
      lock_type: "tip_lottery",
      lottery_tip_cents: 175,
      lottery_quiet_period_seconds: 90,
      lottery_state: "open",
    });

    expect(await screen.findByText(/lottery lock/i)).toBeInTheDocument();
    expect(screen.getByText(/tip \$1\.75/i)).toBeInTheDocument();
    expect(screen.getByText(/quiet period 90s/i)).toBeInTheDocument();
    expect(screen.getByText(/state open/i)).toBeInTheDocument();
  });

  it("renders lottery lock fallback values safely when metadata is missing", async () => {
    renderCard({
      locked: true,
      unlocked: false,
      lock_type: "tip_lottery",
    });

    expect(await screen.findByText(/lottery lock/i)).toBeInTheDocument();
    expect(screen.getByText(/tip n\/a/i)).toBeInTheDocument();
    expect(screen.getByText(/quiet period n\/a/i)).toBeInTheDocument();
    expect(screen.getByText(/state open/i)).toBeInTheDocument();
  });

  it("keeps fixed-price lock display unchanged", async () => {
    renderCard({
      locked: true,
      unlocked: false,
      lock_type: "fixed_price",
      unlock_price_cents: 250,
    });

    expect(await screen.findByRole("button", { name: /unlock for \$2\.50/i })).toBeInTheDocument();
    expect(screen.queryByText(/lottery lock/i)).not.toBeInTheDocument();
  });

  it("hides lottery metadata when tip-lottery feature flag is disabled", async () => {
    (window as any).__TIP_LOTTERY_ENABLED__ = false;
    renderCard({
      locked: true,
      unlocked: false,
      lock_type: "tip_lottery",
      lottery_tip_cents: 175,
      lottery_quiet_period_seconds: 90,
      lottery_state: "open",
    });

    expect(await screen.findByText(/this post is locked\./i)).toBeInTheDocument();
    expect(screen.queryByText(/lottery lock/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/tip \$1\.75/i)).not.toBeInTheDocument();
  });
});
