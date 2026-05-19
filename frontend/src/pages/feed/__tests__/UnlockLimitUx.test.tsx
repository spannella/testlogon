import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";

import { ApiError } from "@/api/client";
import { CreatePost } from "../CreatePost";
import { EditPostDialog } from "../EditPostDialog";
import { PostCard } from "../PostCard";

const createPostMock = vi.fn();
const editPostMock = vi.fn();
const unlockPostMock = vi.fn();
const getPaymentMethodsMock = vi.fn();

const toast = {
  success: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
};

vi.mock("sonner", () => ({ toast }));

vi.mock("@/stores/offlineStore", () => ({
  useOfflineStore: (selector: (s: { isOnline: boolean; addToQueue: (...args: unknown[]) => void }) => unknown) =>
    selector({ isOnline: true, addToQueue: vi.fn() }),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { userId: string }) => string) => selector({ userId: "viewer_1" }),
}));

vi.mock("@/api/endpoints/files", () => ({
  downloadUrl: vi.fn(() => "https://example.com/file"),
}));

vi.mock("@/pages/messages/FilePickerDialog", () => ({
  FilePickerDialog: () => null,
}));

vi.mock("../MarkdownComposer", () => ({
  MarkdownComposer: ({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) => (
    <textarea
      aria-label={placeholder ?? "composer"}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
  buildContentPayload: (body: string) => ({ body }),
  richDocToPlain: () => "",
}));

vi.mock("@/api/endpoints/newsfeed", () => ({
  createPost: (...args: unknown[]) => createPostMock(...args),
  editPost: (...args: unknown[]) => editPostMock(...args),
  getFeedCapabilities: vi.fn(async () => ({ unlock_limit_enabled: true, unlock_limit_rollout_mode: "broad" })),
  unlockPost: (...args: unknown[]) => unlockPostMock(...args),
  uploadPostImage: vi.fn(async () => ({ url: "https://example.com/image.jpg" })),
  likePost: vi.fn(async () => ({ ok: true })),
  unlikePost: vi.fn(async () => ({ ok: true })),
  addPostReaction: vi.fn(async () => ({ ok: true })),
  removePostReaction: vi.fn(async () => ({ ok: true })),
  reportFeedContent: vi.fn(async () => ({ ok: true, report_id: "r1" })),
}));

vi.mock("@/api/endpoints/billing", () => ({
  getPaymentMethods: (...args: unknown[]) => getPaymentMethodsMock(...args),
}));

vi.mock("../CommentsThread", () => ({ CommentsThread: () => null }));
vi.mock("../PostActions", () => ({ PostActions: () => null }));
vi.mock("../TipDialog", () => ({ TipDialog: () => null }));
vi.mock("../SharePostDialog", () => ({ SharePostDialog: () => null }));
vi.mock("../RichContentRenderer", () => ({ RichContentRenderer: () => <div>post body</div> }));
vi.mock("@/pages/files/FilePreview", () => ({ FilePreview: () => null }));

function renderWithClient(ui: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("unlock-limit UX", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createPostMock.mockResolvedValue({ post_id: "p1" });
    editPostMock.mockResolvedValue({ ok: true });
    unlockPostMock.mockResolvedValue({ ok: true });
    getPaymentMethodsMock.mockResolvedValue([
      { payment_method_id: "pm_1", method_type: "card", brand: "visa", last4: "4242", is_default: true },
    ]);
  });

  it("blocks create submit with invalid unlock limit and shows inline validation", async () => {
    renderWithClient(<CreatePost />);
    const user = userEvent.setup();

    await user.type(screen.getByPlaceholderText("Write a post..."), "hello");
    await user.click(screen.getByRole("button", { name: "Lock" }));
    await user.type(screen.getByPlaceholderText("e.g. 2.99"), "2.99");
    await user.click(screen.getByLabelText("Limit unlocks to N users"));
    await user.type(screen.getByPlaceholderText("e.g. 50"), "0");
    await user.click(screen.getByRole("button", { name: "Post" }));

    expect(await screen.findByText("Unlock limit must be a whole number greater than 0.")).toBeInTheDocument();
    expect(createPostMock).not.toHaveBeenCalled();
  });

  it("blocks edit save with invalid unlock limit and shows inline validation", async () => {
    renderWithClient(
      <EditPostDialog
        open
        onOpenChange={vi.fn()}
        postId="post_1"
        initialBody="hello"
        initialUnlockPriceCents={200}
      />,
    );
    const user = userEvent.setup();

    await user.click(screen.getByLabelText("Limit unlocks to N users"));
    await user.type(screen.getByPlaceholderText("e.g. 50"), "0");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("Unlock limit must be a whole number greater than 0.")).toBeInTheDocument();
    expect(editPostMock).not.toHaveBeenCalled();
  });

  it("shows sold-out state and no actionable unlock CTA", async () => {
    renderWithClient(
      <PostCard
        post={{
          post_id: "post_1",
          author_id: "author_1",
          body: "locked",
          created_at: new Date().toISOString(),
          unlock_price_cents: 250,
          unlock_limit: 3,
          unlock_count: 3,
          unlock_limit_reached: true,
          unlocked: false,
        } as never}
      />,
    );

    expect(await screen.findByText("Sold out — no unlock slots remaining.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unlock for $2.50" })).not.toBeInTheDocument();
  });

  it("maps unlock error codes to sold-out and expired user messages", async () => {
    unlockPostMock
      .mockRejectedValueOnce(
        new ApiError(409, "unlock limit reached", { detail: { code: "unlock_limit_reached", message: "unlock limit reached" } }),
      )
      .mockRejectedValueOnce(
        new ApiError(409, "post lock expired", { detail: { code: "post_lock_expired", message: "post lock expired" } }),
      );

    const post = {
      post_id: "post_2",
      author_id: "author_2",
      body: "locked",
      created_at: new Date().toISOString(),
      unlock_price_cents: 250,
      unlocked: false,
    };

    const user = userEvent.setup();
    const { rerender } = renderWithClient(<PostCard post={post as never} />);

    await user.click(await screen.findByRole("button", { name: "Unlock for $2.50" }));
    await user.click(await screen.findByRole("button", { name: "Pay & Unlock" }));
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith("This post is sold out and can no longer be unlocked.");
    });

    rerender(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
        <PostCard post={post as never} />
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Unlock for $2.50" }));
    await user.click(await screen.findByRole("button", { name: "Pay & Unlock" }));
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith("This post’s lock has expired and can no longer be unlocked.");
    });
  });
});
