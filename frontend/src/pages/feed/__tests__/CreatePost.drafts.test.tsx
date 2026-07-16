import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CreatePost } from "../CreatePost";
import { ApiError } from "@/api/client";

const toastSuccess = vi.fn();
const toastInfo = vi.fn();
const toastError = vi.fn();
const createPost = vi.fn();
const publishDraftPost = vi.fn();
const createDraftPost = vi.fn();
const listDraftPosts = vi.fn();
const getDraftPost = vi.fn();
const deleteDraftPost = vi.fn();
const updateDraftPost = vi.fn();
const getFileInfo = vi.fn();
const reportDraftLifecycleEvent = vi.fn();
let draftsFeatureEnabled = true;

vi.mock("@/stores/offlineStore", () => ({
  useOfflineStore: (selector: (state: { isOnline: boolean; addToQueue: ReturnType<typeof vi.fn> }) => unknown) =>
    selector({ isOnline: true, addToQueue: vi.fn() }),
}));

vi.mock("@/api/endpoints/newsfeed", () => ({
  createPost: (...args: unknown[]) => createPost(...args),
  publishDraftPost: (...args: unknown[]) => publishDraftPost(...args),
  uploadPostImage: vi.fn(),
  createDraftPost: (...args: unknown[]) => createDraftPost(...args),
  listDraftPosts: (...args: unknown[]) => listDraftPosts(...args),
  getDraftPost: (...args: unknown[]) => getDraftPost(...args),
  updateDraftPost: (...args: unknown[]) => updateDraftPost(...args),
  deleteDraftPost: (...args: unknown[]) => deleteDraftPost(...args),
}));

vi.mock("@/api/endpoints/files", () => ({
  downloadUrl: vi.fn(() => ""),
  getFileInfo: (...args: unknown[]) => getFileInfo(...args),
}));

vi.mock("@/pages/messages/FilePickerDialog", () => ({
  FilePickerDialog: () => null,
}));

vi.mock("@/lib/featureFlags", () => ({
  isNewsfeedDraftsEnabled: () => draftsFeatureEnabled,
}));

vi.mock("@/lib/newsfeedDraftTelemetry", () => ({
  reportDraftLifecycleEvent: (...args: unknown[]) => reportDraftLifecycleEvent(...args),
}));

vi.mock("../MarkdownComposer", () => ({
  MarkdownComposer: ({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) => (
    <textarea aria-label="Post body" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
  ),
  buildContentPayload: (body: string) => ({ body, body_plain: body, body_format: "plain" }),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
    info: (...args: unknown[]) => toastInfo(...args),
  },
}));

function renderCreatePost() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <CreatePost />
    </QueryClientProvider>,
  );
}

describe("CreatePost server-backed draft controls", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    draftsFeatureEnabled = true;

    listDraftPosts.mockResolvedValue({
      items: [
        {
          draft_id: "d_1",
          author_id: "u_1",
          created_at: "2026-04-01T00:00:00Z",
          updated_at: "2026-04-01T00:00:00Z",
          body_plain: "Server saved draft",
          body_format: "plain",
        },
        {
          draft_id: "d_3",
          author_id: "u_1",
          created_at: "2026-04-01T00:02:00Z",
          updated_at: "2026-04-01T00:02:00Z",
          body_plain: "Second server draft",
          body_format: "plain",
        },
      ],
    });

    createDraftPost.mockResolvedValue({
      draft_id: "d_3",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:00:00Z",
      body_plain: "My new draft",
      body_format: "plain",
    });

    getDraftPost.mockResolvedValue({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:01:00Z",
      body_plain: "Server saved draft",
      body_format: "plain",
      image_urls: [],
      file_paths: [],
    });

    deleteDraftPost.mockResolvedValue({ ok: true });
    createPost.mockResolvedValue({
      post_id: "p_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:10:00Z",
      body: "published",
      body_plain: "published",
      body_format: "plain",
      body_version: 1,
      image_urls: [],
      visibility: "followers",
      locked: false,
      like_count: 0,
      comment_count: 0,
    });
    publishDraftPost.mockResolvedValue({
      post_id: "p_from_draft",
      author_id: "u_1",
      created_at: "2026-04-01T00:10:00Z",
      body: "published from draft",
      body_plain: "published from draft",
      body_format: "plain",
      body_version: 1,
      image_urls: [],
      visibility: "followers",
      locked: false,
      like_count: 0,
      comment_count: 0,
    });
    getFileInfo.mockResolvedValue({ name: "spec.pdf", path: "/docs/spec.pdf", type: "file", content_type: "application/pdf" });
    updateDraftPost.mockResolvedValue({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:05:00Z",
      body_plain: "Server saved draft edited",
      body_format: "plain",
    });
  });

  it("supports save-changes mode and confirms before switching dirty drafts", async () => {
    const user = userEvent.setup();
    renderCreatePost();

    await screen.findByText("Saved drafts (2)");
    expect(screen.getByText("Server saved draft")).toBeInTheDocument();

    const input = screen.getByPlaceholderText("What's on your mind?");
    await user.type(input, "My new draft");
    await user.click(screen.getByRole("button", { name: "Save Draft" }));

    await waitFor(() => {
      expect(createDraftPost).toHaveBeenCalled();
    });

    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledWith("d_1");
    });
    expect(screen.getByDisplayValue("Server saved draft")).toBeInTheDocument();
    expect(screen.getByText("Draft state: All changes saved")).toBeInTheDocument();

    await user.type(input, " edited");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeInTheDocument();
    expect(screen.getByText("Draft state: Unsaved changes")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => {
      expect(updateDraftPost).toHaveBeenCalledWith("d_1", expect.objectContaining({
        body: "Server saved draft edited",
        expected_updated_at: "2026-04-01T00:01:00Z",
      }));
    });

    await user.type(input, " pending");

    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    await user.click(screen.getAllByRole("button", { name: "Load" })[1]!);
    expect(confirmSpy).toHaveBeenCalled();
    expect(getDraftPost).toHaveBeenCalledTimes(1);

    confirmSpy.mockReturnValue(true);
    getDraftPost.mockResolvedValueOnce({
      draft_id: "d_2",
      author_id: "u_1",
      created_at: "2026-04-01T00:02:00Z",
      updated_at: "2026-04-01T00:02:00Z",
      body_plain: "Second server draft",
      body_format: "plain",
      image_urls: [],
      file_paths: [],
    });
    await user.click(screen.getAllByRole("button", { name: "Load" })[1]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledTimes(2);
    });
    expect(screen.getByDisplayValue("Second server draft")).toBeInTheDocument();

    await user.click(screen.getAllByRole("button", { name: "Remove" })[0]!);
    await waitFor(() => {
      expect(deleteDraftPost).toHaveBeenCalledWith("d_1", expect.any(String));
    });

    expect(toastSuccess).toHaveBeenCalledWith("Draft saved");
    expect(toastSuccess).toHaveBeenCalledWith("Draft loaded");
    expect(toastSuccess).toHaveBeenCalledWith("Draft removed");
  });

  it("drops missing file references when loading a draft", async () => {
    const user = userEvent.setup();
    getDraftPost.mockResolvedValueOnce({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:01:00Z",
      body_plain: "Server saved draft",
      body_format: "plain",
      image_urls: [],
      file_paths: ["/docs/spec.pdf", "/docs/missing.pdf"],
    });
    getFileInfo
      .mockResolvedValueOnce({ name: "spec.pdf", path: "/docs/spec.pdf", type: "file", content_type: "application/pdf" })
      .mockRejectedValueOnce(new Error("Not found"));

    renderCreatePost();
    await screen.findByText("Saved drafts (2)");
    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);

    await waitFor(() => {
      expect(getFileInfo).toHaveBeenCalledWith("/docs/spec.pdf");
      expect(getFileInfo).toHaveBeenCalledWith("/docs/missing.pdf");
    });
    expect(screen.getByText("spec.pdf")).toBeInTheDocument();
    expect(screen.queryByText("missing.pdf")).not.toBeInTheDocument();
  });

  it("debounces autosave and retries transient failures with backoff", async () => {
    createDraftPost
      .mockRejectedValueOnce(new Error("Network timeout"))
      .mockResolvedValueOnce({
        draft_id: "d_9",
        author_id: "u_1",
        created_at: "2026-04-01T00:00:00Z",
        updated_at: "2026-04-01T00:00:05Z",
        body_plain: "Autosave draft",
        body_format: "plain",
      });

    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    const input = screen.getByPlaceholderText("What's on your mind?");
    fireEvent.change(input, { target: { value: "Auto" } });
    await new Promise((resolve) => setTimeout(resolve, 500));
    fireEvent.change(input, { target: { value: "Autosave draft" } });

    await new Promise((resolve) => setTimeout(resolve, 1200));
    expect(createDraftPost).not.toHaveBeenCalled();

    await waitFor(() => expect(createDraftPost).toHaveBeenCalledTimes(1), { timeout: 3000 });
    await screen.findByText("Autosave retrying…");

    await waitFor(() => expect(createDraftPost).toHaveBeenCalledTimes(2), { timeout: 4000 });
    expect(screen.getByText("Saved just now")).toBeInTheDocument();
  }, 15000);

  it("imports legacy localStorage draft once and cleans up keys", async () => {
    const legacyKey = "newsfeed_create_post_draft";
    window.localStorage.setItem(legacyKey, JSON.stringify({
      body: "Legacy local draft",
      image_urls: ["https://cdn.example.com/local.jpg"],
    }));

    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    await waitFor(() => {
      expect(createDraftPost).toHaveBeenCalledWith(expect.objectContaining({ body_plain: "Legacy local draft" }));
    });
    expect(window.localStorage.getItem(legacyKey)).toBeNull();
    expect(window.localStorage.getItem("newsfeed_draft_migration_v1_done")).toBe("1");
    expect(toastSuccess).toHaveBeenCalledWith("Imported 1 local draft from this device");
  });

  it("hides draft controls when feature flag is disabled", async () => {
    draftsFeatureEnabled = false;
    renderCreatePost();

    expect(screen.queryByRole("button", { name: "Save Draft" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Saved drafts/i)).not.toBeInTheDocument();
  });

  it("surfaces save/load/delete draft errors", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    createDraftPost.mockRejectedValueOnce(new Error("Save failed"));
    await user.type(screen.getByPlaceholderText("What's on your mind?"), "Needs save");
    await user.click(screen.getByRole("button", { name: "Save Draft" }));
    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Save failed"));
    expect(reportDraftLifecycleEvent).toHaveBeenCalledWith("save_fail", "fail", "save_failed");

    getDraftPost.mockRejectedValueOnce(new Error("Load failed"));
    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Load failed"));
    expect(reportDraftLifecycleEvent).toHaveBeenCalledWith("load_fail", "fail", "load_failed");

    deleteDraftPost.mockRejectedValueOnce(new Error("Delete failed"));
    await user.click(screen.getAllByRole("button", { name: "Remove" })[0]!);
    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Delete failed"));
    expect(reportDraftLifecycleEvent).toHaveBeenCalledWith("delete_fail", "fail", "delete_failed");
  });

  it("surfaces stale-draft conflict errors on remove", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    deleteDraftPost.mockRejectedValueOnce(
      new ApiError(409, "Conflict", { detail: { code: "newsfeed_draft_version_conflict" } }),
    );
    await user.click(screen.getAllByRole("button", { name: "Remove" })[0]!);

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith("Draft changed on another session. Refresh and try removing it again.");
    });
  });

  it("surfaces stale-draft conflict errors on save changes", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledWith("d_1");
    });

    updateDraftPost.mockRejectedValueOnce(
      new ApiError(409, "Conflict", { detail: { code: "newsfeed_draft_version_conflict" } }),
    );
    getDraftPost.mockResolvedValueOnce({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:05:00Z",
      body_plain: "Server latest draft",
      body_format: "plain",
      image_urls: [],
      file_paths: [],
    });

    await user.type(screen.getByPlaceholderText("What's on your mind?"), " conflicted");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith("Draft changed on another session. Reloading latest draft...");
    });
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledTimes(2);
    });
    expect(toastSuccess).toHaveBeenCalledWith("Latest draft loaded. Review changes and save again.");
  });

  it("pauses autosave with conflict status when server draft changed elsewhere", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledWith("d_1");
    });

    updateDraftPost.mockRejectedValueOnce(
      new ApiError(409, "Conflict", { detail: { code: "newsfeed_draft_version_conflict" } }),
    );

    await user.type(screen.getByPlaceholderText("What's on your mind?"), " autosave-conflict");
    await waitFor(() => {
      expect(updateDraftPost).toHaveBeenCalled();
    }, { timeout: 3500 });

    expect(screen.getByText("Autosave paused: draft changed on another session.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload latest" })).toBeInTheDocument();
    const callsAfterConflict = updateDraftPost.mock.calls.length;
    await user.type(screen.getByPlaceholderText("What's on your mind?"), " more");
    await new Promise((resolve) => setTimeout(resolve, 2500));
    expect(updateDraftPost).toHaveBeenCalledTimes(callsAfterConflict);
    expect(reportDraftLifecycleEvent).toHaveBeenCalledWith("save_fail", "fail", "newsfeed_draft_version_conflict");

    getDraftPost.mockResolvedValueOnce({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:10:00Z",
      body_plain: "Recovered latest draft",
      body_format: "plain",
      image_urls: [],
      file_paths: [],
    });
    await user.click(screen.getByRole("button", { name: "Reload latest" }));
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledTimes(2);
    });
  }, 10000);

  it("supports cross-session draft persistence and publish after load", async () => {
    const serverDrafts: Array<{
      draft_id: string;
      author_id: string;
      created_at: string;
      updated_at: string;
      body_plain: string;
      body_format: "plain";
      image_urls: string[];
      file_paths: string[];
    }> = [];
    let seq = 0;

    listDraftPosts.mockImplementation(async () => ({ items: serverDrafts.map(({ image_urls, file_paths, ...rest }) => rest) }));
    createDraftPost.mockImplementation(async (payload: { body_plain?: string }) => {
      seq += 1;
      const created = {
        draft_id: `d_${seq}`,
        author_id: "u_1",
        created_at: "2026-04-01T00:00:00Z",
        updated_at: "2026-04-01T00:00:00Z",
        body_plain: payload.body_plain ?? "",
        body_format: "plain" as const,
        image_urls: [],
        file_paths: [],
      };
      serverDrafts.push(created);
      return created;
    });
    getDraftPost.mockImplementation(async (draftId: string) => {
      const found = serverDrafts.find((d) => d.draft_id === draftId);
      if (!found) throw new Error("Not found");
      return found;
    });

    const user1 = userEvent.setup();
    const session1 = renderCreatePost();
    await screen.findByText("Saved drafts (0)");
    await user1.type(screen.getByPlaceholderText("What's on your mind?"), "Draft from session one");
    await user1.click(screen.getByRole("button", { name: "Save Draft" }));
    await waitFor(() => expect(createDraftPost).toHaveBeenCalled());
    session1.unmount();

    const user2 = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (1)");
    expect(screen.getByText("Draft from session one")).toBeInTheDocument();

    await user2.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(getDraftPost).toHaveBeenCalledWith("d_1"));
    expect(screen.getByDisplayValue("Draft from session one")).toBeInTheDocument();

    await user2.click(screen.getByRole("button", { name: "Post" }));
    await waitFor(() => {
      expect(publishDraftPost).toHaveBeenCalledWith("d_1", false, "2026-04-01T00:00:00Z");
    });
    expect(createPost).not.toHaveBeenCalled();
    expect(reportDraftLifecycleEvent).toHaveBeenCalledWith("publish_from_draft", "success");
    expect(screen.getByText("Saved drafts (0)")).toBeInTheDocument();
  });

  it("surfaces stale-draft conflict errors on publish-from-draft", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledWith("d_1");
    });

    publishDraftPost.mockRejectedValueOnce(
      new ApiError(409, "Conflict", { detail: { code: "newsfeed_draft_version_conflict" } }),
    );
    getDraftPost.mockResolvedValueOnce({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:04:00Z",
      body_plain: "Server latest draft",
      body_format: "plain",
      image_urls: [],
      file_paths: [],
    });

    await user.click(screen.getByRole("button", { name: "Post" }));
    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith("Draft changed on another session. Reloading latest draft...");
    });
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledTimes(2);
    });
    expect(toastSuccess).toHaveBeenCalledWith("Latest draft loaded. Review changes and publish again.");
    expect(reportDraftLifecycleEvent).toHaveBeenCalledWith("publish_from_draft", "fail", "version_conflict");
  });

  it("saves unsaved draft changes before publish-from-draft", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledWith("d_1");
    });

    updateDraftPost.mockResolvedValueOnce({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:03:00Z",
      body_plain: "Server saved draft changed",
      body_format: "plain",
    });

    await user.type(screen.getByPlaceholderText("What's on your mind?"), " changed");
    await user.click(screen.getByRole("button", { name: "Post" }));

    await waitFor(() => {
      expect(updateDraftPost).toHaveBeenCalledWith("d_1", expect.objectContaining({
        body: "Server saved draft changed",
        expected_updated_at: "2026-04-01T00:01:00Z",
      }));
    });
    await waitFor(() => {
      expect(publishDraftPost).toHaveBeenCalledWith("d_1", false, "2026-04-01T00:03:00Z");
    });
  });

  it("prevents duplicate submit while pre-publish save is pending", async () => {
    const user = userEvent.setup();
    renderCreatePost();
    await screen.findByText("Saved drafts (2)");

    await user.click(screen.getAllByRole("button", { name: "Load" })[0]!);
    await waitFor(() => {
      expect(getDraftPost).toHaveBeenCalledWith("d_1");
    });

    let resolveSave: (value: any) => void = () => {};
    const pendingSave = new Promise((resolve) => {
      resolveSave = resolve;
    });
    updateDraftPost.mockReturnValueOnce(pendingSave);

    await user.type(screen.getByPlaceholderText("What's on your mind?"), " changed");
    const postButton = screen.getByRole("button", { name: "Post" });
    await user.click(postButton);
    await user.click(postButton);

    expect(updateDraftPost).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Posting..." })).toBeDisabled();
    expect(publishDraftPost).not.toHaveBeenCalled();

    resolveSave?.({
      draft_id: "d_1",
      author_id: "u_1",
      created_at: "2026-04-01T00:00:00Z",
      updated_at: "2026-04-01T00:06:00Z",
      body_plain: "Server saved draft changed",
      body_format: "plain",
    });

    await waitFor(() => {
      expect(publishDraftPost).toHaveBeenCalledWith("d_1", false, "2026-04-01T00:06:00Z");
    });
  });
});
