import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import {
  createDraftPost,
  listDraftPosts,
  getDraftPost,
  updateDraftPost,
  deleteDraftPost,
  publishDraftPost,
} from "@/api/endpoints/newsfeed";

describe("newsfeed draft endpoints", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("maps create/list/get/update/delete draft routes", async () => {
    const postSpy = vi.spyOn(api, "post").mockResolvedValue({} as never);
    const getSpy = vi.spyOn(api, "get").mockResolvedValue({} as never);
    const patchSpy = vi.spyOn(api, "patch").mockResolvedValue({} as never);
    const delSpy = vi.spyOn(api, "del").mockResolvedValue({ ok: true } as never);

    await createDraftPost({ body_plain: "Draft body", body_format: "plain" });
    await listDraftPosts("cursor_1", 25);
    await getDraftPost("draft_1");
    await updateDraftPost("draft_1", { body_plain: "Updated" });
    await deleteDraftPost("draft_1", "2026-04-01T00:00:00Z");

    expect(postSpy).toHaveBeenCalledWith("/posts/drafts", { body_plain: "Draft body", body_format: "plain" });
    expect(getSpy).toHaveBeenCalledWith("/posts/drafts", { cursor: "cursor_1", limit: "25" });
    expect(getSpy).toHaveBeenCalledWith("/posts/drafts/draft_1");
    expect(patchSpy).toHaveBeenCalledWith("/posts/drafts/draft_1", { body_plain: "Updated" });
    expect(delSpy).toHaveBeenCalledWith("/posts/drafts/draft_1", {
      expected_updated_at: "2026-04-01T00:00:00Z",
    });
  });

  it("maps publish draft route and keep_copy flag", async () => {
    const spy = vi.spyOn(api, "post").mockResolvedValue({ post_id: "p1" } as never);

    await publishDraftPost("draft_1");
    await publishDraftPost("draft_2", true);
    await publishDraftPost("draft_3", true, "2026-04-01T00:00:00Z");

    expect(spy).toHaveBeenNthCalledWith(1, "/posts/drafts/draft_1/publish", { keep_copy: false });
    expect(spy).toHaveBeenNthCalledWith(2, "/posts/drafts/draft_2/publish", { keep_copy: true });
    expect(spy).toHaveBeenNthCalledWith(3, "/posts/drafts/draft_3/publish", {
      keep_copy: true,
      expected_updated_at: "2026-04-01T00:00:00Z",
    });
  });
});
