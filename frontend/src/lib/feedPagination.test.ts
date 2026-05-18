import { describe, expect, it } from "vitest";
import { mergeFeedPages } from "./feedPagination";

describe("mergeFeedPages", () => {
  it("deduplicates posts across page boundaries", () => {
    const pages = [
      { items: [{ post_id: "p1" }, { post_id: "p2" }] },
      { items: [{ post_id: "p2" }, { post_id: "p3" }] },
    ] as any;

    const out = mergeFeedPages(pages);
    expect(out.map((p: any) => p.post_id)).toEqual(["p1", "p2", "p3"]);
  });
});
