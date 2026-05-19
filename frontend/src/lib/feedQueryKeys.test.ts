import { describe, expect, it } from "vitest";
import { feedQueryKeys } from "./feedQueryKeys";

describe("feedQueryKeys.timeline", () => {
  it("isolates global and profile caches", () => {
    const globalKey = feedQueryKeys.timeline();
    const profileKey = feedQueryKeys.timeline({ authorId: "u1" });
    expect(globalKey).not.toEqual(profileKey);
  });

  it("changes when filter params change", () => {
    const a = feedQueryKeys.timeline({ authorId: "u1", q: "alpha" });
    const b = feedQueryKeys.timeline({ authorId: "u1", q: "beta" });
    expect(a).not.toEqual(b);
  });
});
