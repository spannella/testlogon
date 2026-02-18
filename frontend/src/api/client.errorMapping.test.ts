import { describe, expect, it } from "vitest";

import { normalizeErrorDetail } from "./client";

describe("normalizeErrorDetail authorization mapping", () => {
  it("maps scope-denied payload to actionable guidance", () => {
    const msg = normalizeErrorDetail(
      {
        code: "role_required_scope",
        required_scope: "billing_support",
        actual_role: "admin",
      },
      "Permission denied",
    );

    expect(msg).toContain("billing support");
    expect(msg).toContain("Request temporary elevation");
  });

  it("maps general-admin-required payload to actionable guidance", () => {
    const msg = normalizeErrorDetail(
      {
        code: "role_required_admin_profile_type",
        required_admin_profile_type: "general",
        actual_role: "admin",
      },
      "Permission denied",
    );

    expect(msg).toContain("general admin access");
    expect(msg).toContain("Request temporary elevation");
  });

  it("does not leak raw object payload for unknown structures", () => {
    const msg = normalizeErrorDetail({ code: "unknown_code", foo: "bar" }, "Permission denied");
    expect(msg).toBe("Permission denied");
  });
});
