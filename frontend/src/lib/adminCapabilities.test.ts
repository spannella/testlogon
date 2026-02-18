import { describe, expect, it } from "vitest";

import {
  canAccessGeneralAdminControls,
  canSeeRootRoleManagement,
  getAdminProfileFromAccessToken,
  getRoleFromAccessToken,
} from "./adminCapabilities";

function tokenFor(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  return `${header}.${body}.sig`;
}

describe("adminCapabilities", () => {
  it("parses role from token", () => {
    expect(getRoleFromAccessToken(tokenFor({ role: "admin" }))).toBe("admin");
    expect(getRoleFromAccessToken(tokenFor({ role: "root" }))).toBe("root");
    expect(getRoleFromAccessToken("bad")).toBeNull();
  });

  it("normalizes admin profile from token", () => {
    expect(getAdminProfileFromAccessToken(tokenFor({ role: "admin" }))).toEqual({ type: "general", scopes: [] });
    expect(
      getAdminProfileFromAccessToken(
        tokenFor({ role: "admin", admin_profile: { type: "scoped", scopes: ["auth_support", "auth_support"] } }),
      ),
    ).toEqual({ type: "scoped", scopes: ["auth_support"] });
    expect(
      getAdminProfileFromAccessToken(
        tokenFor({ role: "admin", admin_profile: { type: "scoped", scopes: ["unknown_scope"] } }),
      ),
    ).toEqual({ type: "general", scopes: [] });
  });

  it("gates general admin controls", () => {
    expect(canAccessGeneralAdminControls(tokenFor({ role: "root" }))).toBe(true);
    expect(canAccessGeneralAdminControls(tokenFor({ role: "admin" }))).toBe(true);
    expect(
      canAccessGeneralAdminControls(
        tokenFor({ role: "admin", admin_profile: { type: "scoped", scopes: ["billing_support"] } }),
      ),
    ).toBe(false);
  });

  it("gates root-only role management visibility", () => {
    expect(canSeeRootRoleManagement(tokenFor({ role: "root" }))).toBe(true);
    expect(canSeeRootRoleManagement(tokenFor({ role: "admin" }))).toBe(false);
    expect(canSeeRootRoleManagement(tokenFor({ role: "user" }))).toBe(false);
  });
});
