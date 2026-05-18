import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";

import { UserProfileLink, resolveCanonicalProfilePath, resolveUserProfileLabel } from "@/components/shared/UserProfileLink";
import { isCanonicalProfileNavigationEnabled } from "@/lib/featureFlags";

vi.mock("@/lib/featureFlags", () => ({
  isCanonicalProfileNavigationEnabled: vi.fn(() => true),
}));

describe("UserProfileLink helpers", () => {
  it("prefers username when generating canonical route", () => {
    expect(resolveCanonicalProfilePath({ username: "alice", userId: "u_123" })).toBe("/u/alice");
  });

  it("falls back to user id when username is missing", () => {
    expect(resolveCanonicalProfilePath({ userId: "u_123" })).toBe("/u/u_123");
  });

  it("returns null route when neither username nor user id exists", () => {
    expect(resolveCanonicalProfilePath({})).toBeNull();
  });

  it("builds label from display name then username then id then fallback", () => {
    expect(resolveUserProfileLabel({ displayName: "Alice", username: "alice", userId: "u_1" })).toBe("Alice");
    expect(resolveUserProfileLabel({ username: "alice", userId: "u_1" })).toBe("alice");
    expect(resolveUserProfileLabel({ userId: "u_1" })).toBe("u_1");
    expect(resolveUserProfileLabel({}, "Member")).toBe("Member");
  });
});

describe("UserProfileLink component", () => {
  it("renders accessible link to canonical profile route", () => {
    render(
      <MemoryRouter>
        <UserProfileLink username="alice" displayName="Alice" />
      </MemoryRouter>,
    );

    const link = screen.getByRole("link", { name: "View Alice profile" });
    expect(link).toHaveAttribute("href", "/u/alice");
    expect(link).toHaveTextContent("Alice");
  });

  it("falls back to text when canonical navigation flag is disabled", () => {
    vi.mocked(isCanonicalProfileNavigationEnabled).mockReturnValue(false);
    render(
      <MemoryRouter>
        <UserProfileLink username="alice" displayName="Alice" />
      </MemoryRouter>,
    );

    const text = screen.getByText("Alice");
    expect(text.tagName.toLowerCase()).toBe("span");
    expect(screen.queryByRole("link", { name: "View Alice profile" })).not.toBeInTheDocument();
    vi.mocked(isCanonicalProfileNavigationEnabled).mockReturnValue(true);
  });

  it("renders fallback text with accessibility label when route cannot be built", () => {
    render(
      <MemoryRouter>
        <UserProfileLink fallbackLabel="Unknown member" />
      </MemoryRouter>,
    );

    const text = screen.getByText("Unknown member");
    expect(text.tagName.toLowerCase()).toBe("span");
    expect(text).toHaveAttribute("aria-label", "View Unknown member profile");
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
