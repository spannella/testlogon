import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import ProfilePage from "./ProfilePage";

const isProfilePostsFeedEnabledMock = vi.fn();

vi.mock("@/lib/featureFlags", () => ({
  isProfilePostsFeedEnabled: () => isProfilePostsFeedEnabledMock(),
}));

vi.mock("./Profile", () => ({ Profile: () => <div>ProfileContent</div> }));
vi.mock("./Addresses", () => ({ Addresses: () => <div>AddressesContent</div> }));
vi.mock("./ProfileAudit", () => ({ ProfileAudit: () => <div>ProfileAuditContent</div> }));
vi.mock("./ProfilePosts", () => ({ ProfilePosts: () => <div>ProfilePostsContent</div> }));

describe("ProfilePage profile posts flag", () => {
  it("shows Posts tab when profile posts feed is enabled", () => {
    isProfilePostsFeedEnabledMock.mockReturnValue(true);

    render(<ProfilePage />);

    expect(screen.getByRole("tab", { name: "Posts" })).toBeInTheDocument();
  });

  it("hides Posts tab when profile posts feed is disabled", () => {
    isProfilePostsFeedEnabledMock.mockReturnValue(false);

    render(<ProfilePage />);

    expect(screen.queryByRole("tab", { name: "Posts" })).not.toBeInTheDocument();
  });
});
