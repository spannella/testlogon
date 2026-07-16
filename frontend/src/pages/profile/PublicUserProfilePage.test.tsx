import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";

import PublicUserProfilePage from "@/pages/profile/PublicUserProfilePage";
import { getProfileByIdentifier, ProfileLookupError } from "@/api/endpoints/profile";

let mockAuthState = { isAuthenticated: false, userId: null as string | null };
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("@/api/endpoints/profile", () => ({
  getProfileByIdentifier: vi.fn(),
  ProfileLookupError: class ProfileLookupError extends Error {
    constructor(
      public code: "not_found_or_suppressed" | "rate_limited" | "unknown",
      message: string,
      public status: number,
      public detail = "",
      public body?: unknown,
      public retryAfterSeconds?: number,
    ) {
      super(message);
      this.name = "ProfileLookupError";
    }
  },
}));

vi.mock("@/api/endpoints/messaging", () => ({
  findOrCreateDm: vi.fn(),
}));

vi.mock("@/api/endpoints/contacts", () => ({
  addContact: vi.fn(),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { isAuthenticated: boolean; userId: string | null }) => unknown) => selector(mockAuthState),
}));

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={qc}>
        <Routes>
          <Route path="/u/:identifier" element={<PublicUserProfilePage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("PublicUserProfilePage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
    mockAuthState = { isAuthenticated: false, userId: null };
  });

  it("renders public preview for anonymous viewer", async () => {
    vi.mocked(getProfileByIdentifier).mockResolvedValue({
      identifier: "alice",
      canonical_identifier: "u_alice",
      user_sub: "u_alice",
      audience: "public",
      profile: {
        display_name: "Alice",
        first_name: "PrivateFirstName",
        last_name: "PrivateLastName",
        title: "Engineer",
        description: "Hello there",
        location: "NYC",
      },
    });

    renderAt("/u/alice");

    expect(await screen.findByText("Alice")).toBeInTheDocument();
    expect(screen.getByText(/canonical profile url/i)).toBeInTheDocument();
    expect(screen.getByText(/\/u\/u_alice/i)).toBeInTheDocument();
    expect(screen.getByTestId("signin-upsell")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in to view more/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^message$/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /add contact/i })).toBeDisabled();
    expect(screen.queryByTestId("member-details")).not.toBeInTheDocument();
    expect(screen.queryByText("PrivateFirstName")).not.toBeInTheDocument();
    expect(screen.getByText(/Audience: public/i)).toBeInTheDocument();
  });

  it("renders member view with member-eligible fields and enabled actions", async () => {
    mockAuthState = { isAuthenticated: true, userId: "u_viewer" };
    vi.mocked(getProfileByIdentifier).mockResolvedValue({
      identifier: "alice",
      user_sub: "u_alice",
      audience: "member",
      profile: {
        display_name: "Alice",
        title: "Engineer",
        displayed_email: "alice@example.com",
        displayed_telephone_number: "+1 555-1234",
        languages: [{ name: "English", level: "native" }],
        first_name: "OwnerPrivateFirst",
      },
    });

    renderAt("/u/alice");

    expect(await screen.findByText("Alice")).toBeInTheDocument();
    expect(screen.getByTestId("member-details")).toBeInTheDocument();
    expect(screen.getByText("alice@example.com")).toBeInTheDocument();
    expect(screen.getByText(/Phone: \+1 555-1234/)).toBeInTheDocument();
    expect(screen.getByText(/Languages: English \(native\)/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^message$/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /add contact/i })).toBeEnabled();
    expect(screen.queryByText(/sign in to view more/i)).not.toBeInTheDocument();
    expect(screen.queryByText("OwnerPrivateFirst")).not.toBeInTheDocument();
    expect(screen.getByText(/Audience: member/i)).toBeInTheDocument();
  });

  it("renders not-found state for suppressed or missing profiles", async () => {
    vi.mocked(getProfileByIdentifier).mockRejectedValue(
      new ProfileLookupError("not_found_or_suppressed", "Profile not available", 404, "Profile not available"),
    );

    renderAt("/u/missing");

    expect(await screen.findByText("Profile Not Available")).toBeInTheDocument();
  });

  it("renders rate-limited state", async () => {
    vi.mocked(getProfileByIdentifier).mockRejectedValue(
      new ProfileLookupError("rate_limited", "Too many profile lookups", 429, "rate limited", null, 17),
    );

    renderAt("/u/alice");

    expect(await screen.findByText("Too Many Requests")).toBeInTheDocument();
    expect(screen.getByText(/Please wait about 17 seconds/i)).toBeInTheDocument();
  });

  it("redirects to canonical identifier path when response canonical identifier differs", async () => {
    vi.mocked(getProfileByIdentifier).mockResolvedValue({
      identifier: "legacy_alias",
      canonical_identifier: "u_alice",
      user_sub: "u_alice",
      audience: "public",
      profile: {
        display_name: "Alice",
      },
    });

    renderAt("/u/legacy_alias");

    expect(await screen.findByText("Alice")).toBeInTheDocument();
    expect(navigateMock).toHaveBeenCalledWith("/u/u_alice", { replace: true });
  });
});
