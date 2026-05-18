import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ProfilePosts } from "./ProfilePosts";

const feedTimelineSpy = vi.fn();
const useAuthStoreMock = vi.fn();

vi.mock("@/pages/feed/FeedTimeline", () => ({
  FeedTimeline: (props: Record<string, unknown>) => {
    feedTimelineSpy(props);
    return <div data-testid="feed-timeline" />;
  },
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (state: { userId: string | null }) => unknown) =>
    useAuthStoreMock(selector),
}));

describe("ProfilePosts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStoreMock.mockImplementation((selector: (state: { userId: string | null }) => unknown) =>
      selector({ userId: "user-123" }),
    );
  });

  const renderPage = (entry = "/settings/profile?pf_q=hello&pf_from=2026-03-01&pf_to=2026-03-10&pf_has_media=1") =>
    render(
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/settings/profile" element={<ProfilePosts />} />
        </Routes>
      </MemoryRouter>,
    );

  it("hydrates timeline params from URL state", () => {
    renderPage();

    expect(screen.getByLabelText("Search posts")).toHaveValue("hello");
    expect(screen.getByLabelText("From")).toHaveValue("2026-03-01");
    expect(screen.getByLabelText("To")).toHaveValue("2026-03-10");

    expect(feedTimelineSpy).toHaveBeenCalled();
    const lastCall = feedTimelineSpy.mock.calls[feedTimelineSpy.mock.calls.length - 1]?.[0] as Record<string, unknown>;
    expect(lastCall.authorId).toBe("user-123");
    expect(lastCall.q).toBe("hello");
    expect(lastCall.from).toBe("2026-03-01T00:00:00Z");
    expect(lastCall.to).toBe("2026-03-10T23:59:59Z");
    expect(lastCall.hasMedia).toBe(true);
    expect(screen.getByLabelText("Media")).toHaveValue("with");
  });

  it("hydrates hasMedia=false from URL state and forwards it to timeline", () => {
    renderPage("/settings/profile?pf_has_media=0");

    const lastCall = feedTimelineSpy.mock.calls[feedTimelineSpy.mock.calls.length - 1]?.[0] as Record<string, unknown>;
    expect(lastCall.hasMedia).toBe(false);
    expect(screen.getByLabelText("Media")).toHaveValue("without");
  });

  it("clears filters and updates rendered timeline props", () => {
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "Clear" }));

    const lastCall = feedTimelineSpy.mock.calls[feedTimelineSpy.mock.calls.length - 1]?.[0] as Record<string, unknown>;
    expect(screen.getByLabelText("Search posts")).toHaveValue("");
    expect(screen.getByLabelText("From")).toHaveValue("");
    expect(screen.getByLabelText("To")).toHaveValue("");
    expect(lastCall.q).toBeUndefined();
    expect(lastCall.from).toBeUndefined();
    expect(lastCall.to).toBeUndefined();
    expect(lastCall.hasMedia).toBeUndefined();
    expect(screen.getByLabelText("Media")).toHaveValue("all");
  });

  it("returns null when user is not authenticated", () => {
    useAuthStoreMock.mockImplementation((selector: (state: { userId: string | null }) => unknown) =>
      selector({ userId: null }),
    );

    const { container } = renderPage("/settings/profile");

    expect(container).toBeEmptyDOMElement();
    expect(feedTimelineSpy).not.toHaveBeenCalled();
  });
});
