import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PinnedMessageBanner } from "./PinnedMessageBanner";

describe("PinnedMessageBanner", () => {
  it("renders preview and actions", () => {
    render(
      <PinnedMessageBanner
        latestPinnedMessageId="m1"
        latestPinnedAt={1700000000}
        previewText="This is a pinned message"
        onViewAllPins={() => {}}
        onJumpToMessage={() => {}}
        onDismiss={() => {}}
      />,
    );

    expect(screen.getByText("This is a pinned message")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View all pins" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Jump" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Dismiss pinned banner" })).toBeInTheDocument();
  });

  it("fires action callbacks", async () => {
    const onViewAllPins = vi.fn();
    const onJumpToMessage = vi.fn();
    const onDismiss = vi.fn();

    render(
      <PinnedMessageBanner
        latestPinnedMessageId="m42"
        previewText="Pinned"
        onViewAllPins={onViewAllPins}
        onJumpToMessage={onJumpToMessage}
        onDismiss={onDismiss}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: "View all pins" }));
    await userEvent.click(screen.getByRole("button", { name: "Jump" }));
    await userEvent.click(screen.getByRole("button", { name: "Dismiss pinned banner" }));

    expect(onViewAllPins).toHaveBeenCalledTimes(1);
    expect(onJumpToMessage).toHaveBeenCalledWith("m42");
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});
