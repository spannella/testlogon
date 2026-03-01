import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { MarkdownComposer } from "../MarkdownComposer";

vi.mock("@/lib/featureFlags", () => ({
  newsfeedMarkdownEnabled: true,
  newsfeedRichtextEnabled: true,
}));

function ComposerHarness() {
  const [mode, setMode] = React.useState<"plain" | "markdown" | "rich">("plain");
  const [value, setValue] = React.useState("");
  const [richDoc, setRichDoc] = React.useState<any>(null);
  return (
    <MarkdownComposer
      mode={mode}
      onModeChange={setMode}
      value={value}
      onChange={setValue}
      richDoc={richDoc}
      onRichDocChange={setRichDoc}
      placeholder="Write something"
      rows={4}
    />
  );
}

describe("MarkdownComposer", () => {
  it("shows markdown preview after switching modes and typing", async () => {
    const user = userEvent.setup();
    render(<ComposerHarness />);

    await user.click(screen.getByRole("button", { name: "Markdown" }));
    const textarea = screen.getByPlaceholderText("Write something");
    await user.type(textarea, "**bold**\n- item");

    expect(screen.getByText("Preview")).toBeInTheDocument();
    expect(screen.getByText("bold")).toBeInTheDocument();
    expect(screen.getByText(/•/)).toBeInTheDocument();
  });

  it("executes rich editor toolbar actions", async () => {
    const user = userEvent.setup();
    const execCommand = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", { value: execCommand, configurable: true });

    render(<ComposerHarness />);
    await user.click(screen.getByRole("button", { name: "Rich" }));

    await user.click(screen.getByRole("button", { name: "B" }));
    await user.click(screen.getByRole("button", { name: "I" }));
    await user.click(screen.getByRole("button", { name: "• List" }));
    await user.click(screen.getByRole("button", { name: "1. List" }));
    await user.click(screen.getByRole("button", { name: "Quote" }));
    await user.click(screen.getByRole("button", { name: "Code" }));

    expect(execCommand).toHaveBeenCalledWith("bold", false, undefined);
    expect(execCommand).toHaveBeenCalledWith("italic", false, undefined);
    expect(execCommand).toHaveBeenCalledWith("insertUnorderedList", false, undefined);
    expect(execCommand).toHaveBeenCalledWith("insertOrderedList", false, undefined);
    expect(execCommand).toHaveBeenCalledWith("formatBlock", false, "blockquote");
    expect(execCommand).toHaveBeenCalledWith("formatBlock", false, "pre");

  });

  it("updates text content from rich editor input", async () => {
    const user = userEvent.setup();
    render(<ComposerHarness />);

    await user.click(screen.getByRole("button", { name: "Rich" }));
    const editable = document.querySelector('[contenteditable="true"]') as HTMLElement;
    expect(editable).toBeTruthy();

    fireEvent.input(editable, {
      target: { innerText: "hello rich", innerHTML: "<p>hello rich</p>" },
    });

    expect(editable.textContent ?? "").toContain("hello rich");
  });
});
