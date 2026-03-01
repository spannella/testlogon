import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RichContentRenderer } from "../RichContentRenderer";

const telemetrySpy = vi.fn();
vi.mock("@/lib/newsfeedTelemetry", () => ({
  reportNewsfeedRendererEvent: (...args: unknown[]) => telemetrySpy(...args),
}));

describe("RichContentRenderer", () => {
  it("renders markdown html when format is markdown", () => {
    render(
      <RichContentRenderer
        body="fallback"
        bodyFormat="markdown"
        bodyMarkdown="**hello**"
        bodyMarkdownHtml="<p><strong>hello</strong></p>"
      />,
    );

    expect(screen.getByText("hello").tagName.toLowerCase()).toBe("strong");
  });

  it("falls back to plain rendering for unsupported format", () => {
    telemetrySpy.mockClear();
    render(
      <RichContentRenderer
        body="legacy"
        bodyPlain="plain fallback"
        bodyFormat="unsupported_format"
      />,
    );

    expect(screen.getByText("plain fallback")).toBeInTheDocument();
    expect(telemetrySpy).toHaveBeenCalledWith("unsupported_format", "unsupported_format");
  });

  it("collapses long content and expands/collapses on toggle", async () => {
    const user = userEvent.setup();
    const longText = "line\n".repeat(12);

    render(<RichContentRenderer body={longText} bodyPlain={longText} bodyFormat="plain" />);

    const button = screen.getByRole("button", { name: "Expand content" });
    expect(button).toHaveTextContent("Show more");

    await user.click(button);
    expect(screen.getByRole("button", { name: "Collapse content" })).toHaveTextContent("Show less");

    await user.click(screen.getByRole("button", { name: "Collapse content" }));
    expect(screen.getByRole("button", { name: "Expand content" })).toHaveTextContent("Show more");
  });

  it("falls back to safe plain text if rich payload is invalid", () => {
    telemetrySpy.mockClear();
    render(
      <RichContentRenderer
        body="safe plain"
        bodyPlain="safe plain"
        bodyFormat="rich"
        bodyRich={{ type: "doc", content: 123 as unknown as [] }}
      />,
    );

    expect(screen.getByText("safe plain")).toBeInTheDocument();
  });
});
