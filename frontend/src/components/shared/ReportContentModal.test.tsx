import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ReportContentModal } from "./ReportContentModal";

describe("ReportContentModal", () => {
  it("requires at least one topic", async () => {
    const onSubmit = vi.fn();

    render(
      <ReportContentModal
        open
        onOpenChange={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    await userEvent.type(screen.getByLabelText("Reason"), "A valid report reason.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    expect(screen.getByRole("alert")).toHaveTextContent("Select at least one topic.");
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("shows server error message", () => {
    render(
      <ReportContentModal
        open
        onOpenChange={vi.fn()}
        serverError="Server rejected request"
        onSubmit={vi.fn()}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Server rejected request");
  });



  it("validates minimum reason length and trims payload", async () => {
    const onSubmit = vi.fn(async () => {});

    render(
      <ReportContentModal
        open
        onOpenChange={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    await userEvent.click(screen.getByLabelText("Spam"));
    await userEvent.type(screen.getByLabelText("Reason"), " no ");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    expect(screen.getByRole("alert")).toHaveTextContent("Reason must be at least 5 characters.");
    expect(onSubmit).not.toHaveBeenCalled();

    await userEvent.clear(screen.getByLabelText("Reason"));
    await userEvent.type(screen.getByLabelText("Reason"), "   valid reason   ");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith({
        topics: ["spam"],
        reason_text: "valid reason",
      });
    });
  });
  it("emits normalized payload", async () => {
    const onSubmit = vi.fn(async () => {});

    render(
      <ReportContentModal
        open
        onOpenChange={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    await userEvent.click(screen.getByLabelText("Criminal"));
    await userEvent.click(screen.getByLabelText("Spam"));
    await userEvent.type(screen.getByLabelText("Reason"), "Suspicious criminal spam content.");
    await userEvent.click(screen.getByRole("button", { name: "Submit report" }));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith({
        topics: ["criminal", "spam"],
        reason_text: "Suspicious criminal spam content.",
      });
    });
  });
});
