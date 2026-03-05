import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import ValidationRuleBuilder from "./ValidationRuleBuilder";

describe("ValidationRuleBuilder", () => {
  it("adds rules from templates and triggers preview", () => {
    const onChange = vi.fn();
    const onPreview = vi.fn();

    render(
      <ValidationRuleBuilder
        rules={[]}
        onChange={onChange}
        onPreview={onPreview}
        previewOutput={null}
        referenceErrors={[]}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Required if another question is answered/i }));
    expect(onChange).toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Sample answers JSON (preview)"), { target: { value: '{"q1":"x"}' } });
    fireEvent.click(screen.getByRole("button", { name: /Run evaluation preview/i }));
    expect(onPreview).toHaveBeenCalledWith({ q1: "x" });
  });
});
