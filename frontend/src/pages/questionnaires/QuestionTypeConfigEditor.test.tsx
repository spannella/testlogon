import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import QuestionTypeConfigEditor from "./QuestionTypeConfigEditor";

const cases: Array<{ type: any; label: RegExp; initial: Record<string, unknown> }> = [
  { type: "text", label: /Min length/i, initial: { minLength: 1, maxLength: 10 } },
  { type: "select", label: /Options/i, initial: { options: ["A"] } },
  { type: "multiselect", label: /Min selections/i, initial: { options: ["A"], minSelections: 0, maxSelections: 1 } },
  { type: "radio", label: /Options/i, initial: { options: ["A"] } },
  { type: "slider", label: /Slider min/i, initial: { min: 0, max: 10, step: 1 } },
  { type: "date", label: /Min date/i, initial: { minDate: "", maxDate: "" } },
  { type: "time", label: /Min time/i, initial: { minTime: "", maxTime: "" } },
  { type: "timezone", label: /Allowed timezones/i, initial: { allowedTimezones: ["UTC"] } },
  { type: "address", label: /Required address fields/i, initial: { requiredFields: ["line1"] } },
];

describe("QuestionTypeConfigEditor", () => {
  it.each(cases)("renders editor controls for $type", ({ type, label, initial }) => {
    const onChange = vi.fn();
    render(<QuestionTypeConfigEditor type={type} config={initial} onChange={onChange} />);
    expect(screen.getByLabelText(label)).toBeInTheDocument();
  });

  it("emits updated config on change", () => {
    const onChange = vi.fn();
    render(<QuestionTypeConfigEditor type="text" config={{ minLength: 1, maxLength: 5 }} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText("Min length"), { target: { value: "2" } });
    expect(onChange).toHaveBeenCalled();
    const payload = onChange.mock.calls[onChange.mock.calls.length - 1]?.[0] as Record<string, unknown>;
    expect(payload.minLength).toBe(2);
  });
});
