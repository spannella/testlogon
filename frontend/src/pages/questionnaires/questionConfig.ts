export type BuilderQuestionType =
  | "text"
  | "select"
  | "multiselect"
  | "radio"
  | "slider"
  | "date"
  | "time"
  | "timezone"
  | "address";

export type BuilderQuestion = {
  question_id: string;
  section_id: string;
  type: BuilderQuestionType;
  label: string;
  required: boolean;
  hint: string;
  config_json: Record<string, unknown>;
};

export function defaultConfigForType(type: BuilderQuestionType): Record<string, unknown> {
  switch (type) {
    case "text":
      return { minLength: 0, maxLength: 200 };
    case "select":
    case "multiselect":
    case "radio":
      return { options: ["Option 1", "Option 2"] };
    case "slider":
      return { min: 0, max: 10, step: 1 };
    case "date":
      return { minDate: "", maxDate: "" };
    case "time":
      return { minTime: "", maxTime: "" };
    case "timezone":
      return { allowedTimezones: [] };
    case "address":
      return { requiredFields: ["line1", "city", "country"] };
  }
}

export function validateQuestionConfig(question: BuilderQuestion): string | null {
  const cfg = question.config_json || {};
  if (question.type === "text") {
    const minLength = Number(cfg.minLength ?? 0);
    const maxLength = Number(cfg.maxLength ?? 0);
    if (Number.isNaN(minLength) || Number.isNaN(maxLength) || minLength < 0 || maxLength < minLength) {
      return "Text constraints are invalid (min/max length).";
    }
  }
  if (question.type === "select" || question.type === "multiselect" || question.type === "radio") {
    const options = cfg.options;
    if (!Array.isArray(options) || options.length === 0 || options.some((opt) => typeof opt !== "string" || !opt.trim())) {
      return "At least one non-empty option is required.";
    }
  }
  if (question.type === "multiselect") {
    const minSelections = Number(cfg.minSelections ?? 0);
    const maxSelections = Number(cfg.maxSelections ?? 9999);
    if (Number.isNaN(minSelections) || Number.isNaN(maxSelections) || minSelections < 0 || maxSelections < minSelections) {
      return "Multiselect min/max selections are invalid.";
    }
  }
  if (question.type === "slider") {
    const min = Number(cfg.min);
    const max = Number(cfg.max);
    const step = Number(cfg.step);
    if (Number.isNaN(min) || Number.isNaN(max) || Number.isNaN(step) || step <= 0 || max <= min) {
      return "Slider config requires numeric min/max and positive step (max > min).";
    }
  }
  return null;
}
