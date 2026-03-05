import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

import type { BuilderQuestionType } from "./questionConfig";

type Props = {
  type: BuilderQuestionType;
  config: Record<string, unknown>;
  onChange: (config: Record<string, unknown>) => void;
};

function csvToList(value: string): string[] {
  return value
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

function listToCsv(value: unknown): string {
  if (!Array.isArray(value)) return "";
  return value.filter((v) => typeof v === "string").join(", ");
}

export default function QuestionTypeConfigEditor({ type, config, onChange }: Props) {
  if (type === "text") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <div>
          <Label>Min length</Label>
          <Input
            aria-label="Min length"
            type="number"
            value={String(config.minLength ?? "")}
            onChange={(e) => onChange({ ...config, minLength: Number(e.target.value) })}
          />
        </div>
        <div>
          <Label>Max length</Label>
          <Input
            aria-label="Max length"
            type="number"
            value={String(config.maxLength ?? "")}
            onChange={(e) => onChange({ ...config, maxLength: Number(e.target.value) })}
          />
        </div>
        <div className="col-span-2">
          <Label>Regex pattern (optional)</Label>
          <Input
            aria-label="Regex pattern"
            value={String(config.pattern ?? "")}
            onChange={(e) => onChange({ ...config, pattern: e.target.value })}
          />
        </div>
      </div>
    );
  }

  if (type === "select" || type === "multiselect" || type === "radio") {
    return (
      <div className="space-y-2">
        <Label>Options (comma separated)</Label>
        <Textarea
          aria-label="Options"
          rows={2}
          value={listToCsv(config.options)}
          onChange={(e) => onChange({ ...config, options: csvToList(e.target.value) })}
        />
        {type === "multiselect" && (
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label>Min selections</Label>
              <Input
                aria-label="Min selections"
                type="number"
                value={String(config.minSelections ?? 0)}
                onChange={(e) => onChange({ ...config, minSelections: Number(e.target.value) })}
              />
            </div>
            <div>
              <Label>Max selections</Label>
              <Input
                aria-label="Max selections"
                type="number"
                value={String(config.maxSelections ?? "")}
                onChange={(e) => onChange({ ...config, maxSelections: Number(e.target.value) })}
              />
            </div>
          </div>
        )}
      </div>
    );
  }

  if (type === "slider") {
    return (
      <div className="grid grid-cols-3 gap-2">
        <div>
          <Label>Min</Label>
          <Input aria-label="Slider min" type="number" value={String(config.min ?? "")} onChange={(e) => onChange({ ...config, min: Number(e.target.value) })} />
        </div>
        <div>
          <Label>Max</Label>
          <Input aria-label="Slider max" type="number" value={String(config.max ?? "")} onChange={(e) => onChange({ ...config, max: Number(e.target.value) })} />
        </div>
        <div>
          <Label>Step</Label>
          <Input aria-label="Slider step" type="number" value={String(config.step ?? "")} onChange={(e) => onChange({ ...config, step: Number(e.target.value) })} />
        </div>
      </div>
    );
  }

  if (type === "date") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <div>
          <Label>Min date</Label>
          <Input aria-label="Min date" type="date" value={String(config.minDate ?? "")} onChange={(e) => onChange({ ...config, minDate: e.target.value })} />
        </div>
        <div>
          <Label>Max date</Label>
          <Input aria-label="Max date" type="date" value={String(config.maxDate ?? "")} onChange={(e) => onChange({ ...config, maxDate: e.target.value })} />
        </div>
      </div>
    );
  }

  if (type === "time") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <div>
          <Label>Min time</Label>
          <Input aria-label="Min time" type="time" value={String(config.minTime ?? "")} onChange={(e) => onChange({ ...config, minTime: e.target.value })} />
        </div>
        <div>
          <Label>Max time</Label>
          <Input aria-label="Max time" type="time" value={String(config.maxTime ?? "")} onChange={(e) => onChange({ ...config, maxTime: e.target.value })} />
        </div>
      </div>
    );
  }

  if (type === "timezone") {
    return (
      <div className="space-y-2">
        <Label>Allowed timezones (comma separated)</Label>
        <Input
          aria-label="Allowed timezones"
          value={listToCsv(config.allowedTimezones)}
          onChange={(e) => onChange({ ...config, allowedTimezones: csvToList(e.target.value) })}
        />
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <Label>Required address fields (comma separated)</Label>
      <Input
        aria-label="Required address fields"
        value={listToCsv(config.requiredFields)}
        onChange={(e) => onChange({ ...config, requiredFields: csvToList(e.target.value) })}
      />
    </div>
  );
}
