import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

import type { BuilderRule, ValidationScope } from "./validationRules";
import { templatesForScope } from "./validationRules";

type Props = {
  rules: BuilderRule[];
  onChange: (rules: BuilderRule[]) => void;
  onPreview: (sampleAnswers: Record<string, unknown>) => void;
  previewOutput: Record<string, unknown> | null;
  referenceErrors: string[];
};

const scopes: ValidationScope[] = ["question", "group", "form"];

export default function ValidationRuleBuilder({ rules, onChange, onPreview, previewOutput, referenceErrors }: Props) {
  const [newScope, setNewScope] = useState<ValidationScope>("question");
  const [sampleAnswersJson, setSampleAnswersJson] = useState("{}");

  const templates = useMemo(() => templatesForScope(newScope), [newScope]);

  const patchRule = (id: string, patch: Partial<BuilderRule>) => {
    onChange(rules.map((r) => (r.id === id ? ({ ...r, ...patch } as BuilderRule) : r)));
  };

  return (
    <div className="space-y-3" data-testid="validation-rule-builder">
      <div className="flex items-center gap-2">
        <Select value={newScope} onValueChange={(v: ValidationScope) => setNewScope(v)}>
          <SelectTrigger className="w-48" aria-label="Rule scope"><SelectValue /></SelectTrigger>
          <SelectContent>
            {scopes.map((scope) => <SelectItem key={scope} value={scope}>{scope}</SelectItem>)}
          </SelectContent>
        </Select>
        {templates.map((t) => (
          <Button key={t.label} type="button" variant="outline" onClick={() => onChange([...rules, t.create()])}>
            {t.label}
          </Button>
        ))}
      </div>

      {referenceErrors.length > 0 && (
        <div className="rounded border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive" data-testid="rule-reference-errors">
          {referenceErrors.map((err) => <div key={err}>{err}</div>)}
        </div>
      )}

      <div className="space-y-2">
        {rules.map((rule) => (
          <div key={rule.id} className="rounded border p-2 space-y-2" data-testid={`rule-${rule.id}`}>
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium">{rule.scope} rule: {rule.rule_type}</div>
              <Button type="button" size="sm" variant="ghost" onClick={() => onChange(rules.filter((r) => r.id !== rule.id))}>Delete</Button>
            </div>

            {rule.scope === "question" && (
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label>Question ID</Label>
                  <Input aria-label="Question ID" value={rule.question_id} onChange={(e) => patchRule(rule.id, { question_id: e.target.value } as Partial<BuilderRule>)} />
                </div>
                <div>
                  <Label>Rule type</Label>
                  <Input value={rule.rule_type} readOnly />
                </div>
              </div>
            )}

            {rule.scope === "group" && (
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label>Group ID</Label>
                  <Input aria-label="Group ID" value={rule.group_id} onChange={(e) => patchRule(rule.id, { group_id: e.target.value } as Partial<BuilderRule>)} />
                </div>
                <div>
                  <Label>Question IDs (csv)</Label>
                  <Input
                    aria-label="Question IDs (csv)"
                    value={rule.question_ids.join(",")}
                    onChange={(e) => patchRule(rule.id, { question_ids: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) } as Partial<BuilderRule>)}
                  />
                </div>
              </div>
            )}

            {rule.scope === "form" && (
              <div className="flex items-center gap-2">
                <Label>Blocking</Label>
                <input
                  aria-label="Rule blocking"
                  type="checkbox"
                  checked={rule.blocking}
                  onChange={(e) => patchRule(rule.id, { blocking: e.target.checked } as Partial<BuilderRule>)}
                />
              </div>
            )}

            <div>
              <Label>Config (JSON)</Label>
              <Textarea
                rows={3}
                value={JSON.stringify(rule.config)}
                onChange={(e) => {
                  try {
                    const parsed = JSON.parse(e.target.value);
                    patchRule(rule.id, { config: parsed } as Partial<BuilderRule>);
                  } catch {
                    // keep current config on invalid edit
                  }
                }}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="rounded border p-3 space-y-2">
        <Label>Sample answers JSON (preview)</Label>
        <Textarea aria-label="Sample answers JSON (preview)" value={sampleAnswersJson} onChange={(e) => setSampleAnswersJson(e.target.value)} rows={4} />
        <Button
          type="button"
          onClick={() => {
            try {
              const parsed = JSON.parse(sampleAnswersJson);
              onPreview(parsed);
            } catch {
              onPreview({});
            }
          }}
        >
          Run evaluation preview
        </Button>
        {previewOutput && <pre className="text-xs overflow-auto bg-muted/40 p-2 rounded">{JSON.stringify(previewOutput, null, 2)}</pre>}
      </div>
    </div>
  );
}
