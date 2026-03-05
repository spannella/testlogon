export type ValidationScope = "question" | "group" | "form";

export type QuestionRule = {
  id: string;
  scope: "question";
  question_id: string;
  rule_type: "required_if" | "min" | "max";
  config: Record<string, unknown>;
};

export type GroupRule = {
  id: string;
  scope: "group";
  group_id: string;
  rule_type: "min_answered" | "requires_if_answered" | "mutually_exclusive";
  question_ids: string[];
  config: Record<string, unknown>;
};

export type FormRule = {
  id: string;
  scope: "form";
  rule_type: "requires_if_answered" | "mutually_exclusive";
  config: Record<string, unknown>;
  blocking: boolean;
};

export type BuilderRule = QuestionRule | GroupRule | FormRule;

export function templatesForScope(scope: ValidationScope): Array<{ label: string; create: () => BuilderRule }> {
  if (scope === "question") {
    return [
      {
        label: "Required if another question is answered",
        create: () => ({ id: crypto.randomUUID(), scope: "question", question_id: "", rule_type: "required_if", config: { if_question_id: "" } }),
      },
      {
        label: "Min numeric value",
        create: () => ({ id: crypto.randomUUID(), scope: "question", question_id: "", rule_type: "min", config: { min: 0 } }),
      },
      {
        label: "Max numeric value",
        create: () => ({ id: crypto.randomUUID(), scope: "question", question_id: "", rule_type: "max", config: { max: 10 } }),
      },
    ];
  }
  if (scope === "group") {
    return [
      {
        label: "At least one answered",
        create: () => ({ id: crypto.randomUUID(), scope: "group", group_id: "", rule_type: "min_answered", question_ids: [], config: { min_answered: 1 } }),
      },
      {
        label: "Required-if in group",
        create: () => ({ id: crypto.randomUUID(), scope: "group", group_id: "", rule_type: "requires_if_answered", question_ids: [], config: { if_question_id: "", required_question_ids: [] } }),
      },
      {
        label: "Mutually exclusive group",
        create: () => ({ id: crypto.randomUUID(), scope: "group", group_id: "", rule_type: "mutually_exclusive", question_ids: [], config: {} }),
      },
    ];
  }
  return [
    {
      label: "Cross-section required-if",
      create: () => ({ id: crypto.randomUUID(), scope: "form", rule_type: "requires_if_answered", config: { if_question_id: "", required_question_ids: [] }, blocking: true }),
    },
    {
      label: "Cross-section mutually exclusive",
      create: () => ({ id: crypto.randomUUID(), scope: "form", rule_type: "mutually_exclusive", config: { question_ids: [] }, blocking: true }),
    },
  ];
}

export function toBackendRulePayload(rules: BuilderRule[]): { group_rules: Record<string, unknown>[]; form_rules: Record<string, unknown>[] } {
  const group_rules = rules
    .filter((r): r is GroupRule => r.scope === "group")
    .map((r) => ({
      rule_id: r.id,
      group_id: r.group_id,
      rule_type: r.rule_type,
      question_ids: r.question_ids,
      config_json: r.config,
    }));

  const form_rules = rules
    .filter((r): r is FormRule => r.scope === "form")
    .map((r) => ({
      rule_id: r.id,
      rule_type: r.rule_type,
      config_json: r.config,
      blocking: r.blocking,
    }));

  return { group_rules, form_rules };
}

export function validateRuleReferences(rules: BuilderRule[], knownQuestionIds: string[]): string[] {
  const known = new Set(knownQuestionIds);
  const errors: string[] = [];

  const checkRef = (ruleId: string, ref: string, label: string) => {
    if (ref && !known.has(ref)) errors.push(`Rule ${ruleId}: ${label} references unknown question '${ref}'.`);
  };

  for (const rule of rules) {
    if (rule.scope === "question") {
      checkRef(rule.id, rule.question_id, "question_id");
      if (rule.rule_type === "required_if") checkRef(rule.id, String(rule.config.if_question_id || ""), "if_question_id");
    }
    if (rule.scope === "group") {
      rule.question_ids.forEach((qid) => checkRef(rule.id, qid, "question_ids"));
      if (rule.rule_type === "requires_if_answered") {
        checkRef(rule.id, String(rule.config.if_question_id || ""), "if_question_id");
        const req = Array.isArray(rule.config.required_question_ids) ? rule.config.required_question_ids : [];
        req.forEach((qid) => checkRef(rule.id, String(qid), "required_question_ids"));
      }
    }
    if (rule.scope === "form") {
      if (rule.rule_type === "requires_if_answered") {
        checkRef(rule.id, String(rule.config.if_question_id || ""), "if_question_id");
        const req = Array.isArray(rule.config.required_question_ids) ? rule.config.required_question_ids : [];
        req.forEach((qid) => checkRef(rule.id, String(qid), "required_question_ids"));
      }
      if (rule.rule_type === "mutually_exclusive") {
        const ids = Array.isArray(rule.config.question_ids) ? rule.config.question_ids : [];
        ids.forEach((qid) => checkRef(rule.id, String(qid), "question_ids"));
      }
    }
  }

  return errors;
}
