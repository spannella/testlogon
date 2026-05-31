import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listDesignRules,
  createDesignRule,
  updateDesignRule,
  deleteDesignRule,
} from "@/api/endpoints/stylistAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Ruler, Trash2 } from "lucide-react";
import type { CreateDesignRuleInput } from "@/api/types";

const CATEGORIES = [
  "spacing",
  "color",
  "typography",
  "layout",
  "component",
  "responsive",
  "accessibility",
] as const;
const SEVERITIES = ["error", "warning", "info"] as const;

export default function StylistDesignRulesPage() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [category, setCategory] = useState<CreateDesignRuleInput["category"]>("spacing");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<CreateDesignRuleInput["severity"]>("warning");

  const { data: rules } = useQuery({
    queryKey: ["stylist-rules"],
    queryFn: () => listDesignRules().catch(() => []),
  });

  const create = useMutation({
    mutationFn: () => createDesignRule({ name, category, description, severity }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["stylist-rules"] });
      setOpen(false);
      setName("");
      setDescription("");
    },
  });

  const toggle = useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) =>
      updateDesignRule(ruleId, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["stylist-rules"] }),
  });

  const remove = useMutation({
    mutationFn: (ruleId: string) => deleteDesignRule(ruleId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["stylist-rules"] }),
  });

  return (
    <div className="space-y-6 p-6" data-testid="design-rules-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Ruler className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">Design Rules</h1>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button data-testid="add-rule-btn">Add Rule</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>New Design Rule</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <div>
                <Label htmlFor="rule-name">Name</Label>
                <Input
                  id="rule-name"
                  data-testid="rule-name-input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div>
                <Label>Category</Label>
                <Select value={category} onValueChange={(v) => setCategory(v as CreateDesignRuleInput["category"])}>
                  <SelectTrigger data-testid="rule-category-trigger">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CATEGORIES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Severity</Label>
                <Select value={severity} onValueChange={(v) => setSeverity(v as CreateDesignRuleInput["severity"])}>
                  <SelectTrigger data-testid="rule-severity-trigger">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="rule-desc">Description</Label>
                <Textarea
                  id="rule-desc"
                  data-testid="rule-description-input"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => create.mutate()}
                disabled={!name || !description || create.isPending}
                data-testid="rule-submit-btn"
              >
                Create
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {(!rules || rules.length === 0) ? (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground" data-testid="no-rules">
            No design rules configured.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {rules.map((rule) => (
            <Card key={rule.rule_id} data-testid="design-rule-row">
              <CardHeader>
                <CardTitle className="flex items-center justify-between text-base">
                  <span>{rule.name}</span>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{rule.category}</Badge>
                    <Badge variant={rule.severity === "error" ? "destructive" : "default"}>
                      {rule.severity}
                    </Badge>
                    <Switch
                      checked={rule.enabled}
                      onCheckedChange={(v) => toggle.mutate({ ruleId: rule.rule_id, enabled: v })}
                      aria-label="toggle rule"
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      data-testid="delete-rule-btn"
                      onClick={() => remove.mutate(rule.rule_id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">{rule.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
