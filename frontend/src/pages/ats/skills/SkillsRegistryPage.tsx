/**
 * RSK-001 — Skill Registry Admin Page (ats/skills)
 *
 * Allows viewing the skills registry (autocomplete), assigning skills to
 * candidates or job-orders, and removing skill assignments.
 * Gated by S.candidates_enabled + S.ats_skills_enabled — shows a clear
 * "not enabled" state if the backend returns 404.
 */

import { useState, useCallback, useRef, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Search,
  Tag,
  Plus,
  X,
  Star,
  CheckSquare,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";

import {
  searchSkills,
  listEntitySkills,
  assignSkill,
  unassignSkill,
  isRskNotEnabled,
  type SkillOut,
} from "@/api/endpoints/resumeSkills";

// ─── Not-enabled guard ────────────────────────────────────────────────────────

function SkillsNotEnabled() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[40vh] gap-4 text-center">
      <Tag className="h-12 w-12 text-muted-foreground" />
      <h2 className="text-xl font-semibold">Skill Registry Not Available</h2>
      <p className="text-muted-foreground max-w-sm">
        The ATS skill registry feature is not currently enabled. Contact your
        administrator to enable{" "}
        <code className="text-xs bg-muted px-1 py-0.5 rounded">
          CANDIDATES_ENABLED
        </code>{" "}
        and{" "}
        <code className="text-xs bg-muted px-1 py-0.5 rounded">
          ATS_SKILLS_ENABLED
        </code>
        .
      </p>
    </div>
  );
}

// ─── Skill badge ──────────────────────────────────────────────────────────────

function SkillBadge({
  skill,
  onRemove,
}: {
  skill: SkillOut;
  onRemove?: (skillId: string) => void;
}) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary border border-primary/20">
      {skill.name}
      {skill.weight != null && (
        <span className="text-muted-foreground">· {skill.weight}/5</span>
      )}
      {skill.required === true && (
        <CheckSquare className="h-3 w-3 text-amber-600" />
      )}
      {onRemove && (
        <button
          onClick={() => onRemove(skill.skill_id)}
          className="ml-0.5 hover:text-destructive"
          aria-label={`Remove ${skill.name}`}
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </span>
  );
}

// ─── Skill autocomplete input ─────────────────────────────────────────────────

function SkillAutocomplete({
  onSelect,
  placeholder = "Search skills…",
}: {
  onSelect: (name: string) => void;
  placeholder?: string;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [debouncedQ, setDebouncedQ] = useState("");

  const { data } = useQuery({
    queryKey: ["skills", "search", debouncedQ],
    queryFn: () => searchSkills(debouncedQ, 10),
    enabled: debouncedQ.length >= 1,
    retry: false,
  });

  const handleChange = useCallback((val: string) => {
    setQuery(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setDebouncedQ(val), 250);
    setOpen(val.length > 0);
  }, []);

  const handleSelect = (name: string) => {
    onSelect(name);
    setQuery("");
    setDebouncedQ("");
    setOpen(false);
  };

  const suggestions = data?.skills ?? [];

  return (
    <div className="relative">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => handleChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && query.trim()) {
              handleSelect(query.trim());
            }
            if (e.key === "Escape") setOpen(false);
          }}
          placeholder={placeholder}
          className="pl-9"
        />
      </div>
      {open && suggestions.length > 0 && (
        <ul className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md max-h-52 overflow-y-auto">
          {suggestions.map((s) => (
            <li key={s.skill_id}>
              <button
                className="w-full text-left px-3 py-2 hover:bg-accent text-sm flex items-center justify-between"
                onMouseDown={() => handleSelect(s.name)}
              >
                <span>{s.name}</span>
                {s.usage_count > 0 && (
                  <span className="text-xs text-muted-foreground">
                    {s.usage_count} uses
                  </span>
                )}
              </button>
            </li>
          ))}
          {query.trim() &&
            !suggestions.find(
              (s) => s.name.toLowerCase() === query.trim().toLowerCase(),
            ) && (
              <li>
                <button
                  className="w-full text-left px-3 py-2 hover:bg-accent text-sm text-muted-foreground italic"
                  onMouseDown={() => handleSelect(query.trim())}
                >
                  Add "{query.trim()}"
                </button>
              </li>
            )}
        </ul>
      )}
    </div>
  );
}

// ─── Entity skills panel ──────────────────────────────────────────────────────

function EntitySkillsPanel({
  entityType,
  entityId,
}: {
  entityType: "candidate" | "job_order";
  entityId: string;
}) {
  const qc = useQueryClient();
  const queryKey = ["entity-skills", entityType, entityId];

  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => listEntitySkills(entityType, entityId),
    enabled: !!entityId,
    retry: false,
  });

  const [weight, setWeight] = useState<string>("none");
  const [required, setRequired] = useState<string>("any");

  const assignMut = useMutation({
    mutationFn: (name: string) =>
      assignSkill(entityType, entityId, {
        name,
        weight: weight && weight !== "none" ? Number(weight) : undefined,
        required:
          entityType === "job_order" && required && required !== "any"
            ? required === "true"
            : undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey });
      toast.success("Skill assigned");
    },
    onError: (e: Error) => toast.error(e.message || "Failed to assign skill"),
  });

  const removeMut = useMutation({
    mutationFn: (skillId: string) =>
      unassignSkill(entityType, entityId, skillId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey });
      toast.success("Skill removed");
    },
    onError: (e: Error) => toast.error(e.message || "Failed to remove skill"),
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-3/4" />
      </div>
    );
  }

  if (error && isRskNotEnabled(error)) return <SkillsNotEnabled />;
  if (error)
    return (
      <p className="text-sm text-destructive">
        Failed to load skills: {(error as Error).message}
      </p>
    );

  const skills = data?.skills ?? [];

  return (
    <div className="space-y-4">
      {/* Assignment row */}
      <div className="flex flex-wrap gap-2 items-end">
        <div className="flex-1 min-w-[180px]">
          <Label className="mb-1 block text-xs text-muted-foreground">
            Skill name
          </Label>
          <SkillAutocomplete onSelect={(n) => assignMut.mutate(n)} />
        </div>
        {entityType === "candidate" && (
          <div className="w-28">
            <Label className="mb-1 block text-xs text-muted-foreground">
              Weight (1–5)
            </Label>
            <Select value={weight} onValueChange={setWeight}>
              <SelectTrigger>
                <SelectValue placeholder="—" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">—</SelectItem>
                {[1, 2, 3, 4, 5].map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        {entityType === "job_order" && (
          <div className="w-32">
            <Label className="mb-1 block text-xs text-muted-foreground">
              Required?
            </Label>
            <Select value={required} onValueChange={setRequired}>
              <SelectTrigger>
                <SelectValue placeholder="—" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">—</SelectItem>
                <SelectItem value="true">Required</SelectItem>
                <SelectItem value="false">Optional</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}
      </div>

      {/* Current skills */}
      {skills.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No skills assigned yet.
        </p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {skills.map((s) => (
            <SkillBadge
              key={s.skill_id}
              skill={s}
              onRemove={(id) => removeMut.mutate(id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function SkillsRegistryPage() {
  const [notEnabled, setNotEnabled] = useState(false);
  const [entityType, setEntityType] = useState<"candidate" | "job_order">(
    "candidate",
  );
  const [entityId, setEntityId] = useState("");
  const [committedId, setCommittedId] = useState("");

  // Probe: try to autocomplete anything — if 404 the feature is off
  const probeQuery = useQuery({
    queryKey: ["skills", "probe"],
    queryFn: () => searchSkills("a", 1),
    retry: false,
    enabled: !notEnabled,
  });
  useEffect(() => {
    if (probeQuery.isError && isRskNotEnabled(probeQuery.error)) {
      setNotEnabled(true);
    }
  }, [probeQuery.isError, probeQuery.error]);

  if (notEnabled) return <SkillsNotEnabled />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Skill Registry"
        description="Assign and manage skill tags for candidates and job orders."
        actions={
          <Badge variant="secondary" className="text-xs">
            <Tag className="h-3 w-3 mr-1" />
            RSK-001
          </Badge>
        }
      />

      {/* Autocomplete demo / registry browser */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Search className="h-4 w-4" />
            Registry Search
          </CardTitle>
          <CardDescription>
            Search canonical skill names. Skills are auto-created when first
            assigned.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SkillAutocomplete
            onSelect={(name) =>
              toast.info(`Selected: "${name}" — assign it to an entity below.`)
            }
            placeholder="Type to search registry…"
          />
        </CardContent>
      </Card>

      {/* Entity skill editor */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Star className="h-4 w-4" />
            Entity Skill Assignment
          </CardTitle>
          <CardDescription>
            View and manage skills for a candidate or job order.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-3 items-end">
            <div className="w-40">
              <Label className="mb-1 block text-xs text-muted-foreground">
                Entity type
              </Label>
              <Select
                value={entityType}
                onValueChange={(v) =>
                  setEntityType(v as "candidate" | "job_order")
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="candidate">Candidate</SelectItem>
                  <SelectItem value="job_order">Job Order</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1 min-w-[220px]">
              <Label className="mb-1 block text-xs text-muted-foreground">
                Entity ID
              </Label>
              <div className="flex gap-2">
                <Input
                  value={entityId}
                  onChange={(e) => setEntityId(e.target.value)}
                  placeholder="e.g. cand_abc123"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && entityId.trim())
                      setCommittedId(entityId.trim());
                  }}
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCommittedId(entityId.trim())}
                  disabled={!entityId.trim()}
                >
                  <Plus className="h-4 w-4 mr-1" />
                  Load
                </Button>
              </div>
            </div>
          </div>

          {committedId ? (
            <EntitySkillsPanel
              key={`${entityType}:${committedId}`}
              entityType={entityType}
              entityId={committedId}
            />
          ) : (
            <p className="text-sm text-muted-foreground">
              Enter an entity ID and click Load to manage its skills.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
