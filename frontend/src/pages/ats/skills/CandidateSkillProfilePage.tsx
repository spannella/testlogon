/**
 * RSK-001 — Candidate Skill Profile Page (/ats/skills/candidate/:candidateId)
 *
 * Displays the full skill profile for a single candidate:
 * - All assigned skills with weight badges
 * - Add / remove skill UI
 * - Links back to the candidate detail page
 *
 * Designed to be linked from CandidateDetailPage and from skill-search results.
 * Gated by S.candidates_enabled — shows "not enabled" on 404.
 */

import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Tag,
  Plus,
  X,
  Star,
  User,
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
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

import {
  listEntitySkills,
  assignSkill,
  unassignSkill,
  searchSkills,
  isRskNotEnabled,
  type SkillOut,
} from "@/api/endpoints/resumeSkills";

import { getCandidate } from "@/api/endpoints/candidates";

// ─── Not-enabled guard ────────────────────────────────────────────────────────

function SkillsNotEnabled() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[40vh] gap-4 text-center">
      <Tag className="h-12 w-12 text-muted-foreground" />
      <h2 className="text-xl font-semibold">Skills Not Available</h2>
      <p className="text-muted-foreground max-w-sm">
        The ATS skills feature is not currently enabled. Ask your administrator to
        enable{" "}
        <code className="text-xs bg-muted px-1 py-0.5 rounded">
          CANDIDATES_ENABLED
        </code>
        .
      </p>
    </div>
  );
}

// ─── Weight indicator ─────────────────────────────────────────────────────────

function WeightStars({ weight }: { weight: number }) {
  return (
    <span className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((n) => (
        <Star
          key={n}
          className={`h-3 w-3 ${n <= weight ? "fill-amber-400 text-amber-400" : "text-muted-foreground/30"}`}
        />
      ))}
    </span>
  );
}

// ─── Skill card ───────────────────────────────────────────────────────────────

function SkillCard({
  skill,
  onRemove,
  removing,
}: {
  skill: SkillOut;
  onRemove: (id: string) => void;
  removing: boolean;
}) {
  return (
    <Card className="group relative hover:border-primary/40 transition-colors">
      <CardContent className="py-3 px-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="font-medium text-sm truncate">{skill.name}</p>
            {skill.weight != null && (
              <div className="mt-1">
                <WeightStars weight={skill.weight} />
              </div>
            )}
            {skill.usage_count > 0 && (
              <p className="text-xs text-muted-foreground mt-0.5">
                {skill.usage_count} uses in registry
              </p>
            )}
          </div>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                variant="ghost"
                className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity text-destructive hover:text-destructive"
                onClick={() => onRemove(skill.skill_id)}
                disabled={removing}
                aria-label={`Remove ${skill.name}`}
              >
                <X className="h-3 w-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Remove skill</TooltipContent>
          </Tooltip>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Add skill form ───────────────────────────────────────────────────────────

function AddSkillForm({
  candidateId,
  onAdded,
}: {
  candidateId: string;
  onAdded: () => void;
}) {
  const [skillName, setSkillName] = useState("");
  const [weight, setWeight] = useState<string>("none");
  const [suggestions, setSuggestions] = useState<SkillOut[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const qc = useQueryClient();

  const assignMut = useMutation({
    mutationFn: () =>
      assignSkill("candidate", candidateId, {
        name: skillName.trim(),
        weight: weight && weight !== "none" ? Number(weight) : undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["entity-skills", "candidate", candidateId],
      });
      setSkillName("");
      setWeight("none");
      setSuggestions([]);
      onAdded();
      toast.success("Skill added");
    },
    onError: (e: Error) => toast.error(e.message || "Failed to add skill"),
  });

  const handleInput = async (val: string) => {
    setSkillName(val);
    if (val.length >= 1) {
      try {
        const res = await searchSkills(val, 8);
        setSuggestions(res.skills);
        setShowSuggestions(true);
      } catch {
        setSuggestions([]);
      }
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2 items-end">
        <div className="flex-1 relative">
          <Label
            htmlFor="new-skill"
            className="mb-1 block text-xs text-muted-foreground"
          >
            Skill name
          </Label>
          <Input
            id="new-skill"
            value={skillName}
            onChange={(e) => handleInput(e.target.value)}
            placeholder="e.g. Python, AWS, Project Management"
            onKeyDown={(e) => {
              if (e.key === "Enter" && skillName.trim()) assignMut.mutate();
              if (e.key === "Escape") setShowSuggestions(false);
            }}
            onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
          />
          {showSuggestions && suggestions.length > 0 && (
            <ul className="absolute z-50 mt-1 w-full bg-popover border rounded-md shadow-md max-h-44 overflow-y-auto">
              {suggestions.map((s) => (
                <li key={s.skill_id}>
                  <button
                    className="w-full text-left px-3 py-2 hover:bg-accent text-sm"
                    onMouseDown={() => {
                      setSkillName(s.name);
                      setShowSuggestions(false);
                    }}
                  >
                    {s.name}
                    {s.usage_count > 0 && (
                      <span className="ml-2 text-xs text-muted-foreground">
                        {s.usage_count} uses
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="w-28">
          <Label className="mb-1 block text-xs text-muted-foreground">
            Proficiency
          </Label>
          <Select value={weight} onValueChange={setWeight}>
            <SelectTrigger>
              <SelectValue placeholder="1–5" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">None</SelectItem>
              {[1, 2, 3, 4, 5].map((n) => (
                <SelectItem key={n} value={String(n)}>
                  {n} — {["Beginner", "Basic", "Intermediate", "Advanced", "Expert"][n - 1]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Button
          onClick={() => assignMut.mutate()}
          disabled={!skillName.trim() || assignMut.isPending}
          className="shrink-0"
        >
          <Plus className="h-4 w-4 mr-1" />
          {assignMut.isPending ? "Adding…" : "Add"}
        </Button>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function CandidateSkillProfilePage() {
  const { candidateId } = useParams<{ candidateId: string }>();
  const qc = useQueryClient();
  const [notEnabled, setNotEnabled] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);

  const candidateQuery = useQuery({
    queryKey: ["candidate", candidateId],
    queryFn: () => getCandidate(candidateId!),
    enabled: !!candidateId,
    retry: false,
  });

  const skillsQuery = useQuery({
    queryKey: ["entity-skills", "candidate", candidateId],
    queryFn: () => listEntitySkills("candidate", candidateId!),
    enabled: !!candidateId,
    retry: false,
  });
  useEffect(() => {
    if (skillsQuery.isError && isRskNotEnabled(skillsQuery.error)) {
      setNotEnabled(true);
    }
  }, [skillsQuery.isError, skillsQuery.error]);

  const removeMut = useMutation({
    mutationFn: (skillId: string) =>
      unassignSkill("candidate", candidateId!, skillId),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["entity-skills", "candidate", candidateId],
      });
      setRemovingId(null);
      toast.success("Skill removed");
    },
    onError: (e: Error) => {
      setRemovingId(null);
      toast.error(e.message || "Failed to remove skill");
    },
  });

  const handleRemove = (skillId: string) => {
    setRemovingId(skillId);
    removeMut.mutate(skillId);
  };

  if (!candidateId) {
    return (
      <p className="text-destructive">No candidate ID provided in the URL.</p>
    );
  }

  if (notEnabled) return <SkillsNotEnabled />;

  const candidate = candidateQuery.data;
  const skills: SkillOut[] = skillsQuery.data?.skills ?? [];
  const isLoadingSkills = skillsQuery.isLoading;

  const candidateName = candidate
    ? `${candidate.first_name} ${candidate.last_name}`
    : candidateId;

  return (
    <div className="space-y-6">
      {/* Back link */}
      <div className="flex items-center gap-2">
        <Link
          to={`/ats/candidates/${candidateId}`}
          className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Candidate
        </Link>
      </div>

      <PageHeader
        title={`Skill Profile`}
        description={
          candidate
            ? `Managing skills for ${candidateName}`
            : `Candidate ${candidateId}`
        }
        actions={
          <div className="flex items-center gap-2">
            {candidate && (
              <Badge variant="outline" className="text-xs gap-1">
                <User className="h-3 w-3" />
                {candidateName}
              </Badge>
            )}
            <Badge variant="secondary" className="text-xs">
              <Tag className="h-3 w-3 mr-1" />
              {skills.length} skill{skills.length !== 1 ? "s" : ""}
            </Badge>
          </div>
        }
      />

      {/* Add skill */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Plus className="h-4 w-4" />
            Add Skill
          </CardTitle>
          <CardDescription>
            Assign a skill tag to this candidate. Type to search the registry or
            create a new skill by entering its name.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AddSkillForm
            candidateId={candidateId}
            onAdded={() =>
              qc.invalidateQueries({
                queryKey: ["entity-skills", "candidate", candidateId],
              })
            }
          />
        </CardContent>
      </Card>

      {/* Current skills */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Tag className="h-4 w-4" />
            Assigned Skills
          </CardTitle>
          <CardDescription>
            Hover a skill card and click × to remove it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoadingSkills ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[1, 2, 3, 4, 5, 6].map((n) => (
                <Skeleton key={n} className="h-20 w-full" />
              ))}
            </div>
          ) : skillsQuery.isError && !notEnabled ? (
            <p className="text-sm text-destructive">
              Failed to load skills:{" "}
              {(skillsQuery.error as Error).message}
            </p>
          ) : skills.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Tag className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">
                No skills assigned yet. Use the form above to add the first one.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {skills.map((skill) => (
                <SkillCard
                  key={skill.skill_id}
                  skill={skill}
                  onRemove={handleRemove}
                  removing={removingId === skill.skill_id}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Summary bar */}
      {skills.length > 0 && (
        <div className="text-xs text-muted-foreground flex flex-wrap gap-3">
          <span>
            <strong>{skills.length}</strong> skill
            {skills.length !== 1 ? "s" : ""} assigned
          </span>
          {skills.some((s) => s.weight != null) && (
            <span>
              Avg proficiency:{" "}
              <strong>
                {(
                  skills
                    .filter((s) => s.weight != null)
                    .reduce((sum, s) => sum + (s.weight ?? 0), 0) /
                  skills.filter((s) => s.weight != null).length
                ).toFixed(1)}
                /5
              </strong>
            </span>
          )}
        </div>
      )}
    </div>
  );
}
